import logging
from collections import defaultdict
from copy import deepcopy
from datetime import datetime
from typing import Union

from dp3 import g
from dp3.common.attrspec import AttrSpec
from dp3.common.config import HierarchicalDict
from dp3.common.entityspec import EntitySpec
from dp3.common.utils import parse_rfc_time
from dp3.database.database import EntityDatabase
from dp3.database.record import Record
from dp3.task_processing.task_queue import TaskQueueWriter
from .constants import *


def extrapolate_confidence(datapoint, timestamp, history_params):
    pre_validity = history_params['pre_validity']
    post_validity = history_params['post_validity']
    t1 = datapoint['t1']
    t2 = datapoint['t2']
    base_confidence = datapoint['c']

    if t2 < timestamp:
        distance = timestamp - t2
        multiplier = (1 - (distance / post_validity))
    elif t1 > timestamp:
        distance = t1 - timestamp
        multiplier = (1 - (distance / pre_validity))
    else:
        multiplier = 1
    return base_confidence * multiplier


class HistoryManager:
    def __init__(self, db: EntityDatabase,
                 attr_spec: dict[str, dict[str, Union[EntitySpec, dict[str, AttrSpec]]]],
                 worker_index: int, num_workers: int, config: HierarchicalDict) -> None:
        self.log = logging.getLogger("HistoryManager")

        self.db = db
        self.attr_spec = attr_spec
        self.worker_index = worker_index
        self.num_workers = num_workers
        self.config = config
        self._tqw = TaskQueueWriter(g.app_name, self.num_workers, g.config['processing_core']['msg_broker'])

        entity_management_period = self.config['entity_management']['tick_rate']
        datapoint_cleaning_period = self.config['datapoint_cleaning']['tick_rate']

        if worker_index != 0:
            self.log.debug("History management will not be active in this worker instance to avoid race conditions.")
            return

        g.scheduler.register(self.manage_current_entity_values, minute=f"*/{entity_management_period}")
        g.scheduler.register(self.delete_old_datapoints, minute=f"*/{datapoint_cleaning_period}")

    def process_datapoint(self, etype, attr_id, data):
        redundant_ids = []
        redundant_data = []
        delete_ids = []
        attr_spec = self.attr_spec[etype]['attribs'][attr_id]
        history_params = attr_spec.history_params
        multi_value = attr_spec.multi_value
        t1 = parse_rfc_time(data['t1'])
        t2 = parse_rfc_time(data['t2'])
        data['tag'] = TAG_PLAIN

        # Don't aggregate,... timeseries data
        if attr_spec.type == "timeseries":
            self.db.create_datapoint(etype, attr_id, data)
            return

        # Check for collisions
        datapoints = self.db.get_datapoints_range(etype=etype, attr_name=attr_id, eid=data['eid'], t1=data['t1'],
                                                  t2=data['t2'], closed_interval=False, filter_redundant=None)
        merge_list = []
        for d in datapoints:
            m = mergeable(data, d, history_params)
            merge_list.append(m)
            if not m and not d['tag'] == TAG_AGGREGATED and multi_value is False:
                raise ValueError("Incoming data point is overlapping with other, non mergeable data point(s)")

        # Merge with directly overlapping datapoints
        agg = deepcopy(data)
        for d in datapoints:
            is_mergeable = merge_list.pop(0)
            if d['tag'] == TAG_REDUNDANT:
                continue
            if is_mergeable:
                merge(agg, d, history_params)
                if d['tag'] == TAG_AGGREGATED:
                    delete_ids.append(d['id'])
                else:
                    d['tag'] = TAG_REDUNDANT
                    redundant_ids.append(d['id'])
                    redundant_data.append(d)
            elif multi_value is True:
                continue
            else:
                self.split_datapoint(etype, attr_id, d, t1)

        # Merge with non-overlapping datapoints
        aggregation_interval = history_params["aggregation_interval"]
        pre = self.db.get_datapoints_range(etype=etype, attr_name=attr_id, eid=data['eid'],
                                           t1=str(t1 - aggregation_interval), t2=data['t1'],
                                           closed_interval=False, sort=1, filter_redundant=True)
        post = self.db.get_datapoints_range(etype=etype, attr_name=attr_id, eid=data['eid'],
                                            t1=data['t2'], t2=str(t2 + aggregation_interval),
                                            closed_interval=False, sort=0, filter_redundant=True)
        for datapoints in pre, post:
            for d in datapoints:
                if d in pre and d['t2'] >= t1 or \
                   d in post and d['t1'] <= t2:
                    continue
                if mergeable(agg, d, history_params):
                    merge(agg, d, history_params)
                    if d['tag'] == TAG_AGGREGATED:
                        delete_ids.append(d['id'])
                    else:
                        d['tag'] = TAG_REDUNDANT
                        redundant_ids.append(d['id'])
                        redundant_data.append(d)
                elif multi_value is True:
                    continue
                else:
                    break

        # Write changes to db
        if agg['t1'] != data['t1'] or agg['t2'] != data['t2']:
            agg['tag'] = TAG_AGGREGATED
            data['tag'] = TAG_REDUNDANT
            self.db.create_datapoint(etype, attr_id, agg)
        self.db.create_datapoint(etype, attr_id, data)
        if redundant_ids.__len__() > 0:
            self.db.rewrite_data_points(etype, attr_id, redundant_ids, redundant_data)
        if delete_ids.__len__() > 0:
            self.db.delete_multiple_records(f"{etype}__{attr_id}", delete_ids)

    def split_datapoint(self, etype, attr_id, data, timestamp):
        history_params = self.attr_spec[etype]['attribs'][attr_id].history_params
        redundant = self.db.get_datapoints_range(etype=etype, attr_name=attr_id, eid=data['eid'],
                                                 t1=data['t1'], t2=data['t2'], sort=0, filter_redundant=False)
        assert redundant.__len__() > 0, "split_datapoint(): unable to split, not enough data"
        assert redundant[0]['t1'] < timestamp, "split_datapoint(): unable to split, not enough data"
        agg = deepcopy(redundant[0])
        agg.pop('id')
        agg['t1'] = data['t1']  # in case some old data points got deleted
        flag = True
        for r in redundant[1:]:
            if flag and r['t1'] > timestamp:
                flag = False
                tmp1 = agg
                tmp2 = r
                agg = deepcopy(r)
                agg.pop('id')
                continue
            merge(agg, r, history_params)

        self.db.delete_record(f"{etype}__{attr_id}", data['id'])

        if tmp1['t2'] == redundant[0]['t2']:
            tmp1['tag'] = TAG_PLAIN
            self.db.delete_record(f"{etype}__{attr_id}", redundant[0]['id'])
        else:
            tmp1['tag'] = TAG_AGGREGATED
        self.db.create_datapoint(etype, attr_id, tmp1)

        if agg['t1'] == tmp2['t1']:
            agg['tag'] = TAG_PLAIN
            self.db.delete_record(f"{etype}__{attr_id}", tmp2['id'])
        else:
            agg['tag'] = TAG_AGGREGATED
        self.db.create_datapoint(etype, attr_id, agg)

    def delete_old_datapoints(self):
        """ Deletes old records (data points) from history tables. """
        self.log.debug("Deleting old records ...")
        for etype in self.attr_spec:
            for attr_id in self.attr_spec[etype]['attribs']:
                attr_conf = self.attr_spec[etype]['attribs'][attr_id]

                if attr_conf.type == "observations":
                    t_old = str(datetime.utcnow() - attr_conf.history_params["max_age"])
                    t_redundant = str(datetime.utcnow() - attr_conf.history_params["aggregation_max_age"])
                elif attr_conf.type == "timeseries":
                    max_age = attr_conf.timeseries_params["max_age"]
                    if not max_age:
                        continue

                    t_old = str(datetime.utcnow() - max_age)
                    t_redundant = None
                else:
                    continue

                self.db.delete_old_datapoints(etype=etype, attr_name=attr_id, t_old=t_old, t_redundant=t_redundant,
                                              tag=TAG_REDUNDANT)

    def manage_current_entity_values(self):
        """
        Maintains values in entity tables:
        - updates confidence values
        - deletes expired attribute values
        """
        t_now = datetime.utcnow()
        self.log.debug("Updating confidence and deleting expired attribute values ...")

        for etype in self.attr_spec:
            entities = self.db.get_entities(etype)
            entity_events = defaultdict(set)

            # Confidence processing
            for attr_id, attr_conf in self.attr_spec[etype]['attribs'].items():
                attr_c = f"{attr_id}:c"
                if not attr_conf.confidence:
                    continue
                t1 = t_now - attr_conf.history_params['pre_validity']
                t2 = t_now + attr_conf.history_params['post_validity']
                for eid in entities:
                    rec = Record(self.db, etype, eid)
                    if not rec[attr_c]:
                        continue
                    entity_events[eid].add('!CONFIDENCE')
                    datapoints = self.db.get_datapoints_range(etype, attr_id, eid, t1, t2)
                    if attr_conf.multi_value:
                        best = [0.0 for _ in rec[attr_id]]
                        for d in datapoints:
                            if d['v'] not in rec[attr_id]:
                                continue
                            i = rec[attr_id].index(d['v'])
                            confidence = extrapolate_confidence(d, t_now, attr_conf.history_params)
                            if confidence > best[i]:
                                best[i] = confidence
                        rec[attr_c] = best

                    else:  # single value
                        best = None
                        for d in datapoints:
                            if d['v'] != rec[attr_id]:
                                continue
                            confidence = extrapolate_confidence(d, t_now, attr_conf.history_params)
                            if best is None or confidence > best:
                                best = confidence
                        if best is not None:
                            rec[attr_c] = best
                    rec.push_changes_to_db()

            # Expiration processing
            for attr_id in self.attr_spec[etype]['attribs']:
                attr_conf = self.attr_spec[etype]['attribs'][attr_id]
                attr_exp = f"{attr_id}:exp"
                attr_c = f"{attr_id}:c"
                if not attr_conf.history:
                    continue
                if attr_conf.multi_value:
                    entities = self.db.get_entities_with_expired_values(etype, attr_id)
                    for eid in entities:
                        try:
                            rec = Record(self.db, etype, eid)
                            new_val = rec[attr_id]
                            new_exp = rec[attr_exp]
                            new_c = rec[attr_c] if attr_conf.confidence else None
                            for exp in rec[attr_exp]:
                                if exp < t_now:
                                    idx = rec[attr_exp].index(exp)
                                    del new_val[idx]
                                    del new_exp[idx]
                                    rec[attr_id] = new_val
                                    rec[attr_exp] = new_exp
                                    if new_c:
                                        del new_c[idx]
                                        rec[attr_c] = new_c
                            rec.push_changes_to_db()
                            entity_events[eid].add('!EXPIRED')
                        except Exception as e:
                            self.log.exception(f"manage_history(): {etype} / {eid} / {attr_id}: {e}")
                            rec = Record(self.db, etype, eid)
                            rec[attr_id] = []
                            rec[attr_exp] = []
                            if attr_conf.confidence:
                                rec[attr_c] = []
                            rec.push_changes_to_db()
                            entity_events[eid].add('!EXPIRED')
                else:
                    entities = self.db.unset_expired_values(etype, attr_id, attr_conf.confidence,
                                                            return_updated_ids=True)
                    for eid in entities:
                        entity_events[eid].add('!EXPIRED')

            # Create expiration events for the entities
            for eid, events in entity_events.items():
                self._tqw.put_task(etype, eid, events=list(events))


def get_historic_value(db, config, etype, eid, attr_id, timestamp):
    attr_spec = config[etype]['attribs'][attr_id]
    t1 = timestamp - attr_spec.history_params['pre_validity']
    t2 = timestamp + attr_spec.history_params['post_validity']
    datapoints = db.get_datapoints_range(etype, attr_id, eid, t1, t2)

    if len(datapoints) < 1:
        return None

    if attr_spec.multi_value is True:
        return set([d['v'] for d in datapoints])

    best = None
    for d in datapoints:
        confidence = extrapolate_confidence(d, timestamp, attr_spec.history_params)
        if best is None or confidence > best[1]:
            best = d['v'], confidence
    return best[0] if best is not None else None


def csv_union(a, b):
    return ','.join(set(f"{a},{b}".split(sep=',')))


def mergeable(a, b, params):
    res = merge_check[params['aggregation_function_value']](a['v'], b['v'])
    res = res and merge_check[params['aggregation_function_confidence']](a['c'], b['c'])
    return res and merge_check[params['aggregation_function_source']](a['src'], b['src'])


def merge(a, b, history_params):
    a['v'] = merge_apply[history_params['aggregation_function_value']](a['v'], b['v'])
    a['c'] = merge_apply[history_params['aggregation_function_confidence']](a['c'], b['c'])
    a['src'] = merge_apply[history_params['aggregation_function_source']](a['src'], b['src'])
    a['t1'] = str(min(parse_rfc_time(str(a['t1'])), b['t1']))
    a['t2'] = str(max(parse_rfc_time(str(a['t2'])), b['t2']))


merge_check = {
    "keep": lambda a, b: a == b,
    "add": lambda a, b: True,
    "avg": lambda a, b: True,
    "csv_union": lambda a, b: True
}

merge_apply = {
    "keep": lambda a, b: a,
    "add": lambda a, b: a + b,
    "avg": lambda a, b: (a + b) / 2,
    "csv_union": lambda a, b: csv_union(a, b)
}
