import datetime
import time
import threading

from dp3.common.utils import parse_rfc_time
from copy import deepcopy


class HistoryManager:
    def __init__(self, db, attr_spec):
        # TODO singleton?
        self.db = db
        self.attr_spec = attr_spec
        self.hm_thread = threading.Thread(target=self.history_management_thread, daemon=True)
        self.hm_thread.start()

    def process_datapoint(self, etype, attr_id, data):
        redundant_ids = []
        redundant_data = []
        delete_ids = []
        history_params = self.attr_spec[etype]['attribs'][attr_id].history_params
        aggregation_interval = history_params["aggregation_interval"]
        t1 = parse_rfc_time(data['t1'])
        t2 = parse_rfc_time(data['t2'])
        data['agg'] = 0

        # Check for collisions
        datapoints = self.db.get_datapoints_range(etype, attr_id, data['eid'], data['t1'], data['t2'])
        merge_list = []
        for d in datapoints:
            m = mergeable(data, d, history_params)
            merge_list.append(m)
            if not m and not is_flag_set("aggregated", d['agg']):
                raise ValueError("Incoming data point is overlapping with other, non mergeable data point(s)")

        # Merge with directly overlapping datapoints
        agg = deepcopy(data)
        for d in datapoints:
            is_mergeable = merge_list.pop(0)
            if is_flag_set("redundant", d['agg']):
                continue
            if is_mergeable:
                merge(agg, d, history_params)
                if is_flag_set("aggregated", d['agg']):
                    delete_ids.append(d['id'])
                else:
                    d['agg'] = set_flag("redundant", d['agg'])
                    redundant_ids.append(d['id'])
                    redundant_data.append(d)
            else:
                self.split_datapoint(etype, attr_id, d, t1)

        # Merge with non-overlapping datapoints
        pre = self.db.get_datapoints_range(etype, attr_id, data['eid'], str(t1 - aggregation_interval), data['t1'], False, 1)
        post = self.db.get_datapoints_range(etype, attr_id, data['eid'], data['t2'], str(t2 + aggregation_interval), False, 0)
        for d in pre + post:
            if is_flag_set("redundant", d['agg']):
                continue
            if mergeable(agg, d, history_params):
                merge(agg, d, history_params)
                if is_flag_set("aggregated", d['agg']):
                    delete_ids.append(d['id'])
                else:
                    d['agg'] = set_flag("redundant", d['agg'])
                    redundant_ids.append(d['id'])
                    redundant_data.append(d)
            else:
                break

        # Write changes to db
        if agg['t1'] != data['t1'] or agg['t2'] != data['t2']:  # TODO aka agg changed
            agg['agg'] = set_flag("aggregated", agg['agg'])
            data['agg'] = set_flag("redundant", data['agg'])
            self.db.create_datapoint(etype, attr_id, agg)
        self.db.create_datapoint(etype, attr_id, data)
        if redundant_ids.__len__() > 0:
            self.db.rewrite_data_points(etype, attr_id, redundant_ids, redundant_data)
        if delete_ids.__len__() > 0:
            self.db.delete_multiple_records(f"{etype}__{attr_id}", delete_ids)

    def split_datapoint(self, etype, attr_id, data, timestamp):
        history_params = self.attr_spec[etype]['attribs'][attr_id].history_params
        redundant = self.db.get_datapoints_range(etype, attr_id, data['eid'], data['t1'], data['t2'], sort=0, agg=2)
        assert redundant.__len__() > 0, "split_datapoint(): unable to split, not enough data"
        assert redundant[0]['t1'] < timestamp, "split_datapoint(): unable to split, not enough data"
        agg = deepcopy(redundant[0])
        agg.pop('id')
        agg['agg'] = set_flag("aggregated", 0)
        agg['t1'] = data['t1']  # in case some old data points got deleted
        flag = True
        for r in redundant[1:]:
            if flag and r['t1'] > timestamp:
                flag = False
                self.db.create_datapoint(etype, attr_id, agg)
                agg = deepcopy(r)
                agg.pop('id')
                agg['agg'] = set_flag("aggregated", 0)
                continue
            merge(agg, r, history_params)
        self.db.create_datapoint(etype, attr_id, agg)
        self.db.delete_record(f"{etype}__{attr_id}", data['id'])

    def process_datapoints_range(self, etype, eid, attr_id, t1, t2):
        delete_list = []
        redundant_ids = []
        redundant_data = []
        history_params = self.attr_spec[etype]['attribs'][attr_id].history_params

        # TODO select non redundant
        d1 = self.db.get_datapoints_range(etype, attr_id, eid, t1, t2, sort=0, agg=0)
        d2 = self.db.get_datapoints_range(etype, attr_id, eid, t1, t2, sort=0, agg=1)
        datapoints = d1 + d2
        if not datapoints.__len__() > 0:
            return

        curr = deepcopy(datapoints[0])
        for d in datapoints[1:]:
            if mergeable(curr, d, history_params):
                merge(curr, d, history_params)
                if is_flag_set("aggregated", d['agg']):
                    delete_ids.append(d['id'])
                else:
                    d['agg'] = set_flag("redundant", d['agg'])
                    redundant_ids.append(d['id'])
                    redundant_data.append(d)
            else:
                curr = d
        if redundant_ids.__len__() > 0:
            self.db.rewrite_data_points(etype, attr_id, redundant_ids, redundant_data)
        if delete_ids.__len__() > 0:
            self.db.delete_multiple_records(f"{etype}__{attr_id}", delete_ids)

    def get_historic_value(self, etype, eid, attr_id, timestamp):
        history_params = self.attr_spec[etype]['attribs'][attr_id].history_params

        t1 = parse_rfc_time(timestamp) - history_params['post_validity']
        t2 = parse_rfc_time(timestamp) + history_params['pre_validity']
        datapoints = self.db.get_datapoints_range(etype, attr_id, eid, t1, t2)

        if len(datapoints) < 1:
            return None

        best = None
        for d in datapoints:
            confidence = extrapolate_confidence(d, timestamp, history_params)
            if best is None or confidence > best[1]:
                best = d['v'], confidence
        return best

    def history_management_thread(self):
        tick_rate = datetime.timedelta(seconds=100)  # TODO add to global config
        next_call = datetime.datetime.now()
        while True:
            for etype in self.attr_spec:
                for attr_id in self.attr_spec[etype]['attribs']:
                    table_name = f"{etype}__{attr_id}"

                    if self.attr_spec[etype]['attribs'][attr_id].history is False:
                        continue
                    history_params = self.attr_spec[etype]['attribs'][attr_id].history_params

                    # redundant
                    max_age = history_params["aggregation_max_age"]
                    t2 = str(datetime.datetime.now() - max_age)
                    data = self.db.get_datapoints_range(etype=etype, attr_name=attr_id, t2=t2, agg=2)
                    self.db.delete_multiple_records(table_name, [dp['id'] for dp in data])

                    # too old
                    max_age = history_params["max_age"]
                    t2 = str(datetime.datetime.now() - max_age)
                    data = self.db.get_datapoints_range(etype=etype, attr_name=attr_id, t2=t2)
                    self.db.delete_multiple_records(table_name, [dp['id'] for dp in data])
            next_call = next_call + tick_rate
            time.sleep((next_call - datetime.datetime.now()).total_seconds())


def extrapolate_confidence(datapoint, timestamp, history_params):
    pre_validity = history_params['pre_validity']
    post_validity = history_params['post_validity']
    t = parse_rfc_time(timestamp)
    t1 = parse_rfc_time(datapoint['t1'])
    t2 = parse_rfc_time(datapoint['t2'])
    base_confidence = datapoint['c']

    if t2 < t:
        distance = t - t2
        multiplier = (1 - (distance / post_validity))
    elif t1 > t:
        distance = t1 - t
        multiplier = (1 - (distance / pre_validity))
    else:
        multiplier = 1
    return base_confidence * multiplier


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


def is_flag_set(flag, bits):
    return bool(bits & flag_to_int[flag])


def set_flag(flag, bits):
    if not is_flag_set(flag, bits):
        bits += (1 << (flag_to_int[flag] - 1))
    return bits


def unset_flag(flag, bits):
    if is_flag_set(flag, bits):
        bits -= 1 << (flag_to_int[flag] - 1)
    return bits


merge_check = {
    "keep": lambda a, b: a == b,
    "add": lambda a, b: True,
    "avg": lambda a, b: True,
    "csv_union": lambda a, b: True
}

merge_apply = {
    "keep": lambda a, b: a,
    "add": lambda a, b: a + b,
    "avg": lambda a, b: (a + b) / 2,  # TODO how to compute average?
    "csv_union": lambda a, b: csv_union(a, b)
}

flag_to_int = {
    "aggregated": 1,
    "redundant": 2
}
