import functools
import ipaddress
import re
from datetime import timedelta
from typing import Any

from dp3.common.utils import parse_time_duration

# Error message templates
err_msg_type = "type of '{}' is invalid (must be '{}')"
err_msg_format = "format of '{}' is invalid"
err_msg_value = "value of '{}' is invalid"
err_msg_missing_field = "mandatory field '{}' is missing"

# List of attribute types
attr_types = [
    "plain",
    "observations",
    "timeseries"
]

# Dict of timeseries type spec
timeseries_types = {
    "regular": {
        "default_series": {},
        "sort_by": "t1"
    },
    "irregular": {
        "default_series": {
            "time": { "data_type": "time" }
        },
        "sort_by": "time"
    },
    "irregular_intervals": {
        "default_series": {
            "time_first": { "data_type": "time" },
            "time_last": { "data_type": "time" }
        },
        "sort_by": "time_first"
    }
}

# List of primitive data types
primitive_data_types = [
    "tag",
    "binary",
    "string",
    "int",
    "int64",
    "float",
    "ipv4",
    "ipv6",
    "mac",
    "time",
    "special",  # deprecated, use json instead
    "json"
]

# List of primitive data types allowed in timeseries
primitive_data_types_series = [
    "time",
    "int",
    "float"
]

# List of aggregation functions
aggregation_functions = [
    "keep",
    "add",
    "avg",
    "min",
    "max",
    "csv_union"
]

# Default specification fields
default_color = "#000000"
default_description = ""

# Default history params
default_history_params = {
    "max_age": None,
    "max_items": None,
    "expire_time": "inf",  # means "never expire"/"infinite validity", stored internally as None instead of timedelta
    "pre_validity": "0s",
    "post_validity": "0s",
    "aggregation_max_age": "0s",
    "aggregation_function_value": "keep",
    "aggregation_function_confidence": "avg",
    "aggregation_function_source": "csv_union"
}

# Default timeseries params
default_timeseries_params = {
    "max_age": None,
}

# Regular expressions for parsing various data types
re_timestamp = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?([Zz]|(?:[+-][0-9]{2}:[0-9]{2}))?$")
re_mac = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$")
re_array = re.compile(r"^array<(\w+)>$")
re_set = re.compile(r"^set<(\w+)>$")
re_link = re.compile(r"^link<(\w+)>$")
re_dict = re.compile(r"^dict<((\w+\??:\w+,)*(\w+\??:\w+))>$")


# Validate ipv4 string
def valid_ipv4(address):
    try:
        ipaddress.IPv4Address(address)
        return True
    except ValueError:
        return False


# Validate ipv6 string
def valid_ipv6(address):
    try:
        ipaddress.IPv6Address(address)
        return True
    except ValueError:
        return False


# Validate timestamp string
def valid_rfc3339(timestamp):
    return re_timestamp.match(timestamp)


# Validate MAC string
def valid_mac(address):
    return re_mac.match(address)


# Dictionary containing validator functions for primitive data types
validators = {
    "tag": lambda v: type(v) is bool,
    "binary": lambda v: type(v) is bool,
    "string": lambda v: type(v) is str,
    "int": lambda v: type(v) is int,
    "int64": lambda v: type(v) is int,
    "float": lambda v: type(v) is float,
    "ipv4": valid_ipv4,
    "ipv6": valid_ipv6,
    "mac": valid_mac,
    "time": valid_rfc3339,
    "special": lambda v: v is not None,
    "json": lambda v: v is not None  # TODO validate json format?
}


# Validate array object
def valid_array(obj, data_type):
    if type(obj) is not list:
        return False
    f = validators[data_type]
    for item in obj:
        if not f(item):
            return False
    return True


# Validate set object
def valid_set(obj, data_type):
    if type(obj) is not list:
        return False
    f = validators[data_type]
    for item in obj:
        if not f(item) or obj.count(item) > 1:
            return False
    return True


# Validate dict object
def valid_dict(obj, key_spec):
    if type(obj) is not dict:
        return False
    for key in key_spec:
        if key not in obj:
            if key[-1] == "?":
                continue
            else:
                return False
        f = validators[key_spec[key]]
        if not f(obj[key]):
            return False
    return True


# Validate probablity
def valid_probability(val, data_type):
    if type(val) is not dict:
        return False
    for key, prob in val.items():
        if not validators[data_type] or not isinstance(prob, float):
            return False
    return True


# This class represents specification of an attribute of given id
class AttrSpec:
    # Class constructor
    # Raises AssertionError if the specification is invalid
    def __init__(self, id: str, spec: dict[str, Any]) -> None:
        # Set default values for missing fields
        self.id = id
        self.type = spec.get("type", None)
        self.name = spec.get("name", self.id)
        self.description = spec.get("description", default_description)
        self.color = spec.get("color", default_color)
        self.history = False
        self.data_type = spec.get("data_type", None)
        self.categories = spec.get("categories", None)
        self.confidence = spec.get("confidence", False)
        self.multi_value = spec.get("multi_value", False)
        self.history_params = spec.get("history_params", None)
        self.probability = spec.get("probability", False)
        self.editable = spec.get("editable", False)
        self.history_force_graph = spec.get("history_force_graph", False)
        self.timeseries_type = spec.get("timeseries_type", None)
        self.series = spec.get("series", None)
        self.series_default = None
        self.series_nondefault = spec.get("series", None)
        self.time_step = spec.get("time_step", None)
        self.timeseries_params = spec.get("timeseries_params", default_timeseries_params)

        # Check common mandatory specification fields
        assert self.type is not None, err_msg_missing_field.format("type")
        assert self.id is not None, err_msg_missing_field.format("id")

        # Check validity of type
        assert self.type in attr_types, err_msg_value.format("type")

        # Check data type of common specification fields
        assert type(self.id) is str, err_msg_type.format("id", "str")
        assert type(self.name) is str, err_msg_type.format("name", "str")
        assert type(self.description) is str, err_msg_type.format("description", "str")
        assert type(self.color) is str, err_msg_type.format("color", "str")

        # Check color format
        assert re.match(r"#([0-9a-fA-F]){6}", self.color), err_msg_format.format("color")

        # Type-specific fields
        if (self.type == "plain" or
            self.type == "observations"):
            self.timeseries_type = None
            self.timeseries_params = None
            self.series = None

            assert self.data_type is not None, err_msg_missing_field.format("data_type")
            assert type(self.data_type) is str, err_msg_type.format("data_type", "str")
            assert type(self.confidence) is bool, err_msg_type.format("confidence", "bool")
            assert type(self.probability) is bool, err_msg_type.format("probability", "bool")
            assert type(self.editable) is bool, err_msg_type.format("editable", "bool")

            if self.probability:
                assert self.data_type in primitive_data_types, \
                    f"data type {self.data_type} is not supported as a probability (primitive types only)"

                self.value_validator = functools.partial(valid_probability, data_type=self.data_type)
            else:
                self._init_validator_function()

        if self.type == "plain":
            self.history = False
            self.multi_value = False
            self.history_params = None
            self.history_force_graph = False

        if self.type == "observations":
            self.history = True

            assert type(self.multi_value) is bool, err_msg_type.format("multi_value", "bool")
            assert type(self.history_force_graph) is bool, err_msg_type.format("history_force_graph", "bool")

            self._validate_history_params()

        if self.type == "timeseries":
            self.history = False
            self.data_type = None
            self.categories = None
            self.confidence = None
            self.multi_value = False
            self.history_params = None
            self.probability = False
            self.editable = False
            self.history_force_graph = False

            assert self.timeseries_type in timeseries_types, err_msg_value.format("timeseries_type")
            assert type(self.series) is dict, err_msg_type.format("series", "dict")

            if self.timeseries_type == "regular":
                assert type(self.time_step) is str, err_msg_type.format("time_step", "str")
                self.time_step = self._parse_time_duration_safe(self.time_step, "time_step")
            else:
                self.time_step = None

            self.series_default = timeseries_types[self.timeseries_type]["default_series"]
            self.series_nondefault = self.series

            # Automatically add default series
            self.series = { **self.series_nondefault, **self.series_default }

            for series_id in self.series:
                assert type(series_id) is str, err_msg_type.format(f"series identifier '{series_id}'", "str")
                assert type(self.series.get(series_id)) is dict, err_msg_type.format(f"series['{series_id}']", "dict")
                assert self.series[series_id].get("data_type") in primitive_data_types_series, \
                    err_msg_value.format(f"series['{series_id}']['data_type']")

            # Register dumb validator (validation will be done elsewhere)
            self.value_validator = lambda v: True

            self._validate_timeseries_params()

    def _init_validator_function(self) -> None:
        # Initialize attribute's validator function according to its data type
        if self.data_type in primitive_data_types:
            self.value_validator = validators[self.data_type]

        elif self.data_type == "category":
            if self.categories is None:
                self.value_validator = validators["string"]
            else:
                assert type(self.categories) is list, err_msg_type.format("categories", "list")
                self.value_validator = lambda v: v in self.categories

        elif re.match(re_array, self.data_type):
            element_type = self.data_type.split("<")[1].split(">")[0]
            assert element_type in primitive_data_types, f"data type {element_type} is not supported as an array element"
            self.value_validator = lambda v: valid_array(v, element_type)

        elif re.match(re_set, self.data_type):
            element_type = self.data_type.split("<")[1].split(">")[0]
            assert element_type in primitive_data_types, f"data type {element_type} is not supported as a set element"
            self.value_validator = lambda v: valid_set(v, element_type)

        elif re.match(re_link, self.data_type):
            # TODO
            # Should the entity type be validated here? I.e. does the specification for given entity type have to exist?
            self.value_validator = lambda v: v is not None

        elif re.match(re_dict, self.data_type):
            key_str = self.data_type.split("<")[1].split(">")[0]
            key_spec = dict(item.split(":") for item in key_str.split(","))
            for k in key_spec:
                assert key_spec[k] in primitive_data_types, f"data type {key_spec[k]} is not supported as a dict field"
            self.value_validator = lambda v: valid_dict(v, key_spec)

        else:
            raise AssertionError(f"data type '{self.data_type}' is not supported")

    def _validate_history_params(self) -> None:
        assert self.history_params is not None, err_msg_missing_field.format("history_params")
        assert type(self.history_params) is dict, err_msg_type.format("history_params", "dict")

        # Fill empty fields with default values (merge dictionaries)
        self.history_params = {**default_history_params, **self.history_params}

        if self.history_params["max_items"] is not None:
            assert type(self.history_params["max_items"]) is int, err_msg_type.format("max_items", "int")
            assert self.history_params["max_items"] > 0, err_msg_value.format("max_items")

        if self.history_params["max_age"] is not None:
            self.history_params["max_age"] = self._parse_time_duration_safe(self.history_params["max_age"], "max_age")

        if self.history_params["expire_time"] == "inf":  # "inf" in config file is stored as None
            self.history_params["expire_time"] = None
        else:
            self.history_params["expire_time"] = self._parse_time_duration_safe(self.history_params["expire_time"], "expire_time")

        self.history_params["pre_validity"] = self._parse_time_duration_safe(self.history_params["pre_validity"], "pre_validity")
        self.history_params["post_validity"] = self._parse_time_duration_safe(self.history_params["post_validity"], "post_validity")

        if "aggregation_interval" not in self.history_params:
            self.history_params["aggregation_interval"] = self.history_params["pre_validity"] + self.history_params["post_validity"]
        else:
            self.history_params["aggregation_interval"] = self._parse_time_duration_safe(self.history_params["aggregation_interval"], "aggregation_interval")

        self.history_params["aggregation_max_age"] = self._parse_time_duration_safe(self.history_params["aggregation_max_age"], "aggregation_max_age")

        assert self.history_params["aggregation_function_value"] in aggregation_functions, err_msg_format.format("aggregation_function_value")
        assert self.history_params["aggregation_function_confidence"] in aggregation_functions, err_msg_format.format("aggregation_function_confidence")
        assert self.history_params["aggregation_function_source"] in aggregation_functions, err_msg_format.format("aggregation_function_source")

    def _validate_timeseries_params(self) -> None:
        # assert self.timeseries_params is not None, err_msg_missing_field.format("timeseries_params")
        assert type(self.timeseries_params) is dict, err_msg_type.format("timeseries_params", "dict")

        # Fill empty fields with default values (merge dictionaries)
        self.timeseries_params = {**default_timeseries_params, **self.timeseries_params}

        if self.timeseries_params["max_age"] is not None:
            self.timeseries_params["max_age"] = self._parse_time_duration_safe(self.timeseries_params["max_age"],
                                                                               "max_age")

    @staticmethod
    def _parse_time_duration_safe(time_duration: str, field_id: str) -> timedelta:
        """Simple wrapper around `dp3.common.utils.parse_time_duration` function.

        Effectively only changes error class from ValueError to AssertionError
        and error message.
        """
        try:
            return parse_time_duration(time_duration)
        except ValueError:
            raise AssertionError(err_msg_format.format(field_id))


    def __repr__(self):
        """Return string whose evaluation would create the same object."""
        attrs = {
            "name": self.name,
            "type": self.type
        }

        # Optional common fields
        if self.description:
            attrs["description"] = self.description
        if self.color != default_color:
            attrs["color"] = self.color

        # Type-specific fields
        if (self.type == "plain" or
            self.type == "observations"):
            attrs["data_type"] = self.data_type
            attrs["confidence"] = self.confidence
            attrs["probability"] = self.probability
            attrs["editable"] = self.editable

            if self.categories:
                attrs["categories"] = self.categories

        if self.type == "plain":
            pass

        if self.type == "observations":
            attrs["multi_value"] = self.multi_value
            attrs["history_params"] = self.history_params
            attrs["history_force_graph"] = self.history_force_graph

        if self.type == "timeseries":
            attrs["timeseries_type"] = self.timeseries_type
            attrs["series"] = self.series_nondefault
            
            if self.timeseries_type == "regular":
                attrs["time_step"] = self.time_step

        return f"AttrSpec({self.id!r}, {attrs!r})"

    # TODO shorter and more readable __str__ representation?
