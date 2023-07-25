#!/usr/bin/python3
"""
Crete Flow time series (FTS) for future analysis from NEMEA IFC.

author: Josef Koumar
e-mail: koumajos@fit.cvut.cz, koumar@cesnet.cz

Copyright (C) 2023 CESNET

LICENSE TERMS

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
    1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    3. Neither the name of the Company nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

ALTERNATIVELY, provided that this notice is retained in full, this product may be distributed under the terms of the GNU General Public License (GPL) version 2 or later, in which case the provisions of the GPL apply INSTEAD OF those given above.

This software is provided as is'', and any express or implied warranties, including, but not limited to, the implied warranties of merchantability and fitness for a particular purpose are disclaimed. In no event shall the company or contributors be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, procurement of substitute goods or services; loss of use, data, or profits; or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this software, even if advised of the possibility of such damage.
"""
# Standard libraries imports
import os
import sys
import argparse
from argparse import RawTextHelpFormatter

# NEMEA system library
import pytrap

from pprint import pprint


def create_basic_datapoint(
    packets: int, bytes: int, start_time: float, end_time: float
):
    """Create datapoint from flow record from NEMEA system.

    Args:
        rec (pytrap.UnirecTemplate): Flow record.

    Returns:
        dict: Datapoint for time series.
    """
    return {
        "packets": packets,
        "bytes": bytes,
        "start_time": start_time,
        "end_time": end_time,
    }


def create_time_series():
    """Create time series dictionary for build time series.

    Returns:
        dict: Datapoint for time series.
    """
    return {
        "packets": [],
        "bytes": [],
        "start_time": [],
        "end_time": [],
    }


def append_basic_datapoint(datapoint: dict, time_series: dict):
    time_series["packets"].append(datapoint["packets"])
    time_series["bytes"].append(datapoint["bytes"])
    time_series["start_time"].append(datapoint["start_time"])
    time_series["end_time"].append(datapoint["end_time"])


def build_time_series(
    time_series: dict, packets: int, bytes: int, start_time: float, end_time: float
):
    """Function take flow record and handl creating and adding new datapoint into time series.

    Args:
        time_series (dict): _description_
        packets (int): _description_
        bytes (int): _description_
        start_time (float): _description_
        end_time (float): _description_
    """
    datapoint = create_basic_datapoint(packets, bytes, start_time, end_time)
    append_basic_datapoint(datapoint, time_series)


def proces_flow(
    time_series: dict,
    id_dependency: str,
    packets: int,
    bytes: int,
    start_time: float,
    end_time: float,
):
    if id_dependency not in time_series:
        time_series[id_dependency] = create_time_series()
    build_time_series(time_series[id_dependency], packets, bytes, start_time, end_time)


def load_pytrap(argv: list):
    """Init nemea libraries and set format of IP flows.

    Returns:
        tuple: Return tuple of rec and trap. Where rec is template of IP flows and trap is initialized pytrap NEMEA library.
    """
    trap = pytrap.TrapCtx()
    trap.init(argv, 1, 0)  # argv, ifcin - 1 input IFC, ifcout - 0 output IFC
    # Set the list of required fields in received messages.
    # This list is an output of e.g. flow_meter - basic flow.
    inputspec = "string ID_DEPENDENCY,ipaddr DST_IP,ipaddr SRC_IP,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint32 PACKETS_REV,uint64 BYTES,uint64 BYTES_REV,uint16 DST_PORT,uint16 SRC_PORT,uint8 PROTOCOL"
    trap.setRequiredFmt(0, pytrap.FMT_UNIREC, inputspec)
    rec = pytrap.UnirecTemplate(inputspec)
    return rec, trap


def make_output(time_series: dict):
    """Create output for time series in JSON file format.

    Args:
        time_series (dict): Time series in dictionary format.
        arg (argparse.Namespace): Arguments of module.
        cnt (int): Count of file.
    """
    for key in time_series:
        print(f"key = '{key}'")
        print("")
        print(f"packets = {time_series[key]['packets']}")
        print(f"bytes = {time_series[key]['bytes']}")
        # print(f"bytes = {time_series[key]['start_time']}")
        # print(f"bytes = {time_series[key]['end_time']}")
        print("")
        print("")
        print("")


def parse_arguments():
    """Function for set arguments of module.

    Returns:
        argparse: Return setted argument of module.
    """
    parser = argparse.ArgumentParser(
        description="""

    Usage:""",
        formatter_class=RawTextHelpFormatter,
    )

    parser.add_argument(
        "-i",
        help='Specification of interface types and their parameters, see "-h trap" (mandatory parameter).',
        type=str,
        metavar="IFC_SPEC",
    )

    parser.add_argument("-v", help="Be verbose.", action="store_true")

    parser.add_argument("-vv", help="Be more verbose.", action="store_true")

    parser.add_argument("-vvv", help="Be even more verbose.", action="store_true")

    arg = parser.parse_args()
    return arg


def main():
    """Main function of the module."""
    arg = parse_arguments()
    rec, trap = load_pytrap(sys.argv)
    time_series = {}
    try:
        while True:  # main loop for load ip-flows from interfaces
            try:  # load IP flow from IFC interface
                data = trap.recv()
            except pytrap.FormatChanged as e:
                fmttype, inputspec = trap.getDataFmt(0)
                rec = pytrap.UnirecTemplate(inputspec)
                data = e.data
                biflow = None
            if len(data) <= 1:
                break
            rec.setData(data)  # set the IP flow to created tempalte
            # proces flow to add to time series
            proces_flow(
                time_series,
                rec.ID_DEPENDENCY,
                rec.PACKETS + rec.PACKETS_REV,
                rec.BYTES + rec.BYTES_REV,
                float(rec.TIME_FIRST),
                float(rec.TIME_LAST),
            )
    except KeyboardInterrupt:
        print(f"End creating time series")
    print("")
    print(len(time_series.keys()))
    print("")
    hist = {}
    for key in time_series.keys():
        tmp = len(time_series[key]["packets"])
        if tmp not in hist:
            hist[tmp] = 0
        hist[tmp] += 1
    pprint(hist)
    # make_output(time_series)

    trap.finalize()  # Free allocated TRAP IFCs


if __name__ == "__main__":
    main()
