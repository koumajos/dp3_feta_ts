#!/usr/bin/python3
"""
Analyze IP flows to get information about use of dependencies between devices in (private) networks.
Add dependency info to flows and send flows to output.

author: Josef Koumar
e-mail: koumajos@fit.cvut.cz

Copyright (C) 2022 CESNET

LICENSE TERMS

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
    1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    3. Neither the name of the Company nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

ALTERNATIVELY, provided that this notice is retained in full, this product may be distributed under the terms of the GNU General Public License (GPL) version 2 or later, in which case the provisions of the GPL apply INSTEAD OF those given above.

This software is provided as is'', and any express or implied warranties, including, but not limited to, the implied warranties of merchantability and fitness for a particular purpose are disclaimed. In no event shall the company or contributors be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, procurement of substitute goods or services; loss of use, data, or profits; or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this software, even if advised of the possibility of such damage.
"""
# Standard libraries imports
import sys
import os
import csv
import argparse
from argparse import RawTextHelpFormatter

# NEMEA system library
import pytrap


def check_port(port: int, ports_tb: dict):
    """Check if port used in dependency is service or registered.

    Args:
        port (int): Integer of used port by device.
        ports_tb (dic): Dictionary contains registered port defined by IANA and ICAN.

    Returns:
        bool: True if port is service or registered.
    """
    p = ports_tb.get(port)
    if p is not None:
        if p == "":
            return False
        return True
    return False


def recognize_dependency(ports_tb: dict, src_ip, src_port, dst_ip, dst_port):
    """Recognize dependency and return it.

    Args:
        rec (UNIREC): IP flow record.
        ports_tb (dict): Dictionary of protocol numbers and names registered by IANA and ICAN.

    Returns:
        str: Dependency.
    """
    if check_port(src_port, ports_tb) and check_port(dst_port, ports_tb):
        if dst_port < 1024:
            return f"{dst_ip}({dst_port})-{src_ip}"
        else:
            return f"{src_ip}({src_port})-{dst_ip}"
    elif check_port(dst_port, ports_tb):
        return f"{dst_ip}({dst_port})-{src_ip}"
    elif check_port(src_port, ports_tb):
        return f"{src_ip}({src_port})-{dst_ip}"
    elif dst_port < 1024 and src_port < 1024:
        if src_port < dst_port:
            return f"{src_ip}({src_port})-{dst_ip}"
        else:
            return f"{dst_ip}({dst_port})-{src_ip}"
    elif src_port < 1024:
        return f"{src_ip}({src_port})-{dst_ip}"
    elif dst_port < 1024:
        return f"{dst_ip}({dst_port})-{src_ip}"
    elif src_port < 49152 and dst_port >= 49152:
        return f"{src_ip}({src_port})-{dst_ip}"
    elif dst_port < 49152 and src_port >= 49152:
        return f"{dst_ip}({dst_port})-{src_ip}"
    else:
        if src_port < dst_port:
            return f"{src_ip}({src_port}*)-{dst_ip}"
        else:
            return f"{dst_ip}({dst_port}*)-{src_ip}"
        # return f"{src_ip}({src_port}-{dst_port})-{dst_ip}"


def load_pytrap(argv: list):
    """Init nemea libraries and set format of IP flows.

    Returns:
        tuple: Return tuple of rec and trap. Where rec is template of IP flows and trap is initialized pytrap NEMEA library.
    """
    trap = pytrap.TrapCtx()
    trap.init(argv, 1, 1)  # argv, ifcin - 1 input IFC, ifcout - 1 output IFC
    # Set the list of required fields in received messages.
    # This list is an output of e.g. flow_meter - basic flow.
    inputspec = "ipaddr DST_IP,ipaddr SRC_IP,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint32 PACKETS_REV,uint64 BYTES,uint64 BYTES_REV,uint16 DST_PORT,uint16 SRC_PORT,uint8 PROTOCOL"
    trap.setRequiredFmt(0, pytrap.FMT_UNIREC, inputspec)
    rec = pytrap.UnirecTemplate(inputspec)

    alertspec = "string ID_DEPENDENCY,ipaddr DST_IP,ipaddr SRC_IP,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint32 PACKETS_REV,uint64 BYTES,uint64 BYTES_REV,uint16 DST_PORT,uint16 SRC_PORT,uint8 PROTOCOL"
    alert = pytrap.UnirecTemplate(alertspec)
    trap.setDataFmt(0, pytrap.FMT_UNIREC, alertspec)
    alert.createMessage()
    return rec, trap, alert


def parse_arguments():
    """Parse program arguments using the argparse module.

    Returns:
        Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="""Module for add information about Network Dependency for each flow. Supported inputs of flows are NEMEA IFC, flow CSV file.

    Usage:""",
        formatter_class=RawTextHelpFormatter,
    )

    parser.add_argument(
        "-i",
        help='Specification of interfaces types and their parameters, see "-h trap".',
        type=str,
        metavar="IFC_SPEC",
    )
    parser.add_argument(
        "-P",
        "--ports",
        help="Set the name with suffix of file, where are safe registered ports (default: Ports.csv). File must be .csv",
        type=str,
        metavar="NAME.SUFFIX",
        default="Ports.csv",
    )
    arg = parser.parse_args()
    return arg


def ports_convert_to_int(port: str):
    try:
        return int(port)
    except:
        return port


def load_table_ports(filename: str):
    """Load ports table, that contain ports registered by IANA and ICANN, from csv and return it as dictionary.

    Returns:
        dictionary: Loaded ports table as a dictionary (port->service_name).
    """
    if filename.endswith(".csv") is False:
        print("The filename of table contains services haven't suffix or isn't .csv")
        sys.exit(1)
    if os.path.isfile(filename) is False:
        print(f"The file with name {filename} doesn't exists.")
        sys.exit(1)
    try:
        with open(filename, mode="r", encoding="utf-8") as infile:
            reader = csv.reader(infile)
            reg_ports = dict(
                (ports_convert_to_int(rows[1]), rows[0]) for rows in reader
            )
        return reg_ports
    except Exception as e:
        print(f"Error in loading file {filename}: {e}")
        sys.exit(1)


def main():
    """Main function of the module."""
    arg = parse_arguments()
    rec, trap, alert = load_pytrap(sys.argv)
    ports_tb = load_table_ports(arg.ports)
    while True:  # main loop for load ip-flows from interfaces
        try:  # load IP flow from IFC interface
            data = trap.recv()
        except pytrap.FormatChanged as e:
            fmttype, inputspec = trap.getDataFmt(0)
            rec = pytrap.UnirecTemplate(inputspec)
            data = e.data
        if len(data) <= 1:
            trap.send(data)
            break
        rec.setData(data)
        dependency = recognize_dependency(
            ports_tb, rec.SRC_IP, rec.SRC_PORT, rec.DST_IP, rec.DST_PORT
        )
        alert.ID_DEPENDENCY = dependency
        alert.SRC_IP = rec.SRC_IP
        alert.DST_IP = rec.DST_IP
        alert.TIME_FIRST = rec.TIME_FIRST
        alert.TIME_LAST = rec.TIME_LAST
        alert.PACKETS = rec.PACKETS
        alert.PACKETS_REV = rec.PACKETS_REV
        alert.BYTES = rec.BYTES
        alert.BYTES_REV = rec.BYTES_REV
        alert.SRC_PORT = rec.SRC_PORT
        alert.DST_PORT = rec.DST_PORT
        alert.PROTOCOL = rec.PROTOCOL
        trap.send(alert.getData(), 0)
    trap.finalize()  # Free allocated TRAP IFCs


if __name__ == "__main__":
    main()
