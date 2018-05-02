#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess

from xml.etree import ElementTree

from fingerprinting.common import utils
from fingerprinting.application import Application
from fingerprinting.common.tshark import FileCapture


def process_single_capture(filename):

    print("[>] %s" % filename)
    editcap_filename = filename + ".tmp"

    display_filter = "ssl && \
        ip.src >= {lb} && ip.src <= {ub} && \
        ip.dst >= {lb} && ip.dst <= {ub}".format(lb="172.18.0.0", ub="172.18.0.255")

    override_prefs = {
        "tcp.desegment_tcp_streams": "TRUE",
        "ssl.desegment_ssl_records": "TRUE",
        "ssl.desegment_ssl_application_data": "TRUE",
        "ssl.keylog_file": utils.replace_extension(filename, "log")
    }

    subprocess.Popen(
        ["editcap", "-d", "-F", "pcap", filename, editcap_filename],
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL
    ).wait()

    output_directory = utils.get_output_directory(filename)
    utils.create_output_directory(output_directory)

    capture = FileCapture(
        display_filter=display_filter,
        override_prefs=override_prefs,
        input_filename=editcap_filename
    ).get_tshark_process().stdout

    state = Application()
    state.parse_xml(ElementTree.parse(capture))
    utils.write_pickle(utils.replace_extension(filename, "yml"), state)
    state.serialize(output_directory)
    os.remove(editcap_filename)


if __name__ == "__main__":

    if len(sys.argv) == 2 and os.path.isdir(sys.argv[1]):
        utils.walk_directory(sys.argv[1], process_single_capture)
    elif len(sys.argv) == 2 and utils.validate_extension(sys.argv[1], "pcap"):
        process_single_capture(os.path.abspath(sys.argv[1]))
    else:
        print("usage: %s [<pcap_directory_or_file>]" % sys.argv[0])
