#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess

from xml.etree import ElementTree

from fingerprinting.common import utils
from fingerprinting.application import Application
from fingerprinting.common.tshark import FileCapture

# configure tshark helper functions

def display_filter_iprange(lower_bound, upper_bound):
    return "ssl && \
        ip.src >= {lb} && ip.src <= {ub} && \
        ip.dst >= {lb} && ip.dst <= {ub}".format(lb=lower_bound, ub=upper_bound)

def override_prefs_baseline():
    return {
        "tcp.desegment_tcp_streams": "TRUE",
        "ssl.desegment_ssl_records": "TRUE",
        "ssl.desegment_ssl_application_data": "TRUE",
    }

def stitch_last_record_with_editpcap(filename):
    editcap_filename = filename + ".tmp"
    subprocess.Popen(
        ["editcap", "-d", "-F", "pcap", filename, editcap_filename],
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL
    ).wait()

    return editcap_filename

def analyze_single_capture(display_filter, override_prefs, editcap_filename):

    capture = FileCapture(
        display_filter=display_filter,
        override_prefs=override_prefs,
        input_filename=editcap_filename
    ).get_tshark_process().stdout

    state = Application()
    state.parse_xml(ElementTree.parse(capture))
    os.remove(editcap_filename)
    return state

def save_analysis(state, output_directory):
    state.serialize(output_directory)

def process_single_capture(filename, testname = ""):
    # tshark configs
    # 1
    display_filter = display_filter_iprange("172.18.0.0", "172.18.0.255")
    # 2
    override_prefs = override_prefs_baseline()
    override_prefs["ssl.keylog_file"] = utils.replace_extension(filename, "log")
    # 3
    editcap_filename = stitch_last_record_with_editpcap(filename)

    state = analyze_single_capture(display_filter, override_prefs, editcap_filename)

    output_directory = utils.get_output_directory(filename) + "_" + testname
    utils.create_output_directory(output_directory)
    save_analysis(state, output_directory)


def process_single_capture_notlskeys(filename, testname = ""):

    # tshark configs
    # 1
    display_filter = display_filter_iprange("172.18.0.0", "172.18.0.255")
    # 2
    override_prefs = override_prefs_baseline()
    # 3
    editcap_filename = stitch_last_record_with_editpcap(filename)

    state = analyze_single_capture(display_filter, override_prefs, editcap_filename)

    output_directory = utils.get_output_directory(filename) + "_" + testname
    utils.create_output_directory(output_directory)
    save_analysis(state, output_directory)
