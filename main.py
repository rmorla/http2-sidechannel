#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess

from xml.etree import ElementTree

from fingerprinting.common import utils
from fingerprinting.application import Application
from fingerprinting.common.tshark import FileCapture

from processpcaps.analyze import process_single_capture

if __name__ == "__main__":

    if len(sys.argv) == 2 and os.path.isdir(sys.argv[1]):
        utils.walk_directory(sys.argv[1], process_single_capture)
    elif len(sys.argv) == 2 and utils.validate_extension(sys.argv[1], "pcap"):
        process_single_capture(os.path.abspath(sys.argv[1]))
    else:
        print("usage: %s [<pcap_directory_or_file>]" % sys.argv[0])
