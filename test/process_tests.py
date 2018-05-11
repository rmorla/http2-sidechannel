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
from processpcaps.analyze import process_single_capture_notlskeys

def firefox1 ():
    filename = os.path.abspath("./test/firefox-1.pcap")
    print (filename)
    #process_single_capture(filename, "withtlskeys")
    process_single_capture_notlskeys(os.path.abspath("./test/firefox-1.pcap"), "withouttlskeys")
