# -*- coding: utf-8 -*-

import os
import sys
import subprocess


def get_process_path():

    possible_paths = []

    if sys.platform.startswith("win"):

        for location in ("ProgramFiles(x86)", "ProgramFiles"):
            path = os.path.join(os.getenv(location), "Wireshark", "tshark.exe")
            possible_paths.append(path)

    else:

        os_path = os.getenv("PATH", "/usr/bin:/usr/sbin:/usr/lib/tshark:/usr/local/bin")

        for path in os_path.split(":"):
            possible_paths.append(os.path.join(path, "tshark"))

    for path in possible_paths:
        if os.path.exists(path):
            return path

    raise Exception("TShark executable not found.")


class FileCapture(object):

    def __init__(self, input_filename, display_filter=None, disable_protocol=None, override_prefs=None):

        self.input_filename = input_filename
        self._override_prefs = override_prefs
        self._display_filter = display_filter
        self._disable_protocol = disable_protocol

    def get_tshark_process(self):

        return subprocess.Popen(self.get_parameters(),
                                stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)

    def param_path(self):
        return [get_process_path()]

    def param_input(self):
        return ["-2", "-l", "-nr", self.input_filename]

    def param_output(self):
        return ["-T", "pdml"]

    def get_parameters(self):

        parameters = self.param_path()

        parameters += self.param_input()

        if self._display_filter:
            parameters += ["-Y", self._display_filter]

        if self._override_prefs:
            for preference_name, preference_value in self._override_prefs.items():
                parameters += ["-o", "{0}:{1}".format(preference_name, preference_value)]

        if self._disable_protocol:
            parameters += ["--disable-protocol", self._disable_protocol.strip()]

        parameters += self.param_output()

        return parameters

#tshark -2 -l -nr test/firefox-1.pcap -T fields -e ip.src -e ip.dst -e tcp.stream ssl.handshake.extensions_alpn_str == h2 and ssl.handshake.type==1


class TSharkEnumerateTCPStreams(FileCapture):

    def __init__(self, input_filename, display_filter="ssl.handshake.extensions_alpn_str == h2 and ssl.handshake.type==1", disable_protocol=None, override_prefs=None):
        FileCapture.__init__(self, input_filename, display_filter, disable_protocol, override_prefs)

    def param_output(self):
        return ["-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.stream"]
