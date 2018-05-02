# -*- coding: utf-8 -*-

from fingerprinting.analysis.h2 import Http2Error
from fingerprinting.analysis.record import TlsHandshakeType


class Connection(object):

    def __init__(self):

        self.last_stream = 0
        self.first_stream = 0
        self.terminated = False
        self.client_address = ""
        self.client_streams = []
        self.server_address = ""
        self.server_streams = []
        self.error = Http2Error.NO_ERROR

    def terminate(self, frame):

        self.terminated = True
        self.error = frame.error

    def serialize(self):

        base_dictionary = vars(self)
        base_dictionary["error"] = self.error.name
        return base_dictionary

    def process_stream(self, stream_id, stream_direction):

        if stream_id < self.first_stream:
            self.first_stream = stream_id

        if self.last_stream < stream_id:
            self.last_stream = stream_id

        if stream_direction == "C2S":
            self.client_streams.append(stream_id)
        elif stream_direction == "S2C":
            self.server_streams.append(stream_id)

    def process_handshake(self, packet, handshake):

        if handshake == TlsHandshakeType.CLIENT_HELLO:
            self.client_address = packet.source
        elif handshake == TlsHandshakeType.SERVER_HELLO:
            self.server_address = packet.source
