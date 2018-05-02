# -*- coding: utf-8 -*-

from fingerprinting.analysis.statistics import Statistics
from fingerprinting.analysis.wobj import WebObject
from fingerprinting.analysis.h2 import Http2Error, Http2Frame, Http2State


class Stream(object):

    def __init__(self, stream_id, packet):

        self.length = 0
        self.weight = 16
        self.frames = []
        self.objects = []
        self.id = stream_id
        self.packet = packet
        self.children = set()
        self.state = Http2State.IDLE
        self.statistics = Statistics()
        self.error = Http2Error.NO_ERROR

        packet.streams.append(stream_id)

        if packet.source_port == 443:
            self.direction = "S2C"
        else:
            self.direction = "C2S"

        self.parent = None
        self.last_seen = None
        self.first_seen = None
        self.window_size = None

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        return other and self.id == other.id

    def __ne__(self, other):
        return not self.__eq__(other)

    @property
    def endpoint(self):
        return self.packet.source

    def insert_child(self, stream):
        self.children.add(stream.id)

    def get_last_object(self):

        if len(self.objects) <= 0:
            raise Exception("[E] Received HEADERS/DATA frame before sending HEADERS!")
        else:
            return self.objects[-1]

    def get_last_timestamp(self, frame):

        return self.statistics.get_last_timestamp(frame)

    def insert_frame(self, frame):

        self.frames.append(frame)
        self.length += frame.length
        self.statistics.insert_frame(frame)

    def update_information(self, window_size):

        self.frames.sort(key=lambda frame: frame.timestamp)

        if not self.window_size:
            self.window_size = window_size

        if len(self.frames) > 0:
            self.frames[-1].packet.streams_closed.append(self.id)

        self.first_seen = self.frames[0].timestamp
        self.last_seen = self.frames[-1].timestamp
        [self.process_frame(f, f.type) for f in self.frames]

    def process_frame(self, frame, frame_type):

        if frame_type == Http2Frame.DATA:
            self.handle_data_frame(frame)
        elif frame_type == Http2Frame.HEADERS:
            self.handle_headers_frame(frame)
        elif frame_type == Http2Frame.PRIORITY:
            self.handle_priority_frame(frame)
        elif frame_type == Http2Frame.WINDOW_UPDATE:
            self.handle_window_update_frame(frame)
        elif frame_type == Http2Frame.PUSH_PROMISE:
            self.handle_push_promise_frame(frame)
        elif frame_type == Http2Frame.RST_STREAM:
            self.handle_rst_stream_frame()

    def handle_data_frame(self, frame):

        if frame.end_stream:
            self.handle_endstream_flag(frame.endpoint)

        if len(self.objects) == 0 or self.objects[-1].finished:
            self.objects.append(WebObject(frame))

        self.objects[-1].handle_data(frame)

    def handle_headers_frame(self, frame):

        if self.state == Http2State.IDLE:
            self.state = Http2State.OPEN
        elif self.state == Http2State.RESERVED_LOCAL and frame.endpoint == self.endpoint:
            self.state = Http2State.HALF_CLOSED_REMOTE
        elif self.state == Http2State.RESERVED_REMOTE and frame.endpoint != self.endpoint:
            self.state = Http2State.HALF_CLOSED_LOCAL

        if frame.priority and frame.weight >= 0:
            self.handle_priority_frame(frame)

        if frame.end_stream:
            self.handle_endstream_flag(frame.endpoint)

        if len(self.objects) == 0 or self.objects[-1].finished:
            self.objects.append(WebObject(frame))

        self.objects[-1].handle_headers(frame)

    def handle_push_promise_frame(self, frame):

        if self.state == Http2State.IDLE and frame.endpoint == self.endpoint:
            self.state = Http2State.RESERVED_LOCAL
        elif self.state == Http2State.IDLE and frame.endpoint != self.endpoint:
            self.state = Http2State.RESERVED_REMOTE

    def handle_priority_frame(self, frame):

        if frame.weight >= 0:
            self.weight = frame.weight

        if frame.exclusive:
            self.handle_exclusive_flag()

    def handle_rst_stream_frame(self):

        if self.state == Http2State.RESERVED_LOCAL or \
                self.state == Http2State.RESERVED_REMOTE or \
                self.state == Http2State.HALF_CLOSED_LOCAL or \
                self.state == Http2State.HALF_CLOSED_REMOTE:
            self.state = Http2State.CLOSED

    def handle_window_update_frame(self, frame):

        if frame.window_size >= 0:
            self.window_size += frame.window_size

    def handle_exclusive_flag(self):

        siblings = self.parent.children.difference({self.id})
        self.children.update(siblings)
        self.parent.children.difference_update(siblings)

        for stream in self.children:
            stream.parent = self

    def handle_endstream_flag(self, endpoint):

        if self.state == Http2State.OPEN and endpoint == self.endpoint:
            self.state = Http2State.HALF_CLOSED_LOCAL
        elif self.state == Http2State.OPEN and endpoint != self.endpoint:
            self.state = Http2State.HALF_CLOSED_REMOTE
        elif (self.state == Http2State.HALF_CLOSED_LOCAL and endpoint != self.endpoint) or \
                (self.state == Http2State.HALF_CLOSED_REMOTE and endpoint == self.endpoint):
            self.state = Http2State.CLOSED

    def serialize(self):

        return {
            "length": self.length,
            "weight": self.weight,
            "error": self.error.name,
            "state": self.state.name,
            "endpoint": self.endpoint,
            "direction": self.direction,
            "last_seen": self.last_seen,
            "first_seen": self.first_seen,
            "window_size": self.window_size,
            "statistics": self.statistics.serialize(),
            "children": [stream_id for stream_id in self.children],
            "parent": None if self.parent is None else self.parent.id,
            "frames": {frame.id: frame.get_summary() for frame in self.frames},
            "objects": [web_object.serialize() for web_object in self.objects],
        }
