# -*- coding: utf-8 -*-

from fingerprinting.analysis.h2 import Http2Frame


class Statistics(object):

    def __init__(self):

        self.total_count = 0
        self.total_length = 0

        self.mapping = {
            frame_type: dict(count=0, length=0, timestamp=0.0)
            for frame_type in Http2Frame
        }

    def insert_frame(self, frame):

        self.total_count += 1
        self.total_length += frame.length
        self.mapping[frame.type]["count"] += 1
        self.mapping[frame.type]["length"] += frame.length

        if frame.timestamp > self.mapping[frame.type]["timestamp"]:
            self.mapping[frame.type]["timestamp"] = frame.timestamp

    def get_last_timestamp(self, frame):

        return self.mapping[frame.type]["timestamp"]

    def get_statistics(self, mapping):

        return {
            "count": mapping["count"],
            "length": mapping["length"],
            "timestamp": mapping["timestamp"],
            "relative_count": (mapping["count"] / self.total_count) * 100,
            "relative_length": (mapping["length"] / self.total_length) * 100
        }

    def serialize(self):

        return {
            k.name: self.get_statistics(v)
            for k, v in self.mapping.items()
        }
