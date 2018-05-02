# -*- coding: utf-8 -*-

import os

from fingerprinting.common import utils

from fingerprinting.analysis.h2f import Frame
from fingerprinting.analysis.h2s import Stream
from fingerprinting.analysis.h2 import Http2Frame
from fingerprinting.analysis.packet import Packet
from fingerprinting.analysis.parser import XmlWrapper
from fingerprinting.analysis.connection import Connection
from fingerprinting.analysis.statistics import Statistics


class Application(object):

    def __init__(self):

        self.frames = {}
        self.packets = {}
        self.streams = {}
        self.records = []
        self.connection = Connection()
        self.statistics = Statistics()

        self.settings = {
            "ENABLE_PUSH": 1,
            "MAX_FRAME_SIZE": 16384,
            "HEADER_TABLE_SIZE": 4096,
            "MAX_HEADER_LIST_SIZE": -1,
            "INITIAL_WINDOW_SIZE": 65536,
            "MAX_CONCURRENT_STREAMS": -1
        }

    def parse_xml(self, capture):

        [self.process_layers(proto) for proto in capture.getroot()]
        self.analyze_streams()
        self.analyze_packets()

    def analyze_packets(self):

        for packet in self.packets.values():

            packet.streams_active = [
                stream.id
                for stream in self.streams.values()
                if stream.first_seen <= packet.time_relative <= stream.last_seen
            ]

    def analyze_streams(self):

        for stream in self.streams.values():
            window_size = self.settings["INITIAL_WINDOW_SIZE"]
            stream.update_information(window_size)

    def serialize(self, directory):

        utils.write_yaml(os.path.join(directory, "stats.yaml"), {
            "settings": self.settings,
            "frames": self.statistics.serialize(),
            "connection": self.connection.serialize(),
        })

        utils.write_yaml(os.path.join(directory, "streams.yaml"), {
            k: v.serialize() for k, v in self.streams.items()
        })

        utils.write_yaml(os.path.join(directory, "packets.yaml"), {
            k: v.serialize() for k, v in self.packets.items()
        })

        utils.write_yaml(os.path.join(directory, "frames.yaml"), {
            k: v.serialize() for k, v in self.frames.items()
        })

        utils.write_pickle(os.path.join(directory, "all.yaml"), self)

    def insert_frames(self, packet, layer, layer_id):

        if type(layer) is list:
            for sublayer_id, sublayer in enumerate(layer):
                self.insert_frame(packet, sublayer, layer_id, sublayer_id)
        else:
            self.insert_frame(packet, layer, layer_id, 0)

    def insert_packet(self, packet):

        self.packets[packet.id] = packet

        if len(packet.frames) > 0:
            packet.process_mapssl2http2()

        for record in packet.handshakes:
            self.connection.process_handshake(packet, record.handshake)

    def associate_with_stream(self, packet, frame):

        stream_id = frame.stream_id

        if stream_id in self.streams:
            stream = self.streams[stream_id]
        else:
            stream = Stream(stream_id, packet)
            self.streams[stream_id] = stream
            self.connection.process_stream(stream_id, stream.direction)

        # if frame.direction == "S2C":
        #    self.graph.insert_server_stream(stream_id)
        # else:
        #    self.graph.insert_client_stream(stream_id)

        stream.insert_frame(frame)

        if frame.type == Http2Frame.SETTINGS:
            self.handle_settings(stream, frame)
        elif frame.type == Http2Frame.GO_AWAY:
            self.handle_goaway(stream, frame)
        elif frame.type == Http2Frame.PRIORITY or (frame.type == Http2Frame.HEADERS and frame.priority):
            self.handle_priority(stream, frame)

    def handle_goaway(self, stream, frame):

        if stream.id == 0 and frame.timestamp >= stream.get_last_timestamp(frame):
            self.connection.terminate(frame)

    def handle_priority(self, stream, frame):

        parent = self.streams[frame.stream_dependency]
        # self.graph.insert_dependency(stream.id, frame.stream_dependency)

        if isinstance(parent, Stream):
            stream.parent = parent
            parent.insert_child(stream)

    def handle_settings(self, stream, frame):

        last_timestamp = stream.get_last_timestamp(frame)

        if frame.settings and frame.timestamp >= last_timestamp:
            self.settings.update(frame.settings)

    def insert_frame(self, packet, layer, layer_id, sublayer_id):

        frame = Frame.parse(packet, layer, layer_id, sublayer_id)
        packet.insert_frame(frame)
        self.frames[frame.id] = frame
        self.statistics.insert_frame(frame)
        self.associate_with_stream(packet, frame)

    def process_layers(self, layers):

        relevant_packet = False
        packet = Packet(XmlWrapper(layers))
        print(packet.id, end="...", flush=True)

        for layer_id, layer in enumerate(layers):

            layer_name = layer.attrib["name"]

            if layer_name == "ssl":

                last_ssl_record = None

                for sublayer_id, sublayer in enumerate(layer):

                    sublayer_name = sublayer.attrib["name"]

                    if sublayer_name == "ssl.record":
                        print("ssl.record @ %d, %d" % (layer_id, sublayer_id))
                        last_ssl_record = packet.insert_ssl_record(XmlWrapper(sublayer), layer_id, sublayer_id)
                        self.records.append(last_ssl_record)
                    elif sublayer_name == "ssl.segment.data":
                        print("ssl.segment.data @ %d, %d" % (layer_id, sublayer_id))
                        last_ssl_record.insert_segment_data(int(sublayer.attrib["size"]))

                relevant_packet = True

            elif layer_name == "http2":

                for sublayer_id, sublayer in enumerate(layer):

                    if sublayer.attrib["name"] != "http2.stream":
                        continue

                    print("http2.stream @ %d, %d" % (layer_id, sublayer_id))
                    self.insert_frame(packet, XmlWrapper(sublayer), layer_id, sublayer_id)

                relevant_packet = True

            elif layer_name == "fake-field-wrapper":

                for sublayer_id, sublayer in enumerate(layer):

                    if sublayer.attrib["name"] != "ssl.segments":
                        continue

                    print("ssl.segments @ %d, %d" % (layer_id, sublayer_id))
                    packet.insert_fake_segment(XmlWrapper(sublayer), layer_id, sublayer_id)

                relevant_packet = True

        if relevant_packet:
            self.insert_packet(packet)
