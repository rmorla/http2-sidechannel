# -*- coding: utf-8 -*-

from fingerprinting.analysis.parser import XmlWrapper
from fingerprinting.analysis.h2 import Http2Error, Http2Frame, Http2Settings


class SslSegmentIndex(object):

    def __init__(self, record_id, record_size, segment_id, segment_size):

        self.record_id = record_id
        self.record_size = record_size
        self.segment_id = segment_id
        self.segment_size = segment_size
        self.bytecount_start = 0
        self.bytecount_finish = 0
        self.content_length = 0


class Frame(object):

    INSTANCE_COUNTER = 0

    def __init__(self, packet, layer, layer_id, sublayer_id):

        Frame.INSTANCE_COUNTER += 1

        if packet.source_port == 443:
            self.direction = "S2C"
        else:
            self.direction = "C2S"

        self.last_ssl_record = None
        self.packet = packet
        self.layer_id = layer_id
        self.bytecount_start = 0
        self.bytecount_finish = 0
        self.sublayer_id = sublayer_id
        self.id = Frame.INSTANCE_COUNTER

        if layer.exists("http2.streamid"):
            self.type = Http2Frame(layer.integer("http2.type"))
            self.stream_id = layer.integer("http2.streamid")
            self.body = layer.integer("http2.length")
            self.length = self.body + 9
        else:
            self.body = 0
            self.length = 24
            self.stream_id = 0
            self.type = Http2Frame.MAGIC

        self.ssl_segment_indices = []
        self.ssl_segment_reassembly = []

    @property
    def endpoint(self):
        return self.packet.source

    @property
    def timestamp(self):
        return self.packet.time_relative

    def insert_unique_segment(self, record, segment_id):

        self.ssl_segment_indices.append(SslSegmentIndex(
            record.id,
            record.lengths["total"],
            segment_id,
            self.length,
        ))

    def insert_reassembled_segment(self, record_id, record_length, segment_id, segment_length):

        self.ssl_segment_indices.append(SslSegmentIndex(
            record_id,
            record_length,
            segment_id,
            segment_length
        ))

    def serialize(self):

        return {
            "body": self.body,
            "length": self.length,
            "type": self.type.name,
            "packet": self.packet.id,
            "stream": self.stream_id,
            "record": self.last_ssl_record.id if self.last_ssl_record else None,
            "direction": self.direction,
            "timestamp": self.timestamp,
        }

    def get_summary(self):

        return {
            "length": self.length,
            "type": self.type.name,
            "direction": self.direction,
            "timestamp": self.timestamp
        }

    @staticmethod
    def parse(packet, layer, layer_id, sublayer_id):

        if layer.exists("http2.type"):
            frame_type = Http2Frame(layer.integer("http2.type"))
            return PARSER_MAPPING[frame_type](packet, layer, layer_id, sublayer_id)
        elif layer.exists("http2.magic"):
            return Frame(packet, layer, layer_id, sublayer_id)
        else:
            raise Exception("[!] Unknown HTTP/2 frame type @ packet %d" % packet.id)


class Data(Frame):

    def __init__(self, packet, layer, layer_id, sublayer_id):

        super().__init__(packet, layer, layer_id, sublayer_id)
        flags = layer.nested("http2.flags")
        self.padded = flags.boolean("http2.flags.padded")
        self.end_stream = flags.boolean("http2.flags.end_stream")

    def serialize(self):

        return {
            **super().serialize(),
            "flags_padded": self.padded,
            "flags_end_stream": self.end_stream
        }


class GoAway(Frame):

    def __init__(self, packet, layer, layer_id, sublayer_id):

        super().__init__(packet, layer, layer_id, sublayer_id)
        self.error = Http2Error(layer.integer("http2.goaway.error"))
        self.last_stream = layer.integer("http2.goaway.last_stream_id")

    def serialize(self):

        return {
            **super().serialize(),
            "error": self.error.name,
            "last_stream": self.last_stream
        }


class Headers(Frame):

    def __init__(self, packet, layer, layer_id, sublayer_id):

        super().__init__(packet, layer, layer_id, sublayer_id)
        flags = layer.nested("http2.flags")
        self.padded = flags.boolean("http2.flags.padded")
        self.end_headers = flags.boolean("http2.flags.eh")
        self.priority = flags.boolean("http2.flags.priority")
        self.end_stream = flags.boolean("http2.flags.end_stream")

        if self.priority:
            self.exclusive = layer.boolean("http2.exclusive")
            self.weight = layer.integer("http2.headers.weight_real")
            self.stream_dependency = layer.integer("http2.stream_dependency")

        self.http_response = False

        for _, header in layer.children("http2.header"):

            wrapper = XmlWrapper(header)

            if wrapper.exists("http2.headers.status"):
                self.http_response = True
                self.http_status = wrapper.integer("http2.headers.status")
            elif wrapper.exists("http2.headers.method"):
                self.http_method = wrapper.string("http2.headers.method")
            elif wrapper.exists("http2.headers.path"):
                self.http_resource = wrapper.string("http2.headers.path")

    def serialize(self):

        base_dictionary = {
            **super().serialize(),
            "flags_padded": self.padded,
            "flags_eh": self.end_headers,
            "flags_priority": self.priority,
            "flags_end_stream": self.end_stream,
            "http_response": self.http_response
        }

        if self.priority:
            base_dictionary.update({
                "weight": self.weight,
                "exclusive": self.exclusive,
                "stream_dependency": self.stream_dependency
            })

        if self.http_response:

            base_dictionary.update({
                "http_status": self.http_status
            })

        else:

            base_dictionary.update({
                "http_method": self.http_method,
                "http_resource": self.http_resource
            })

        return base_dictionary


class Ping(Frame):

    def __init__(self, packet, layer, layer_id, sublayer_id):
        super().__init__(packet, layer, layer_id, sublayer_id)
        flags = layer.nested("http2.flags")
        self.ack = flags.boolean("http2.flags.ack.settings")

    def serialize(self):

        return {
            **super().serialize(),
            "flags_ack": self.ack
        }


class Priority(Frame):

    def __init__(self, packet, layer, layer_id, sublayer_id):

        super().__init__(packet, layer, layer_id, sublayer_id)
        self.exclusive = layer.boolean("http2.exclusive")
        self.weight = layer.integer("http2.headers.weight_real")
        self.stream_dependency = layer.integer("http2.stream_dependency")

    def serialize(self):

        return {
            **super().serialize(),
            "weight": self.weight,
            "exclusive": self.exclusive,
            "stream_dependency": self.stream_dependency
        }


class PushPromise(Frame):

    def __init__(self, packet, layer, layer_id, sublayer_id):

        super().__init__(packet, layer, layer_id, sublayer_id)
        flags = layer.field("http2.flags")
        self.padded = flags.boolean("http2.flags.padded")
        self.end_headers = flags.boolean("http2.flags.eh")

    def serialize(self):

        return {
            **super().serialize(),
            "flags_padded": self.padded,
            "flags_eh": self.end_headers
        }


class RstStream(Frame):

    def __init__(self, packet, layer, layer_id, sublayer_id):

        super().__init__(packet, layer, layer_id, sublayer_id)
        self.error = Http2Error(layer.integer("http2.error"))

    def serialize(self):

        return {
            **super().serialize(),
            "error": self.error.name
        }


class Settings(Frame):

    JSON_VALUES = {
        Http2Settings.ENABLE_PUSH: "http2.settings.enable_push",
        Http2Settings.MAX_FRAME_SIZE: "http2.settings.max_frame_size",
        Http2Settings.HEADER_TABLE_SIZE: "http2.settings.header_table_size",
        Http2Settings.INITIAL_WINDOW_SIZE: "http2.settings.initial_window_size",
        Http2Settings.MAX_HEADER_LIST_SIZE: "http2.settings.max_header_list_size",
        Http2Settings.MAX_CONCURRENT_STREAMS: "http2.settings.max_concurrent_streams"
    }

    def __init__(self, packet, layer, layer_id, sublayer_id):

        super().__init__(packet, layer, layer_id, sublayer_id)
        flags = layer.nested("http2.flags")
        self.ack = flags.boolean("http2.flags.ack.settings")
        self.settings = Settings.parse_json(layer.children("http2.settings"))

    @staticmethod
    def parse_json(settings):

        return dict(Settings.parse_json_setting(XmlWrapper(s)) for _, s in settings)

    @staticmethod
    def parse_json_setting(setting):

        field = Http2Settings(setting.integer("http2.settings.id"))
        return field.name, setting.integer(Settings.JSON_VALUES[field])

    def serialize(self):

        return {
            **super().serialize(),
            "flags_ack": self.ack
        }


class WindowUpdate(Frame):

    def __init__(self, packet, layer, layer_id, sublayer_id):

        super().__init__(packet, layer, layer_id, sublayer_id)
        self.window_size = layer.integer("http2.window_update.window_size_increment")

    def serialize(self):

        return {
            **super().serialize(),
            "window_size": self.window_size
        }


PARSER_MAPPING = {
    Http2Frame.DATA: Data,
    Http2Frame.PING: Ping,
    Http2Frame.GO_AWAY: GoAway,
    Http2Frame.HEADERS: Headers,
    Http2Frame.PRIORITY: Priority,
    Http2Frame.SETTINGS: Settings,
    Http2Frame.RST_STREAM: RstStream,
    Http2Frame.PUSH_PROMISE: PushPromise,
    Http2Frame.WINDOW_UPDATE: WindowUpdate
}
