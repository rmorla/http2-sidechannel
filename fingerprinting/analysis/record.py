# -*- coding: utf-8 -*-

from enum import Enum


class TlsRecordType(Enum):
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23


class TlsHandshakeType(Enum):
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    NEW_SESSION_TICKET = 4
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20
    ENCRYPTED = 255


class SslSegmentData(object):

    INSTANCE_COUNT = 0

    def __init__(self, length):

        SslSegmentData.INSTANCE_COUNT += 1

        self.frames = []
        self.length = length
        self.id = SslSegmentData.INSTANCE_COUNT

    def serialize(self):

        return {
            "id": self.id,
            "frames": self.frames,
            "length": self.length
        }


class TlsRecord(object):

    INSTANCE_COUNT = 0

    def __init__(self, packet, layer, layer_id, sublayer_id):

        TlsRecord.INSTANCE_COUNT += 1

        self.packet = packet
        self.layer_id = layer_id
        self.sublayer_id = sublayer_id
        self.id = TlsRecord.INSTANCE_COUNT
        self.length = layer.integer("ssl.record.length")
        self.type = TlsRecordType(layer.integer("ssl.record.content_type"))

        self.segment_data = []
        self.content_length = 0
        self.segment_data.append(SslSegmentData(self.length))
        self.bytecount_index = packet.lengths["records"]

        if self.type == TlsRecordType.APPLICATION_DATA:
            self.frames = []
            self.frames_length = 0
        elif self.type == TlsRecordType.HANDSHAKE:
            wrapper = layer.nested("ssl.handshake")
            self.handshake = TlsHandshakeType(wrapper.integer("ssl.handshake.type"))

    def insert_frame(self, frame):

        if self.frames_length + frame.length < self.length:
            self.frames_length += frame.length
            self.frames.append(frame)
        else:
            raise Exception("[E] Total frame length exceeded SSL record size!")

    def insert_segment_data(self, length):

        self.segment_data.append(SslSegmentData(length))

    def serialize(self):

        base_dictionary = {
            "length": self.length,
            "type": self.type.name,
            "layer_id": self.layer_id,
            "segment_data": [seg.serialize() for seg in self.segment_data]
        }

        if self.type == TlsRecordType.APPLICATION_DATA:
            base_dictionary["frames_length"] = self.frames_length
            base_dictionary["frames"] = [frame.id for frame in self.frames]
        elif self.type == TlsRecordType.HANDSHAKE:
            base_dictionary["handshake"] = self.handshake.name

        return base_dictionary
