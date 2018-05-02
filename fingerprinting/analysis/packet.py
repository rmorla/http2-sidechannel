# -*- coding: utf-8 -*-

from fingerprinting.analysis.record import TlsRecord, TlsRecordType


class LayerItem(object):

    def __init__(self, item_type, item, sublayer_id=0):
        self.item = item
        self.index = -1
        self.type = item_type
        self.reasslength = -1
        self.layer_id = item.layer_id
        self.sublayer_id = sublayer_id
    
    @staticmethod
    def from_fake_segment(item):
        return LayerItem("sslreass", item, 0)
    
    @staticmethod
    def from_ssl_record(item):
        return LayerItem("ssl", item, item.sublayer_id)

    @staticmethod
    def from_http2_frame(item):
        return LayerItem("http2frame", item, item.sublayer_id)


class SslFakeSegment(object):

    def __init__(self, packet, layer, layer_id, sublayer_id):

        self.segments = []
        self.packet = packet
        self.layer_id = layer_id
        self.frame_layer_id = None
        self.sublayer_id = sublayer_id
        self.count = layer.integer("ssl.segment.count")
        self.length = layer.integer("ssl.reassembled.length")

        for _, ssl_segment in layer.children("ssl.segment"):        
            packet_id = int(ssl_segment.attrib["show"])
            ssl_length = int(ssl_segment.attrib["size"])       
            self.segments.append([packet_id, ssl_length])       

    def serialize(self):

        return {
            "count": self.count,
            "length": self.length,
            "layer_id": self.layer_id,
            "segments": self.segments
        }

class Packet(object):

    def __init__(self, layer):

        self.frames = []
        self.records = []
        self.streams = []
        self.handshakes = []
        self.application = []
        self.fake_segments = []
        self.frames_unique = []
        self.streams_active = []
        self.streams_closed = []
        self.ssl_segments_reassembled = []

        self.lengths = {
            "total": 0,
            "frames": 0,
            "records": 0,
            "handshakes": 0,
            "application_data": 0
        }

        self._parse_ip_layer(layer.proto("ip"))
        self._parse_tcp_layer(layer.proto("tcp"))
        self._parse_frame_layer(layer.proto("frame"))

    def _parse_ip_layer(self, layer):
        self.source = layer.string("ip.src")
        self.destination = layer.string("ip.dst")

    def _parse_tcp_layer(self, layer):
        self.source_port = layer.integer("tcp.srcport")
        self.destination_port = layer.integer("tcp.dstport")

    def _parse_frame_layer(self, layer):
        self.id = layer.integer("frame.number")
        self.time_delta = layer.real("frame.time_delta")
        self.lengths["total"] = layer.integer("frame.len")
        self.time_relative = layer.real("frame.time_relative")

    def insert_frame(self, frame):
        self.frames.append(frame)
        self.lengths["frames"] += frame.length
        self.application[-1].frames.append(frame)

    def insert_fake_segment(self, layer, layer_id, sublayer_id):

        self.fake_segments.append(
            SslFakeSegment(self, layer, layer_id, sublayer_id)
        )

    def insert_ssl_record(self, layer, layer_id, sublayer_id):

        record = TlsRecord(self, layer, layer_id, sublayer_id)
        self.records.append(record)
        self.lengths["records"] += record.length

        if record.type == TlsRecordType.HANDSHAKE:
            self.handshakes.append(record)
            self.lengths["handshakes"] += record.length
        elif record.type == TlsRecordType.APPLICATION_DATA:
            self.application.append(record)
            self.lengths["application_data"] += record.length

        return record

    def serialize(self):

        return {
            "source": self.source,
            "lengths": self.lengths,
            "streams": self.streams,
            "time_delta": self.time_delta,
            "source_port": self.source_port,
            "destination": self.destination,
            "time_relative": self.time_relative,
            "streams_active": self.streams_active,
            "streams_closed": self.streams_closed,
            "destination_port": self.destination_port,
            "frames": [frame.id for frame in self.frames],
            "records": {v.id: v.serialize() for v in self.records},
            "fake_segments": [fake_segment.serialize() for fake_segment in self.fake_segments]
        }

    def process_mapssl2http2(self):

        items = [
            LayerItem.from_ssl_record(record)
            for record in self.records
            if record.type == TlsRecordType.APPLICATION_DATA
        ]

        items.extend([
            LayerItem.from_http2_frame(frame)
            for frame in self.frames
        ])

        items.extend([
            LayerItem.from_fake_segment(fake_segment)
            for fake_segment in self.fake_segments
        ])

        items_sorted = sorted(items, key=lambda item: (item.layer_id, item.sublayer_id))

        for index in range(0, len(items_sorted) - 1):

            item = items_sorted[index]
            next_item = items_sorted[index + 1]

            if item.type != "sslreass":
                continue

            if item.reasslength >= 0:
                print("sort 3")
                next_item.index = item.index - 1
                next_item.reasslength = item.reasslength

            elif next_item.type == "sslreass":
                print("sort 4")
                reassembled_length = 2

                for j in range(index + 2, len(items_sorted)):

                    if items_sorted[j].type == "sslreass":
                        reassembled_length += 1
                    else:
                        break

                item.reasslength = reassembled_length
                item.index = item.reasslength - 1

                next_item.reasslength = reassembled_length
                next_item.index = item.reasslength - 2

            else:
                print("sort 5")
                item.index = 0
                item.reasslength = 1
        
        def get_next_item_of_type(item_type, start):
            for index in range(start, len(items_sorted)):
                if items_sorted[index].type == item_type:
                    return index
            return -1

        def get_next_item_not_of_type(item_type, start):
            for index in range(start, len(items_sorted)):
                if items_sorted[index].type != item_type:
                    return index
            return -1

        def get_next_item_of_type_nossl(item_type, start):
            for index in range(start, len(items_sorted)):
                if items_sorted[index].type == item_type:
                    return index
                elif item_type == "ssl":
                    break
            return -1

        record_index = get_next_item_of_type("ssl", 0)
        frame_index = get_next_item_not_of_type("ssl", record_index)
        reassembled_index = get_next_item_of_type_nossl("sslreass", frame_index)
        frame_index = get_next_item_of_type_nossl("http2frame", frame_index)

        while record_index >= 0 and frame_index >= 0:

            ssl_record = items_sorted[record_index].item

            if len(ssl_record.segment_data) == 1:

                frame_index = get_next_item_of_type_nossl("http2frame", frame_index)

                if frame_index < 0:
                    frame = items_sorted[frame_index].item
                    frame.last_ssl_record = ssl_record
                    frame_index += 1

            elif reassembled_index < 0:

                frame_index = get_next_item_of_type_nossl("http2frame", frame_index)

                if frame_index >= 0:
                    frame = items_sorted[frame_index].item
                    frame.last_ssl_record = ssl_record
                    frame_index += 1

            else:

                reassembled_index = get_next_item_of_type_nossl("sslreass", reassembled_index)

                if reassembled_index >= 0:
                    pointer_sslreass = items_sorted[reassembled_index]
                    actual_sslreass_delta_i = 2 * pointer_sslreass.index - (pointer_sslreass.reasslength - 1)
                    sslreass = items_sorted[reassembled_index + actual_sslreass_delta_i]
                    frame = items_sorted[frame_index].item
                    frame.ssl_segment_reassembly = sslreass.item
                    sslreass.item.frame_layer_id = frame.layer_id
                    frame_index += 1
                    reassembled_index += 1

            if record_index + 1 >= len(items_sorted):
                continue

            if items_sorted[record_index + 1].type != "ssl":

                ssl_record = items_sorted[record_index].item

                while frame_index < len(items_sorted) and items_sorted[frame_index].type == "http2frame":
                    frame = items_sorted[frame_index].item
                    frame.last_ssl_record = ssl_record
                    frame_index += 1

                record_index = get_next_item_of_type("ssl", record_index + 1)
                tmp_index = get_next_item_not_of_type("ssl", record_index)
                reassembled_index = get_next_item_of_type_nossl("sslreass", tmp_index)
                frame_index = get_next_item_of_type_nossl("http2frame", tmp_index)

            else:

                record_index += 1

    def find_sslids_and_update_frameid_withproto_noseg(self, record, frame):

        def filter_records(ssl_record): return \
            ssl_record.packet.id == record.packet.id and \
            ssl_record.layer_id == record.layer_id and \
            ssl_record.sublayer_id == record.sublayer_id

        for ssl_record in filter(filter_records, self.records):

            ssl_segment = ssl_record.segment_data[0]
            ssl_segment.frames.append([frame.id, frame.body])

            return ssl_record.id, ssl_segment.id

        return ()

    def find_sslids_and_update_frameid(self, segment, frame):

        packet_id = segment[0]
        ssl_length = segment[1]

        for ssl_record in self.records:

            if packet_id != self.id:
                continue

            ssl_segments = iter(ssl_record.segment_data)
            next(ssl_segments)

            for ssl_segment in ssl_segments:

                frame_length = sum(segment[1] for segment in ssl_segment.frames)

                if frame_length + ssl_length > ssl_segment.length:
                    continue

                ssl_segment.frames.append([frame.id, ssl_length])

                return ssl_record.id, ssl_segment.id

        return ()
    
    def associate_frames_with_records(self):

        for frame in self.frames:

            if len(frame.ssl_segment_reassembly) == 0:

                record = frame.last_ssl_record
                indices = self.find_sslids_and_update_frameid_withproto_noseg(record, frame)

                if len(indices) != 2:
                    continue

                frame.insert_reassembled_segment(
                    indices[0], record.length,
                    indices[1], frame.body
                )

            else:

                for segment in frame.ssl_segment_reassembly.segments:

                    indices = self.find_sslids_and_update_frameid(segment, frame)

                    if len(indices) != 2:
                        continue
                    
                    frame.insert_reassembled_segment(
                        indices[0], self.records[indices[0]].length,
                        indices[1], segment[1]
                    )

    def remove_duplicate_reassemblies(self):

        for fake_segment in self.fake_segments:

            unique_segment = True

            if len(self.ssl_segments_reassembled) > 0:

                for reassembled_segment in self.ssl_segments_reassembled:

                    if fake_segment.length != reassembled_segment.length or \
                        fake_segment.count != reassembled_segment.count:
                        continue

                    comparison_list = zip(
                        fake_segment.segments,
                        reassembled_segment.segments
                    )

                    if not any(i[0] != j[0] or i[1] != j[1] for i, j in comparison_list):
                        unique_segment = False
                        break

            if unique_segment:

                self.ssl_segments_reassembled.append(fake_segment)

                self.frames_unique.extend([
                    frame for frame in self.frames
                    if frame.layer_id == fake_segment.frame_layer_id
                ])

        self.frames_unique.extend([
            frame for frame in self.frames
            if len(frame.ssl_segment_reassembly) == 0
        ])

    def update_frame_bytecount(self):
        
        for frame in self.frames:

            frame_start = -1
            frame_finish = -1

            for segment_index in frame.ssl_segment_indices:

                frame_length = 0
                ssl_record = self.records[segment_index.record_id]

                for ssl_segment in ssl_record.segment_data:
                    for http_frame_seg in ssl_segment.frames:
                        frame_length += http_frame_seg[1]

                last_http2_frame = 0
                ssl_record.content_length = frame_length
                segment_index.content_length = ssl_record.content_length

                for ssl_segment in ssl_record.segment_data:

                    first_ssl_segment = 0
                    http2_ssl_seg_size = 0

                    for http_frame_seg in ssl_segment.frames:

                        if http_frame_seg[0] == frame.id:
                            http2_ssl_seg_size = http_frame_seg[1]
                            first_ssl_segment = last_http2_frame

                        last_http2_frame += http_frame_seg[1]

                    if ssl_segment.id == segment_index.segment_id:

                        if frame_length > 0:
                            first_ssl_segment = first_ssl_segment / (1.0 * frame_length) * ssl_record.length
                            last_ssl_segment = first_ssl_segment + http2_ssl_seg_size / (1.0 * frame_length) * ssl_record.length
                        else:
                            first_ssl_segment = 0
                            last_ssl_segment = ssl_record.length

                        if first_ssl_segment < 0:
                            first_ssl_segment = 0

                        if last_ssl_segment > ssl_record.length:
                            last_ssl_segment = ssl_record.length

                        segment_index.bytecount_start = ssl_record.bytecount_index + first_ssl_segment
                        segment_index.bytecount_finish = ssl_record.bytecount_index + last_ssl_segment - 1

                        if frame_start == -1:

                            frame_start = segment_index.bytecount_start
                            frame_finish = segment_index.bytecount_finish

                        else:

                            if frame_finish < segment_index.bytecount_finish:
                                frame_finish = segment_index.bytecount_finish

                            if frame_start > segment_index.bytecount_start:
                                frame_start = segment_index.bytecount_start

                        break

            frame.bytecount_start = frame_start
            frame.bytecount_finish = frame_finish
