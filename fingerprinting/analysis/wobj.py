# -*- coding: utf-8 -*-

from enum import Enum


def integer_compare(lhs, rhs):

    return (lhs > rhs) - (lhs < rhs)


class WebObjectState(Enum):
    WAITING = 0
    REQUEST_HEADERS = 1
    RESPONSE_HEADERS = 2
    PAYLOAD_START = 3
    PAYLOAD_FINISHED = 4


class WebObject(object):

    def __init__(self, frame):
        self.length = 0
        self.status = -1
        self.body = []
        self.response = {}
        self.finished = False
        self.transitions = []
        self.name = frame.http_resource
        self.state = WebObjectState.WAITING
        self.request = self.generate_headers_entry(frame)

    @staticmethod
    def generate_headers_entry(frame):

        return {
            "frame": frame.id,
            "length": frame.body,
            "timestamp": frame.timestamp
        }

    def generate_body_entry(self, frame):

        body_dictionary = self.generate_headers_entry(frame)

        if len(self.body) == 0:
            body_dictionary["delta"] = 0.0
        else:
            body_dictionary["delta"] = frame.timestamp - self.body[-1]["timestamp"]

        return body_dictionary

    def transition(self, state, frame):

        transition_dictionary = {
            "state": state.name,
            "timestamp": frame.timestamp
        }

        if len(self.transitions) == 0:
            transition_dictionary["delta"] = 0.0
        else:
            transition_dictionary["delta"] = frame.timestamp - self.transitions[-1]["timestamp"]

        self.state = state
        self.transitions.append(transition_dictionary)

    def handle_headers(self, frame):

        if self.state == WebObjectState.WAITING or self.state == WebObjectState.PAYLOAD_FINISHED:

            if frame.end_headers:
                self.transition(WebObjectState.REQUEST_HEADERS, frame)

        elif self.state == WebObjectState.REQUEST_HEADERS and frame.end_headers:

            self.status = frame.http_status
            self.response = self.generate_headers_entry(frame)

            if frame.end_stream:
                self.transition(WebObjectState.WAITING, frame)
            else:
                self.transition(WebObjectState.RESPONSE_HEADERS, frame)

    def handle_data(self, frame):

        if self.state == WebObjectState.RESPONSE_HEADERS:

            if frame.end_stream:
                self.transition(WebObjectState.PAYLOAD_FINISHED, frame)
            else:
                self.transition(WebObjectState.PAYLOAD_START, frame)

            self._receive_payload(frame)

        elif self.state == WebObjectState.PAYLOAD_START:

            self._receive_payload(frame)

            if frame.end_stream:
                self.transition(WebObjectState.PAYLOAD_FINISHED, frame)

    @property
    def payload_start(self):
        return self.body[0]

    @property
    def payload_finish(self):
        return self.body[-1]

    def serialize(self):

        return {
            "body": self.body,
            "name": self.name,
            "length": self.length,
            "status": self.status,
            "transitions": self.transitions,
            "request": self.request,
            "response": self.response
        }

    def _receive_payload(self, frame):

        if frame.end_stream:
            self.finished = True

        self.length += frame.body
        self.body.append(self.generate_body_entry(frame))

    def compare_lhs_data_rhs_headers(self, other):

        if self.payload_finish["timestamp"] < other["timestamp"]:
            return -1
        elif self.payload_start["timestamp"] > other["timestamp"]:
            return 1
        else:
            return 0

    @staticmethod
    def compare_lhs_headers(this, other):

        comparison = [
            integer_compare(this["timestamp"], other.request_headers["timestamp"]),
            integer_compare(this["timestamp"], other.response_headers["timestamp"])
        ]

        if len(other.payload) > 0:

            if this["timestamp"] < other.payload_start["timestamp"]:
                comparison.append(-1)
            elif this["timestamp"] > other.payload_finish["timestamp"]:
                comparison.append(1)
            else:
                comparison.append(0)

        return comparison

    def compare(self, other):

        if not self.finished or not other.finished:
            return []

        comparison = [
            self.compare_lhs_headers(self.request, other),
            self.compare_lhs_headers(self.response, other)
        ]

        if len(self.body) > 0:

            if self.payload_finish["timestamp"] < other.payload_start["timestamp"]:
                overlap_lhs_data_rhs_data = -1
            elif self.payload_start["timestamp"] > other.payload_finish["timestamp"]:
                overlap_lhs_data_rhs_data = 1
            else:
                overlap_lhs_data_rhs_data = 0

            comparison += [
                self.compare_lhs_data_rhs_headers(other.request_headers),
                self.compare_lhs_data_rhs_headers(other.response_headers),
                overlap_lhs_data_rhs_data
            ]

        return comparison
