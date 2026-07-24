from __future__ import annotations

import io
import json
import struct
import time
import unittest

from event_horizon.protocol import (
    MessageSpec,
    ProtocolError,
    StrictRpcServer,
    encode_frame,
    read_frame,
    request_envelope,
    validate_request,
)


class ProtocolTests(unittest.TestCase):
    def test_canonical_length_prefixed_round_trip(self):
        message = request_envelope('check', 'req-1', {'value': 'ok'})
        framed = encode_frame(message)
        self.assertEqual(struct.unpack('>I', framed[:4])[0], len(framed) - 4)
        self.assertEqual(read_frame(io.BytesIO(framed)), message)

    def test_noncanonical_and_duplicate_json_are_rejected(self):
        noncanonical = b'{"b":2, "a":1}'
        with self.assertRaisesRegex(ProtocolError, 'canonical'):
            read_frame(io.BytesIO(struct.pack('>I', len(noncanonical)) + noncanonical))
        duplicate = b'{"a":1,"a":2}'
        with self.assertRaisesRegex(ProtocolError, 'duplicate'):
            read_frame(io.BytesIO(struct.pack('>I', len(duplicate)) + duplicate))

    def test_byte_string_and_nesting_limits_fail_closed(self):
        with self.assertRaises(ProtocolError) as oversized:
            encode_frame({'value': 'x' * 20_000})
        self.assertEqual(oversized.exception.code, 'string_limit')
        nested: object = 'leaf'
        for _ in range(12):
            nested = [nested]
        with self.assertRaises(ProtocolError) as too_deep:
            encode_frame({'value': nested})
        self.assertEqual(too_deep.exception.code, 'nesting_limit')

    def test_unknown_fields_types_and_deadlines_are_rejected(self):
        specs = {'check': MessageSpec(frozenset({'value'}), lambda body: body)}
        message = request_envelope('check', 'req-1', {'value': 'ok'})
        message['extra'] = True
        with self.assertRaises(ProtocolError) as unknown:
            validate_request(message, specs)
        self.assertEqual(unknown.exception.code, 'unknown_field')
        expired = request_envelope('check', 'req-2', {'value': 'ok'})
        expired['deadline_ms'] = int(time.time() * 1000) - 1
        with self.assertRaises(ProtocolError) as deadline:
            validate_request(expired, specs)
        self.assertEqual(deadline.exception.code, 'deadline_exceeded')

    def test_server_enforces_request_count_limit(self):
        specs = {'check': MessageSpec(frozenset({'value'}), lambda body: body)}
        source = io.BytesIO(encode_frame(request_envelope('check', 'req-1', {'value': 'ok'})))
        sink = io.BytesIO()
        StrictRpcServer(specs, max_requests=1).serve(source, sink)
        sink.seek(0)
        first = read_frame(sink)
        second = read_frame(sink)
        self.assertTrue(first['ok'])
        self.assertFalse(second['ok'])
        self.assertEqual(second['error']['code'], 'request_limit')


if __name__ == '__main__':
    unittest.main()
