from __future__ import annotations

import unittest

from ds4bench.sse import SSEError, SSEParser


class SSEParserTests(unittest.TestCase):
    def test_split_utf8_crlf_comments_and_multiline_data(self) -> None:
        wire = (
            ": keepalive\r\n"
            "event: answer\r\n"
            "id: evt-1\r\n"
            "retry: 250\r\n"
            "data: {\"text\":\"caf\u00e9\"}\r\n"
            "data: second line\r\n"
            "\r\n"
            "data: [DONE]\n\n"
        ).encode("utf-8")
        encoded_character = "\u00e9".encode("utf-8")
        utf8_split = wire.index(encoded_character) + 1
        crlf_split = wire.index(b"\r\n") + 1
        boundaries = (7, crlf_split, utf8_split, utf8_split + 1)
        chunks = [
            wire[start:end]
            for start, end in zip((0, *boundaries), (*boundaries, len(wire)))
            if start != end
        ]

        parser = SSEParser()
        events = []
        for chunk in chunks:
            events.extend(parser.feed(chunk))
        events.extend(parser.finalize())

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].event, "answer")
        self.assertEqual(events[0].id, "evt-1")
        self.assertEqual(events[0].retry, 250)
        self.assertEqual(events[0].data, '{"text":"caf\u00e9"}\nsecond line')
        self.assertEqual(events[1].data, "[DONE]")
        self.assertEqual(events[1].id, "evt-1")

    def test_utf8_codepoint_can_be_split_at_every_byte(self) -> None:
        wire = 'data: {"content":"\U0001f642"}\n\n'.encode("utf-8")
        parser = SSEParser()
        events = []
        for byte in wire:
            events.extend(parser.feed(bytes((byte,))))
        parser.finalize()
        self.assertEqual(events[0].data, '{"content":"\U0001f642"}')

    def test_invalid_utf8_is_rejected_strictly(self) -> None:
        parser = SSEParser()
        with self.assertRaisesRegex(SSEError, "invalid_utf8"):
            parser.feed(b"data: \xff\n\n")

    def test_eof_does_not_dispatch_unterminated_event(self) -> None:
        parser = SSEParser()
        self.assertEqual(parser.feed(b"data: partial\n"), ())
        with self.assertRaisesRegex(SSEError, "unterminated_event"):
            parser.finalize()

    def test_comments_do_not_dispatch_events(self) -> None:
        parser = SSEParser()
        self.assertEqual(parser.feed(b": one\n: two\n\n"), ())
        self.assertEqual(parser.finalize(), ())

    def test_empty_data_field_is_an_event(self) -> None:
        parser = SSEParser()
        events = parser.feed(b"data:\n\n")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].data, "")

    def test_finalize_rejects_partial_utf8_after_dispatched_event(self) -> None:
        parser = SSEParser()
        events = parser.feed(b"data: [DONE]\n\n\xc3")
        self.assertEqual([event.data for event in events], ["[DONE]"])
        with self.assertRaisesRegex(SSEError, "invalid_utf8"):
            parser.finalize()

    def test_event_and_body_limits_are_enforced(self) -> None:
        event_parser = SSEParser(max_event_bytes=8, max_body_bytes=32)
        with self.assertRaisesRegex(SSEError, "event_too_large"):
            event_parser.feed(b"data: 123")

        body_parser = SSEParser(max_event_bytes=8, max_body_bytes=9)
        body_parser.feed(b":123\n\n")
        with self.assertRaisesRegex(SSEError, "body_too_large"):
            body_parser.feed(b":456\n\n")


if __name__ == "__main__":
    unittest.main()
