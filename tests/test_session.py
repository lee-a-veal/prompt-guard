"""Tests for promptguard/session.py."""
from __future__ import unicode_literals

import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from promptguard import session


class _Base(unittest.TestCase):
    def setUp(self):
        fd, self._path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(self._path)
        os.environ["PROMPTGUARD_SESSION_FILE"] = self._path

    def tearDown(self):
        os.environ.pop("PROMPTGUARD_SESSION_FILE", None)
        for p in (self._path, self._path + ".tmp"):
            try:
                os.unlink(p)
            except OSError:
                pass


class TestLoad(_Base):
    def test_fresh_on_missing_file(self):
        state = session.load()
        self.assertEqual(state["taint_count"], 0)
        self.assertEqual(state["tool_calls"], [])
        self.assertIn("session_start", state)

    def test_fresh_on_corrupt_file(self):
        with open(self._path, "w") as f:
            f.write("NOT JSON {{{")
        self.assertEqual(session.load()["taint_count"], 0)

    def test_session_expires(self):
        old = session._empty()
        old["last_seen"] = time.time() - 99999
        old["taint_count"] = 7
        session.save(old)
        os.environ["PROMPTGUARD_SESSION_WINDOW"] = "1"
        try:
            self.assertEqual(session.load()["taint_count"], 0)
        finally:
            os.environ.pop("PROMPTGUARD_SESSION_WINDOW", None)

    def test_session_continues_within_window(self):
        existing = session._empty()
        existing["taint_count"] = 5
        session.save(existing)
        self.assertEqual(session.load()["taint_count"], 5)


class TestRecordTaint(_Base):
    def test_increments_count(self):
        session.record_taint("Bash")
        self.assertEqual(session.get_taint_count(), 1)
        session.record_taint("WebFetch")
        self.assertEqual(session.get_taint_count(), 2)

    def test_appends_source(self):
        session.record_taint("Bash")
        self.assertIn("Bash", session.load()["tainted_sources"])


class TestRecordToolCall(_Base):
    def test_appends_entry(self):
        session.record_tool_call("WebFetch", "https://example.com")
        calls = session.load()["tool_calls"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["tool"], "WebFetch")
        self.assertEqual(calls[0]["label"], "https://example.com")

    def test_trims_at_200(self):
        for i in range(201):
            session.record_tool_call("Bash", "cmd%d" % i)
        calls = session.load()["tool_calls"]
        self.assertEqual(len(calls), 200)
        labels = [c["label"] for c in calls]
        self.assertNotIn("cmd0", labels)
        self.assertIn("cmd200", labels)


class TestGetRecentCalls(_Base):
    def test_respects_window(self):
        now = time.time()
        state = session._empty()
        state["tool_calls"] = [
            {"ts": now - 200, "tool": "Read",     "label": "old"},
            {"ts": now - 10,  "tool": "WebFetch", "label": "recent"},
        ]
        session.save(state)
        recent = session.get_recent_calls(60)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["label"], "recent")

    def test_empty_for_fresh_session(self):
        self.assertEqual(session.get_recent_calls(60), [])


class TestSave(_Base):
    def test_saved_file_is_valid_json(self):
        session.record_taint("Bash")
        with open(self._path) as f:
            data = json.load(f)
        self.assertIn("taint_count", data)

    def test_no_tmp_file_after_save(self):
        session.save(session._empty())
        self.assertFalse(os.path.exists(self._path + ".tmp"))


class TestTaintDecay(_Base):
    """Taint count uses sliding window via taint_log (B-BA-2)."""

    def test_recent_taint_counts(self):
        session.record_taint("WebFetch")
        self.assertEqual(session.get_taint_count(), 1)

    def test_expired_taint_does_not_count(self):
        state = session._empty()
        # Inject a taint event outside the decay window
        state["taint_log"] = [{"ts": 1.0, "source": "Bash"}]
        session.save(state)
        os.environ["PROMPTGUARD_TAINT_DECAY_WINDOW"] = "60"
        try:
            self.assertEqual(session.get_taint_count(), 0)
        finally:
            os.environ.pop("PROMPTGUARD_TAINT_DECAY_WINDOW", None)

    def test_mixed_recent_and_expired(self):
        now = time.time()
        state = session._empty()
        state["taint_log"] = [
            {"ts": now - 7200, "source": "Bash"},   # 2h ago — expired
            {"ts": now - 1800, "source": "Read"},   # 30m ago — within 1h window
            {"ts": now - 10,   "source": "WebFetch"},  # recent
        ]
        session.save(state)
        self.assertEqual(session.get_taint_count(), 2)

    def test_legacy_session_without_taint_log(self):
        # Old session files have taint_count but no taint_log — must fall back.
        state = session._empty()
        del state["taint_log"]
        state["taint_count"] = 5
        session.save(state)
        self.assertEqual(session.get_taint_count(), 5)


class TestCustomWindow(_Base):
    def test_custom_window_env(self):
        os.environ["PROMPTGUARD_SESSION_WINDOW"] = "7200"
        try:
            self.assertEqual(session._window(), 7200)
        finally:
            os.environ.pop("PROMPTGUARD_SESSION_WINDOW", None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
