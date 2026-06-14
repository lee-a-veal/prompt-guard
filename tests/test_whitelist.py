"""Tests for promptguard/whitelist.py."""
from __future__ import unicode_literals

import os
import sys
import tempfile
import time
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

import promptguard.whitelist as wl


def _write_conf(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


class TestLoad(unittest.TestCase):
    def tearDown(self):
        wl._cache_key = None
        wl._cache_entries = []
        os.environ.pop("PROMPTGUARD_WHITELIST_FILE", None)

    def test_missing_file_returns_empty(self):
        os.environ["PROMPTGUARD_WHITELIST_FILE"] = "/tmp/no_such_file_prompt_guard.conf"
        result = wl.load()
        self.assertEqual(result, [])

    def test_parses_valid_entries(self):
        fd, path = tempfile.mkstemp(suffix=".conf")
        os.close(fd)
        try:
            _write_conf(path, "embedded_command: rm -rf\ninstruction_override: ignore\n")
            os.environ["PROMPTGUARD_WHITELIST_FILE"] = path
            wl._cache_key = None
            result = wl.load()
            self.assertEqual(result, [
                ("embedded_command", "rm -rf"),
                ("instruction_override", "ignore"),
            ])
        finally:
            os.unlink(path)

    def test_comments_and_blank_lines_skipped(self):
        fd, path = tempfile.mkstemp(suffix=".conf")
        os.close(fd)
        try:
            _write_conf(path, "# comment\n\nembedded_command: eval\n")
            os.environ["PROMPTGUARD_WHITELIST_FILE"] = path
            wl._cache_key = None
            result = wl.load()
            self.assertEqual(result, [("embedded_command", "eval")])
        finally:
            os.unlink(path)

    def test_malformed_line_skipped_others_kept(self):
        fd, path = tempfile.mkstemp(suffix=".conf")
        os.close(fd)
        try:
            _write_conf(path, "no_colon_here\nembedded_command: eval\n")
            os.environ["PROMPTGUARD_WHITELIST_FILE"] = path
            wl._cache_key = None
            result = wl.load()
            self.assertEqual(result, [("embedded_command", "eval")])
        finally:
            os.unlink(path)

    def test_cache_hit_returns_same_list(self):
        fd, path = tempfile.mkstemp(suffix=".conf")
        os.close(fd)
        try:
            _write_conf(path, "embedded_command: eval\n")
            os.environ["PROMPTGUARD_WHITELIST_FILE"] = path
            wl._cache_key = None
            first = wl.load()
            second = wl.load()
            self.assertIs(first, second)
        finally:
            os.unlink(path)

    def test_cache_invalidated_on_mtime_change(self):
        fd, path = tempfile.mkstemp(suffix=".conf")
        os.close(fd)
        try:
            _write_conf(path, "embedded_command: eval\n")
            os.environ["PROMPTGUARD_WHITELIST_FILE"] = path
            wl._cache_key = None
            first = wl.load()
            self.assertEqual(first, [("embedded_command", "eval")])

            # Write new content and bump mtime so load() detects the change
            _write_conf(path, "instruction_override: ignore\n")
            future = os.path.getmtime(path) + 1
            os.utime(path, (future, future))
            # Do NOT reset _cache_key — load() must detect the mtime change itself
            second = wl.load()
            self.assertNotEqual(first, second)
            self.assertEqual(second, [("instruction_override", "ignore")])
        finally:
            os.unlink(path)


class TestIsSuppressed(unittest.TestCase):
    def _entries(self):
        return [("embedded_command", "rm -rf"), ("instruction_override", "ignore")]

    def test_matching_id_and_evidence_suppressed(self):
        signal = {"id": "embedded_command", "evidence": "...rm -rf /tmp...", "weight": 32}
        self.assertTrue(wl.is_suppressed(signal, self._entries()))

    def test_wrong_id_not_suppressed(self):
        signal = {"id": "role_reassignment", "evidence": "rm -rf /tmp", "weight": 30}
        self.assertFalse(wl.is_suppressed(signal, self._entries()))

    def test_wrong_pattern_not_suppressed(self):
        signal = {"id": "embedded_command", "evidence": "...chmod 777...", "weight": 32}
        self.assertFalse(wl.is_suppressed(signal, self._entries()))

    def test_case_insensitive_match(self):
        signal = {"id": "embedded_command", "evidence": "...RM -RF /home...", "weight": 32}
        self.assertTrue(wl.is_suppressed(signal, self._entries()))

    def test_empty_entries_never_suppresses(self):
        signal = {"id": "embedded_command", "evidence": "rm -rf", "weight": 32}
        self.assertFalse(wl.is_suppressed(signal, []))

    def test_multiple_entries_same_id_ored(self):
        entries = [("embedded_command", "rm -rf"), ("embedded_command", "chmod")]
        signal_a = {"id": "embedded_command", "evidence": "chmod 777", "weight": 32}
        signal_b = {"id": "embedded_command", "evidence": "rm -rf /x", "weight": 32}
        self.assertTrue(wl.is_suppressed(signal_a, entries))
        self.assertTrue(wl.is_suppressed(signal_b, entries))


class TestFilterSignals(unittest.TestCase):
    def test_removes_matching_keeps_others(self):
        entries = [("embedded_command", "rm -rf")]
        signals = [
            {"id": "embedded_command", "evidence": "rm -rf /tmp", "weight": 32},
            {"id": "instruction_override", "evidence": "ignore prior", "weight": 40},
        ]
        result = wl.filter_signals(signals, entries)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["id"], "instruction_override")

    def test_empty_entries_returns_all(self):
        signals = [{"id": "embedded_command", "evidence": "rm -rf", "weight": 32}]
        result = wl.filter_signals(signals, [])
        self.assertEqual(result, signals)

    def test_all_suppressed_returns_empty(self):
        entries = [("embedded_command", "rm -rf")]
        signals = [{"id": "embedded_command", "evidence": "rm -rf /x", "weight": 32}]
        result = wl.filter_signals(signals, entries)
        self.assertEqual(result, [])

    def test_empty_signals_returns_empty(self):
        entries = [("embedded_command", "rm -rf")]
        result = wl.filter_signals([], entries)
        self.assertEqual(result, [])

    def test_score_from_filtered_signals(self):
        entries = [("embedded_command", "rm -rf")]
        signals = [
            {"id": "embedded_command", "evidence": "rm -rf /tmp", "weight": 32},
            {"id": "instruction_override", "evidence": "ignore prior", "weight": 40},
        ]
        filtered = wl.filter_signals(signals, entries)
        score = sum(s["weight"] for s in filtered)
        self.assertEqual(score, 40)


if __name__ == "__main__":
    unittest.main(verbosity=2)
