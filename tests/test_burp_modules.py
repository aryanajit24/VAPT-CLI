"""Tests for v9.0 Burp Suite replacement modules."""

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestCodecEncodeDecode(unittest.TestCase):

    def setUp(self):
        from vapt.utils.codec import Codec
        self.c = Codec

    def test_base64_roundtrip(self):
        self.assertEqual(self.c.decode_base64(self.c.encode_base64("hello")), "hello")

    def test_base64_encode(self):
        self.assertEqual(self.c.encode_base64("hello world"), "aGVsbG8gd29ybGQ=")

    def test_url_roundtrip(self):
        original = "hello world&foo=bar"
        self.assertEqual(self.c.decode_url(self.c.encode_url(original)), original)

    def test_url_encode_special_chars(self):
        encoded = self.c.encode_url("<script>alert(1)</script>")
        self.assertNotIn("<", encoded)
        self.assertNotIn(">", encoded)

    def test_hex_roundtrip(self):
        self.assertEqual(self.c.decode_hex(self.c.encode_hex("test")), "test")

    def test_hex_encode(self):
        self.assertEqual(self.c.encode_hex("AB"), "4142")

    def test_html_roundtrip(self):
        original = '<img src="x">'
        self.assertEqual(self.c.decode_html(self.c.encode_html(original)), original)

    def test_html_numeric(self):
        result = self.c.encode_html_numeric("A")
        self.assertIn("&#65;", result)

    def test_unicode_escape_roundtrip(self):
        original = "hello"
        encoded = self.c.encode_unicode_escape(original)
        self.assertIn("\\u", encoded)
        self.assertEqual(self.c.decode_unicode_escape(encoded), original)

    def test_url_encode_all(self):
        result = self.c.encode_url_all("AB")
        self.assertEqual(result, "%41%42")


class TestCodecJWT(unittest.TestCase):

    def setUp(self):
        from vapt.utils.codec import Codec
        self.c = Codec

    def test_decode_jwt(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = self.c.decode_jwt(token)
        self.assertEqual(result["header"]["alg"], "HS256")
        self.assertEqual(result["payload"]["sub"], "1234567890")
        self.assertEqual(result["payload"]["name"], "John Doe")
        self.assertIn("signature", result)

    def test_invalid_jwt(self):
        with self.assertRaises(ValueError):
            self.c.decode_jwt("not-a-jwt")

    def test_encode_jwt_part(self):
        part = self.c.encode_jwt_part({"alg": "HS256"})
        self.assertIsInstance(part, str)
        self.assertNotIn("=", part)


class TestCodecHash(unittest.TestCase):

    def setUp(self):
        from vapt.utils.codec import Codec
        self.c = Codec

    def test_md5(self):
        result = self.c.hash_string("hello", "md5")
        self.assertEqual(len(result), 32)
        self.assertEqual(result, "5d41402abc4b2a76b9719d911017c592")

    def test_sha256(self):
        result = self.c.hash_string("hello", "sha256")
        self.assertEqual(len(result), 64)

    def test_sha1(self):
        result = self.c.hash_string("test", "sha1")
        self.assertEqual(len(result), 40)

    def test_invalid_algorithm(self):
        with self.assertRaises(ValueError):
            self.c.hash_string("hello", "invalid")

    def test_identify_md5(self):
        md5 = "5d41402abc4b2a76b9719d911017c592"
        matches = self.c.identify_hash(md5)
        self.assertIn("MD5", matches)

    def test_identify_sha256(self):
        sha256 = self.c.hash_string("hello", "sha256")
        matches = self.c.identify_hash(sha256)
        self.assertIn("SHA-256", matches)

    def test_identify_unknown(self):
        matches = self.c.identify_hash("not-a-hash!!!")
        self.assertEqual(matches, ["Unknown"])


class TestCodecUtilities(unittest.TestCase):

    def setUp(self):
        from vapt.utils.codec import Codec
        self.c = Codec

    def test_entropy_empty(self):
        self.assertEqual(self.c.entropy(""), 0.0)

    def test_entropy_single_char(self):
        self.assertEqual(self.c.entropy("aaaa"), 0.0)

    def test_entropy_max(self):
        ent = self.c.entropy("abcd")
        self.assertAlmostEqual(ent, 2.0, places=1)

    def test_smart_decode_base64(self):
        import base64
        encoded = base64.b64encode(b"hello world").decode()
        result = self.c.smart_decode(encoded)
        self.assertIn("base64", result)

    def test_smart_decode_jwt(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
        result = self.c.smart_decode(token)
        self.assertIn("jwt", result)

    def test_test_regex_valid(self):
        result = self.c.test_regex(r"\d+", "abc 123 def 456")
        self.assertTrue(result["valid"])
        self.assertEqual(result["match_count"], 2)

    def test_test_regex_invalid(self):
        result = self.c.test_regex(r"[invalid", "test")
        self.assertFalse(result["valid"])

    def test_encode_all(self):
        result = self.c.encode_all("test")
        self.assertIn("base64", result)
        self.assertIn("url", result)
        self.assertIn("hex", result)
        self.assertIn("md5", result)
        self.assertIn("sha256", result)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestSequencerAnalysis(unittest.TestCase):

    def setUp(self):
        from vapt.engine.sequencer import Sequencer, SequencerResult
        self.Sequencer = Sequencer
        self.SequencerResult = SequencerResult

    def test_analyze_random_tokens(self):
        import secrets
        tokens = [secrets.token_hex(16) for _ in range(100)]
        seq = self.Sequencer.__new__(self.Sequencer)
        seq.tokens = tokens
        result = seq.analyze(tokens=tokens)
        self.assertIsInstance(result, self.SequencerResult)
        self.assertEqual(result.sample_size, 100)
        self.assertGreater(result.entropy_per_char, 0)
        self.assertGreater(result.overall_score, 30)
        self.assertIn(result.rating, ("excellent", "good", "fair", "poor", "critical"))

    def test_analyze_weak_tokens(self):
        tokens = [str(i).zfill(4) for i in range(100)]
        seq = self.Sequencer.__new__(self.Sequencer)
        seq.tokens = tokens
        result = seq.analyze(tokens=tokens)
        self.assertLess(result.overall_score, 80)

    def test_analyze_constant_tokens(self):
        tokens = ["AAAA"] * 100
        seq = self.Sequencer.__new__(self.Sequencer)
        seq.tokens = tokens
        result = seq.analyze(tokens=tokens)
        self.assertLess(result.entropy_per_char, 1.0)
        self.assertIn("critical", result.rating.lower())

    def test_result_to_dict(self):
        result = self.SequencerResult(sample_size=50, overall_score=75.0, rating="good")
        d = result.to_dict()
        self.assertEqual(d["sample_size"], 50)
        self.assertEqual(d["rating"], "good")

    def test_shannon_entropy_static(self):
        import secrets
        tokens = [secrets.token_hex(16) for _ in range(50)]
        entropy = self.Sequencer._shannon_entropy(tokens)
        self.assertGreater(entropy, 0)

    def test_chi_squared_static(self):
        import secrets
        tokens = [secrets.token_hex(16) for _ in range(50)]
        chi_sq, p = self.Sequencer._chi_squared_test(tokens)
        self.assertGreater(chi_sq, 0)

    def test_monobit_static(self):
        import secrets
        tokens = [secrets.token_hex(16) for _ in range(50)]
        ratio = self.Sequencer._monobit_test(tokens)
        self.assertGreater(ratio, 0)
        self.assertLess(ratio, 1)

    def test_runs_test_static(self):
        import secrets
        tokens = [secrets.token_hex(16) for _ in range(50)]
        score = self.Sequencer._runs_test(tokens)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 1)

    def test_block_frequency_static(self):
        import secrets
        tokens = [secrets.token_hex(16) for _ in range(50)]
        score = self.Sequencer._block_frequency_test(tokens)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 1)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestIntruderPayloads(unittest.TestCase):

    def setUp(self):
        from vapt.engine.intruder import BUILTIN_PAYLOADS, PayloadGenerator
        self.PayloadGenerator = PayloadGenerator
        self.BUILTIN_PAYLOADS = BUILTIN_PAYLOADS

    def test_builtin_sqli(self):
        payloads = self.PayloadGenerator.builtin("sqli")
        self.assertGreater(len(payloads), 5)
        self.assertTrue(any("'" in p for p in payloads))

    def test_builtin_xss(self):
        payloads = self.PayloadGenerator.builtin("xss")
        self.assertGreater(len(payloads), 5)
        self.assertTrue(any("script" in p for p in payloads))

    def test_builtin_all_sets_exist(self):
        for name in ["sqli", "xss", "traversal", "ssti", "nosql", "commands", "common_passwords"]:
            payloads = self.PayloadGenerator.builtin(name)
            self.assertGreater(len(payloads), 0, f"Empty payload set: {name}")

    def test_number_range(self):
        nums = self.PayloadGenerator.number_range(1, 5)
        self.assertEqual(nums, ["1", "2", "3", "4", "5"])

    def test_char_range(self):
        chars = self.PayloadGenerator.char_range("a", "d")
        self.assertEqual(chars, ["a", "b", "c", "d"])

    def test_from_list(self):
        items = ["a", "b", "c"]
        self.assertEqual(self.PayloadGenerator.from_list(items), items)

    def test_case_variations(self):
        variations = self.PayloadGenerator.case_variations("ab")
        self.assertIn("ab", variations)
        self.assertIn("AB", variations)
        self.assertIn("Ab", variations)
        self.assertIn("aB", variations)

    def test_dates(self):
        dates = self.PayloadGenerator.dates(2024, 2025)
        self.assertGreater(len(dates), 300)
        self.assertTrue(any("2024" in d for d in dates))


class TestIntruderConfig(unittest.TestCase):

    def setUp(self):
        from vapt.engine.intruder import (
            BATTERING_RAM,
            CLUSTER_BOMB,
            PITCHFORK,
            SNIPER,
            Intruder,
            IntruderConfig,
        )
        self.Intruder = Intruder
        self.IntruderConfig = IntruderConfig
        self.SNIPER = SNIPER
        self.BATTERING_RAM = BATTERING_RAM
        self.PITCHFORK = PITCHFORK
        self.CLUSTER_BOMB = CLUSTER_BOMB

    def test_config_defaults(self):
        cfg = self.IntruderConfig(
            base_url="http://example.com/search?q=§test§",
            positions=["test"],
            payloads=[["a", "b"]],
        )
        self.assertEqual(cfg.method, "GET")
        self.assertEqual(cfg.threads, 10)
        self.assertEqual(cfg.attack_type, "sniper")

    def test_intruder_init(self):
        cfg = self.IntruderConfig(
            base_url="http://example.com/search?q=§test§",
            positions=["test"],
            payloads=[["a", "b"]],
            attack_type=self.SNIPER,
        )
        intruder = self.Intruder(cfg)
        self.assertIsNotNone(intruder)
        self.assertEqual(intruder.config.attack_type, self.SNIPER)

    def test_parse_positions(self):
        cfg = self.IntruderConfig(
            base_url="http://example.com/§p1§?q=§p2§",
            positions=["p1", "p2"],
            payloads=[["a", "b"]],
        )
        intruder = self.Intruder(cfg)
        positions = intruder._parse_positions(cfg.base_url)
        self.assertEqual(len(positions), 2)

    def test_generate_sniper_payloads(self):
        cfg = self.IntruderConfig(
            base_url="http://example.com/§p1§?q=§p2§",
            positions=["p1", "p2"],
            payloads=[["a", "b", "c"]],
            attack_type=self.SNIPER,
        )
        intruder = self.Intruder(cfg)
        payloads = list(intruder._generate_attack_payloads())
        self.assertGreater(len(payloads), 0)

    def test_generate_battering_ram_payloads(self):
        cfg = self.IntruderConfig(
            base_url="http://example.com/§p1§?q=§p2§",
            positions=["p1", "p2"],
            payloads=[["x", "y"]],
            attack_type=self.BATTERING_RAM,
        )
        intruder = self.Intruder(cfg)
        payloads = list(intruder._generate_attack_payloads())
        self.assertEqual(len(payloads), 2)
        for p in payloads:
            vals = list(p.values())
            self.assertTrue(all(v == vals[0] for v in vals))

    def test_generate_cluster_bomb_payloads(self):
        cfg = self.IntruderConfig(
            base_url="http://example.com/§p1§?q=§p2§",
            positions=["p1", "p2"],
            payloads=[["a", "b"], ["1", "2"]],
            attack_type=self.CLUSTER_BOMB,
        )
        intruder = self.Intruder(cfg)
        payloads = list(intruder._generate_attack_payloads())
        self.assertEqual(len(payloads), 4)

    def test_build_request_url(self):
        cfg = self.IntruderConfig(
            base_url="http://example.com/§p1§?q=§p2§",
            positions=["p1", "p2"],
            payloads=[["a"]],
        )
        intruder = self.Intruder(cfg)
        url = intruder._build_request_url({0: "INJECTED", 1: "FUZZ"})
        self.assertIn("INJECTED", url)
        self.assertIn("FUZZ", url)
        self.assertNotIn("§", url)

    def test_summary_empty(self):
        cfg = self.IntruderConfig(
            base_url="http://example.com/§p1§",
            positions=["p1"],
            payloads=[["a"]],
        )
        intruder = self.Intruder(cfg)
        s = intruder.summary()
        self.assertEqual(s["total_requests"], 0)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestCrawlerDataclasses(unittest.TestCase):

    def test_crawl_form(self):
        from vapt.scanner.crawler import CrawlForm
        form = CrawlForm(url="http://ex.com", action="/login", method="POST",
                         inputs=[{"name": "user", "type": "text"}])
        self.assertEqual(form.method, "POST")
        self.assertEqual(len(form.inputs), 1)

    def test_crawl_endpoint(self):
        from vapt.scanner.crawler import CrawlEndpoint
        ep = CrawlEndpoint(url="/api/v1/users", method="GET", source="app.js")
        self.assertEqual(ep.source, "app.js")

    def test_crawl_result_to_dict(self):
        from vapt.scanner.crawler import CrawlResult
        r = CrawlResult(target="http://ex.com", pages_crawled=5, urls=["a", "b"])
        d = r.to_dict()
        self.assertEqual(d["pages_crawled"], 5)
        self.assertIn("unique_urls", d)

    def test_crawler_light_init(self):
        from vapt.scanner.crawler import CrawlerLight
        cl = CrawlerLight("http://example.com", max_depth=2, max_pages=10)
        self.assertEqual(cl.max_depth, 2)
        self.assertEqual(cl.max_pages, 10)

    def test_crawler_init(self):
        from vapt.scanner.crawler import Crawler
        c = Crawler("http://example.com", max_depth=2, max_pages=20, headless=True)
        self.assertEqual(c.target, "http://example.com")
        self.assertEqual(c.max_depth, 2)

    def test_crawler_is_allowed(self):
        from vapt.scanner.crawler import Crawler
        c = Crawler("http://example.com")
        self.assertTrue(c._is_allowed("http://example.com/page"))
        self.assertFalse(c._is_allowed("http://other.com/page"))

    def test_crawler_normalize_url(self):
        from vapt.scanner.crawler import Crawler
        c = Crawler("http://example.com")
        result = c._normalize_url("/about", "http://example.com")
        self.assertEqual(result, "http://example.com/about")

    def test_crawler_normalize_url_fragment(self):
        from vapt.scanner.crawler import Crawler
        c = Crawler("http://example.com")
        result = c._normalize_url("#section", "http://example.com/page")
        self.assertIsNone(result)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestProxyStorage(unittest.TestCase):

    def setUp(self):
        from vapt.proxy.storage import Flow, ProxyStorage
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.storage = ProxyStorage(db_path=self.tmp.name)
        self.Flow = Flow

    def tearDown(self):
        self.storage.close()
        os.unlink(self.tmp.name)

    def test_save_and_get_flow(self):
        flow = self.Flow(
            method="GET", url="http://example.com/test", host="example.com",
            path="/test", request_headers={"Host": "example.com"},
        )
        flow_id = self.storage.save_flow(flow)
        self.assertGreater(flow_id, 0)
        retrieved = self.storage.get_flow(flow_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.method, "GET")
        self.assertEqual(retrieved.host, "example.com")

    def test_update_response(self):
        flow = self.Flow(method="POST", url="http://ex.com/api", host="ex.com", path="/api")
        fid = self.storage.save_flow(flow)
        self.storage.update_response(fid, 200, {"Content-Type": "application/json"}, b'{"ok":true}', 0.5)
        updated = self.storage.get_flow(fid)
        self.assertEqual(updated.status_code, 200)
        self.assertAlmostEqual(updated.response_time, 0.5, places=1)

    def test_get_flows_filter_host(self):
        for host in ["a.com", "b.com", "a.com"]:
            self.storage.save_flow(self.Flow(method="GET", url=f"http://{host}/", host=host, path="/"))
        flows = self.storage.get_flows(host="a.com")
        self.assertEqual(len(flows), 2)

    def test_get_flows_filter_method(self):
        self.storage.save_flow(self.Flow(method="GET", url="http://x.com/", host="x.com", path="/"))
        self.storage.save_flow(self.Flow(method="POST", url="http://x.com/", host="x.com", path="/"))
        self.assertEqual(len(self.storage.get_flows(method="POST")), 1)

    def test_get_flow_count(self):
        self.assertEqual(self.storage.get_flow_count(), 0)
        self.storage.save_flow(self.Flow(method="GET", url="http://x.com", host="x.com", path="/"))
        self.assertEqual(self.storage.get_flow_count(), 1)

    def test_delete_flow(self):
        fid = self.storage.save_flow(self.Flow(method="GET", url="http://x.com", host="x.com", path="/"))
        self.storage.delete_flow(fid)
        self.assertIsNone(self.storage.get_flow(fid))

    def test_clear_flows(self):
        for _ in range(5):
            self.storage.save_flow(self.Flow(method="GET", url="http://x.com", host="x.com", path="/"))
        self.storage.clear_flows()
        self.assertEqual(self.storage.get_flow_count(), 0)

    def test_add_note(self):
        fid = self.storage.save_flow(self.Flow(method="GET", url="http://x.com", host="x.com", path="/"))
        self.storage.add_note(fid, "suspicious response")
        flow = self.storage.get_flow(fid)
        self.assertIn("suspicious", flow.notes)

    def test_add_tag(self):
        fid = self.storage.save_flow(self.Flow(method="GET", url="http://x.com", host="x.com", path="/"))
        self.storage.add_tag(fid, "vuln")
        self.storage.add_tag(fid, "sqli")
        flow = self.storage.get_flow(fid)
        self.assertIn("vuln", flow.tags)
        self.assertIn("sqli", flow.tags)

    def test_save_to_repeater(self):
        fid = self.storage.save_flow(self.Flow(method="GET", url="http://x.com", host="x.com", path="/"))
        rid = self.storage.save_to_repeater(fid, "test-request")
        self.assertGreater(rid, 0)
        items = self.storage.get_repeater_items()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["name"], "test-request")

    def test_export_flows(self):
        for i in range(3):
            self.storage.save_flow(self.Flow(method="GET", url=f"http://x.com/{i}", host="x.com", path=f"/{i}"))
        out = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        out.close()
        try:
            count = self.storage.export_flows(out.name)
            self.assertEqual(count, 3)
            import json
            with open(out.name) as f:
                data = json.load(f)
            self.assertEqual(len(data), 3)
        finally:
            os.unlink(out.name)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestProxyServerHelpers(unittest.TestCase):

    def test_parse_request_line(self):
        from vapt.proxy.server import _parse_request_line
        method, target, version = _parse_request_line(b"GET /index.html HTTP/1.1\r\nHost: example.com")
        self.assertEqual(method, "GET")
        self.assertEqual(target, "/index.html")
        self.assertEqual(version, "HTTP/1.1")

    def test_parse_headers(self):
        from vapt.proxy.server import _parse_headers
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
        headers = _parse_headers(raw)
        self.assertEqual(headers["Host"], "example.com")
        self.assertEqual(headers["User-Agent"], "test")

    def test_get_content_length(self):
        from vapt.proxy.server import _get_content_length
        self.assertEqual(_get_content_length({"Content-Length": "42"}), 42)
        self.assertEqual(_get_content_length({}), 0)

    def test_build_raw_request(self):
        from vapt.proxy.server import _build_raw_request
        raw = _build_raw_request("GET", "/test", {"Host": "example.com"})
        self.assertIn(b"GET /test HTTP/1.1", raw)
        self.assertIn(b"Host: example.com", raw)

    def test_parse_response_status(self):
        from vapt.proxy.server import _parse_response_status
        status = _parse_response_status(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
        self.assertEqual(status, 200)

    def test_parse_response_status_404(self):
        from vapt.proxy.server import _parse_response_status
        self.assertEqual(_parse_response_status(b"HTTP/1.1 404 Not Found\r\n\r\n"), 404)


class TestProxyFilter(unittest.TestCase):

    def setUp(self):
        from vapt.proxy.server import ProxyFilter
        self.ProxyFilter = ProxyFilter

    def test_no_filters(self):
        f = self.ProxyFilter()
        self.assertTrue(f.should_capture("GET", "http://example.com", "example.com"))

    def test_include_domains(self):
        f = self.ProxyFilter(include_domains=["example.com"])
        self.assertTrue(f.should_capture("GET", "http://example.com/x", "example.com"))
        self.assertFalse(f.should_capture("GET", "http://other.com/x", "other.com"))

    def test_exclude_domains(self):
        f = self.ProxyFilter(exclude_domains=["ads.com"])
        self.assertTrue(f.should_capture("GET", "http://example.com/x", "example.com"))
        self.assertFalse(f.should_capture("GET", "http://ads.com/x", "ads.com"))

    def test_include_methods(self):
        f = self.ProxyFilter(include_methods=["POST", "PUT"])
        self.assertTrue(f.should_capture("POST", "http://ex.com/x", "ex.com"))
        self.assertFalse(f.should_capture("GET", "http://ex.com/x", "ex.com"))

    def test_exclude_extensions(self):
        f = self.ProxyFilter(exclude_extensions=[".css", ".js"])
        self.assertFalse(f.should_capture("GET", "http://ex.com/style.css", "ex.com"))
        self.assertTrue(f.should_capture("GET", "http://ex.com/api/data", "ex.com"))


class TestCertificateAuthority(unittest.TestCase):

    def setUp(self):
        from vapt.proxy.server import CertificateAuthority
        self.tmpdir = tempfile.mkdtemp()
        self.ca = CertificateAuthority(ca_dir=self.tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_ca_files_created(self):
        self.assertTrue(Path(self.tmpdir, "ca.key").exists())
        self.assertTrue(Path(self.tmpdir, "ca.pem").exists())

    def test_ca_cert_pem_property(self):
        pem = self.ca.ca_cert_pem
        self.assertIn("BEGIN CERTIFICATE", pem)

    def test_get_cert_for_host(self):
        cert_path, key_path = self.ca.get_cert_for_host("example.com")
        self.assertTrue(Path(cert_path).exists())
        self.assertTrue(Path(key_path).exists())

    def test_cert_cached(self):
        p1 = self.ca.get_cert_for_host("test.com")
        p2 = self.ca.get_cert_for_host("test.com")
        self.assertEqual(p1, p2)

    def test_get_ssl_context(self):
        import ssl
        ctx = self.ca.get_ssl_context("example.com")
        self.assertIsInstance(ctx, ssl.SSLContext)

    def test_different_hosts_different_certs(self):
        c1 = self.ca.get_cert_for_host("host1.com")
        c2 = self.ca.get_cert_for_host("host2.com")
        self.assertNotEqual(c1[0], c2[0])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestProxyServerInit(unittest.TestCase):

    def test_proxy_server_init(self):
        from vapt.proxy.server import CertificateAuthority, ProxyServer
        from vapt.proxy.storage import ProxyStorage

        tmpdir = tempfile.mkdtemp()
        tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp_db.close()
        try:
            storage = ProxyStorage(db_path=tmp_db.name)
            ca = CertificateAuthority(ca_dir=tmpdir)
            server = ProxyServer(host="127.0.0.1", port=0, storage=storage, ca=ca)
            self.assertFalse(server.running)
            self.assertEqual(server.flow_count, 0)
            storage.close()
        finally:
            os.unlink(tmp_db.name)
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestTUIImports(unittest.TestCase):

    def test_import_tui(self):
        from vapt.tui.app import VAPTApp, launch_tui
        self.assertIsNotNone(VAPTApp)
        self.assertIsNotNone(launch_tui)

    def test_import_tabs(self):
        from vapt.tui.app import CodecTab, IntruderTab, ProxyTab, RepeaterTab
        for tab_cls in (ProxyTab, RepeaterTab, IntruderTab, CodecTab):
            self.assertIsNotNone(tab_cls)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestCLICommands(unittest.TestCase):

    def test_proxy_command_exists(self):
        from vapt.main import cmd_proxy
        self.assertIsNotNone(cmd_proxy)

    def test_tui_command_exists(self):
        from vapt.main import cmd_tui
        self.assertIsNotNone(cmd_tui)

    def test_crawl_command_exists(self):
        from vapt.main import cmd_crawl
        self.assertIsNotNone(cmd_crawl)

    def test_intruder_command_exists(self):
        from vapt.main import cmd_intruder
        self.assertIsNotNone(cmd_intruder)

    def test_sequencer_command_exists(self):
        from vapt.main import cmd_sequencer
        self.assertIsNotNone(cmd_sequencer)

    def test_codec_command_exists(self):
        from vapt.main import cmd_codec
        self.assertIsNotNone(cmd_codec)


if __name__ == "__main__":
    unittest.main()
