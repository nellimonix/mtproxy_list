import ast
import base64
import importlib.util
import json
import os
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import quote

os.environ["PYTHON_DOTENV_DISABLED"] = "1"
MODULE_PATH = Path(__file__).resolve().parents[1] / "main.py"
spec = importlib.util.spec_from_file_location("parser_under_test", MODULE_PATH)
parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parser)

PROXY = {"host": "proxy.example", "port": 443, "secret": "Ab_C-123", "country": "DE", "addTime": 123}


def encoded(data, spaced=False):
    code = "return" + ("\n " if spaced else " ") + json.dumps(data)
    value = base64.b64encode(code.encode()).decode()
    return f"eval(atob('{value}'))"


def uri_wrap(code):
    return "eval(decodeURIComponent('" + quote(code, safe="") + "'))"


def card(country="#DE", qr="", secret="Ab_C-123", port="443"):
    return (f'<div class="proxy-item"><a href="tg://proxy?server=proxy.example&amp;port={port}'
            f'&amp;secret={secret}&amp;bot=%40bot&amp;channel=%40channel">truncated...</a>'
            f'{country}<button onclick="{qr}"></button></div>')


def telegram_post(post_id, host, country="DE", timestamp="2026-09-10T12:00:00+00:00"):
    return (f'<div class="tgme_widget_message" data-post="mtpro_xyz/{post_id}">'
            f'<div class="tgme_widget_message_text"><code>{country}</code>'
            f'<a href="https://t.me/proxy?server={host}&amp;amp;port=443&amp;amp;secret=secret-{post_id}'
            f'&amp;amp;bot=@mtpro_xyz_bot&amp;amp;channel=@mtpro_xyz">proxy</a></div>'
            f'<time datetime="{timestamp}"></time></div>')


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.feed_patch = patch.object(parser, "fetch_proxies_from_json_feed", side_effect=RuntimeError("unavailable"))
        self.feed_patch.start()
        self.addCleanup(self.feed_patch.stop)
        self.relay_patch = patch.object(parser, "HTTP_RELAY_URL", "")
        self.relay_patch.start()
        self.addCleanup(self.relay_patch.stop)
        self.source_proxy_patch = patch.object(parser, "SOURCE_PROXY_CURL_CONFIG", "")
        self.source_proxy_patch.start()
        self.addCleanup(self.source_proxy_patch.stop)
        parser._socks_candidates = []
        parser._socks_candidates_loaded = 0.0
        parser._working_socks_proxy = None

    def test_http_relay_on_cloudflare_403(self):
        blocked = Mock(status_code=403)
        error = parser.requests.HTTPError("blocked", response=blocked)
        blocked.raise_for_status.side_effect = error
        good = Mock(text="ok")
        session = Mock()
        session.get.side_effect = [blocked, good]
        with patch.object(parser, "HTTP_RELAY_URL", "http://127.0.0.1:3014"):
            self.assertIs(parser.get_source(session, parser.PAGE_URL), good)
        self.assertEqual(session.get.call_args.args[0], "http://127.0.0.1:3014/mtproto-ru")
        self.assertEqual(good.url, parser.PAGE_URL)
        good.raise_for_status.assert_called_once()

    def test_http_relay_preserves_script_query(self):
        session = Mock()
        good = Mock()
        session.get.side_effect = [parser.requests.ConnectTimeout(), good]
        with patch.object(parser, "HTTP_RELAY_URL", "http://127.0.0.1:3014"):
            parser.get_source(session, "https://mtpro.xyz/wp-content/cache/autoptimize/js/file.js?v=2")
        self.assertEqual(session.get.call_args.args[0], "http://127.0.0.1:3014/wp-content/cache/autoptimize/js/file.js?v=2")

    def test_http_relay_not_used_for_404(self):
        response = Mock(status_code=404)
        response.raise_for_status.side_effect = parser.requests.HTTPError(response=response)
        session = Mock()
        session.get.return_value = response
        with patch.object(parser, "HTTP_RELAY_URL", "http://127.0.0.1:3014"), self.assertRaises(parser.requests.HTTPError):
            parser.get_source(session, parser.PAGE_URL)
        session.get.assert_called_once()

    def test_http_relay_rejects_other_origin(self):
        session = Mock()
        session.get.side_effect = parser.requests.ConnectTimeout()
        with patch.object(parser, "HTTP_RELAY_URL", "http://127.0.0.1:3014"), self.assertRaises(ValueError):
            parser.get_source(session, "https://other.example/file.js")
        session.get.assert_called_once()

    def test_http_relay_rejects_credentials_in_url(self):
        session = Mock()
        session.get.side_effect = parser.requests.ConnectTimeout()
        with patch.object(parser, "HTTP_RELAY_URL", "http://user:password@127.0.0.1"), self.assertRaises(ValueError):
            parser.get_source(session, parser.PAGE_URL)

    def test_http_relay_error_propagates(self):
        session = Mock()
        session.get.side_effect = parser.requests.ConnectTimeout()
        with patch.object(parser, "HTTP_RELAY_URL", "http://127.0.0.1:3014"), patch.object(parser, "get_source_via_socks", side_effect=RuntimeError("no route")), self.assertRaisesRegex(RuntimeError, "no route"):
            parser.get_source(session, parser.PAGE_URL)
        self.assertEqual(session.get.call_count, 2)

    def test_successful_direct_request_does_not_use_relay(self):
        session = Mock()
        with patch.object(parser, "HTTP_RELAY_URL", "http://127.0.0.1:3014"):
            parser.get_source(session, parser.PAGE_URL)
        session.get.assert_called_once()

    def test_socks_candidates_are_public_and_deduplicated(self):
        response = Mock(
            content=b"8.8.8.8:1080\n8.8.8.8:1080\n127.0.0.1:1080\n10.0.0.1:1080\nbad\n1.1.1.1:70000\n",
            text="8.8.8.8:1080\n8.8.8.8:1080\n127.0.0.1:1080\n10.0.0.1:1080\nbad\n1.1.1.1:70000\n",
        )
        session = Mock()
        session.get.return_value = response
        self.assertEqual(parser.load_socks_candidates(session), ["8.8.8.8:1080"])
        response.raise_for_status.assert_called_once()

    def test_refresh_interval_is_shorter_than_publish_interval(self):
        self.assertLess(parser.SOCKS_CANDIDATE_TTL, parser.INTERVAL_SECONDS)
        self.assertGreaterEqual(parser.SOCKS_MAX_ATTEMPTS, 180)
        self.assertGreaterEqual(parser.SOURCE_PROXY_ATTEMPTS, 2)

    def test_curl_socks_keeps_https_verification(self):
        result = Mock(returncode=0, stdout=b"payload")
        with patch.object(parser.subprocess, "run", return_value=result) as run:
            response = parser.curl_via_socks(parser.PAGE_URL, "8.8.8.8:1080")
        command = run.call_args.args[0]
        self.assertIn("--socks5-hostname", command)
        self.assertIn("--proto", command)
        self.assertNotIn("--insecure", command)
        self.assertEqual(response.text, "payload")

    @unittest.skipUnless(os.name == "posix", "POSIX file permissions")
    def test_configured_proxy_keeps_credentials_out_of_arguments(self):
        config = Path(self._testMethodName)
        config.write_text('proxy = "socks5h://proxy.example:1000"\nproxy-user = "user:password"\n')
        config.chmod(0o600)
        result = Mock(returncode=0, stdout=b"payload")
        try:
            with patch.object(parser, "SOURCE_PROXY_CURL_CONFIG", str(config)), patch.object(parser.subprocess, "run", return_value=result) as run:
                response = parser.curl_via_configured_proxy(parser.PAGE_URL)
        finally:
            config.unlink(missing_ok=True)
        command = run.call_args.args[0]
        self.assertIn("--config", command)
        self.assertNotIn("user:password", command)
        self.assertNotIn("--insecure", command)
        self.assertEqual(response.text, "payload")

    @unittest.skipUnless(os.name == "posix", "POSIX file permissions")
    def test_configured_proxy_rejects_readable_config(self):
        config = Path(self._testMethodName)
        config.write_text("test")
        config.chmod(0o644)
        try:
            with patch.object(parser, "SOURCE_PROXY_CURL_CONFIG", str(config)), self.assertRaisesRegex(ValueError, "0600"):
                parser.curl_via_configured_proxy(parser.PAGE_URL)
        finally:
            config.unlink(missing_ok=True)

    def test_get_source_prefers_configured_proxy_before_public_pool(self):
        blocked = Mock(status_code=403)
        blocked.raise_for_status.side_effect = parser.requests.HTTPError(response=blocked)
        good = parser.source_response(parser.PAGE_URL, b"ok")
        session = Mock()
        session.get.return_value = blocked
        with patch.object(parser, "HTTP_RELAY_URL", ""), patch.object(parser, "SOURCE_PROXY_CURL_CONFIG", "credential-file"), patch.object(parser, "curl_via_configured_proxy", return_value=good) as configured, patch.object(parser, "get_source_via_socks") as public:
            self.assertIs(parser.get_source(session, parser.PAGE_URL), good)
        configured.assert_called_once_with(parser.PAGE_URL)
        public.assert_not_called()

    def test_socks_uses_cached_route(self):
        good = parser.source_response(parser.PAGE_URL, b"ok")
        parser._working_socks_proxy = "8.8.8.8:1080"
        with patch.object(parser, "load_socks_candidates", return_value=["1.1.1.1:1080"]), patch.object(parser, "curl_via_socks", return_value=good) as curl:
            self.assertIs(parser.get_source_via_socks(Mock(), parser.PAGE_URL), good)
        curl.assert_called_once_with(parser.PAGE_URL, "8.8.8.8:1080")

    def test_get_source_falls_back_to_socks(self):
        blocked = Mock(status_code=403)
        blocked.raise_for_status.side_effect = parser.requests.HTTPError(response=blocked)
        good = parser.source_response(parser.PAGE_URL, b"ok")
        session = Mock()
        session.get.return_value = blocked
        with patch.object(parser, "HTTP_RELAY_URL", "http://127.0.0.1:3014"), patch.object(parser, "get_source_via_socks", return_value=good) as socks:
            self.assertIs(parser.get_source(session, parser.PAGE_URL), good)
        socks.assert_called_once_with(session, parser.PAGE_URL)

    def test_get_source_can_skip_socks(self):
        blocked = Mock(status_code=403)
        blocked.raise_for_status.side_effect = parser.requests.HTTPError(response=blocked)
        session = Mock()
        session.get.return_value = blocked
        with patch.object(parser, "HTTP_RELAY_URL", ""), patch.object(parser, "get_source_via_socks") as socks, self.assertRaisesRegex(RuntimeError, "HTTP 403"):
            parser.get_source(session, parser.PAGE_URL, allow_socks=False)
        socks.assert_not_called()

    def test_telegram_extracts_double_escaped_link(self):
        data, post_ids = parser.extract_proxies_from_telegram(telegram_post(123, "proxy.example"))
        self.assertEqual(post_ids, [123])
        self.assertEqual(data, [{
            "host": "proxy.example",
            "port": "443",
            "secret": "secret-123",
            "country": "DE",
            "addTime": 1789041600,
        }])

    def test_telegram_paginates_and_limits_result(self):
        first = telegram_post(103, "c.example") + telegram_post(102, "b.example")
        second = telegram_post(101, "a.example")
        responses = [Mock(content=first.encode(), text=first), Mock(content=second.encode(), text=second)]
        session = Mock()
        session.get.side_effect = responses
        with patch.object(parser, "TELEGRAM_TARGET_PROXIES", 3):
            result = parser.fetch_proxies_from_telegram(session)
        self.assertEqual(len(result), 3)
        self.assertEqual(session.get.call_args_list[1].kwargs["params"], {"before": 102})

    def test_fetch_uses_telegram_before_socks(self):
        expected = [PROXY]
        with patch.object(parser, "fetch_proxies_from_site", side_effect=RuntimeError("blocked")) as site, patch.object(parser, "fetch_proxies_from_telegram", return_value=expected) as telegram:
            self.assertEqual(parser.fetch_proxies(), expected)
        site.assert_called_once()
        telegram.assert_called_once()

    def test_old_encoding(self):
        self.assertEqual(parser.extract_proxies_from_js(encoded([PROXY])), [PROXY])

    def test_new_encoding(self):
        self.assertEqual(parser.extract_proxies_from_js(uri_wrap(encoded([PROXY]))), [PROXY])

    def test_nested_encoding(self):
        self.assertEqual(parser.extract_proxies_from_js(uri_wrap(uri_wrap(encoded([PROXY])))), [PROXY])

    def test_return_whitespace_and_brackets_in_secret(self):
        data = [{**PROXY, "secret": 'a]b"c\\d'}]
        self.assertEqual(parser.extract_proxies_from_js(uri_wrap(encoded(data, True))), data)

    def test_no_candidate(self):
        with self.assertRaisesRegex(RuntimeError, "нет подходящего"):
            parser.extract_proxies_from_js("atob('YQ==')")

    def test_bad_base64_utf8(self):
        with self.assertRaises(RuntimeError):
            parser.extract_proxies_from_js("eval(atob('/w=='))")

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            parser.normalize_proxies([], "test")

    def test_invalid_row_rejects_entire_result(self):
        for changes in ({"port": True}, {"port": 0}, {"port": 65536}, {"port": 443.5},
                        {"port": "4e2"}, {"secret": ""}, {"country": "???"}, {"addTime": "123"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                parser.normalize_proxies([PROXY, {**PROXY, **changes}], "test")

    def test_dedup_normalizes_port_and_retains_latest(self):
        newer = {**PROXY, "port": "443", "addTime": 200}
        result = parser.normalize_proxies([PROXY, newer], "test")
        self.assertEqual(result, [{**PROXY, "addTime": 200}])

    def test_same_host_different_secret_is_not_duplicate(self):
        self.assertEqual(len(parser.normalize_proxies([PROXY, {**PROXY, "secret": "other"}], "test")), 2)

    def test_stable_sort(self):
        data = [PROXY, {**PROXY, "host": "a.example"}]
        self.assertEqual(parser.normalize_proxies(data, "test"), parser.normalize_proxies(data[::-1], "test"))

    def test_html_entities_and_query(self):
        result = parser.extract_proxies_from_html(card(secret="Ab%2BC%2F%3D"))[0]
        self.assertEqual(result, {"host": "proxy.example", "port": 443, "secret": "Ab+C/=", "country": "DE", "bot": "@bot", "channel": "@channel"})

    def test_numeric_entities(self):
        self.assertEqual(parser.extract_proxies_from_html(card().replace("&amp;", "&#038;"))[0]["port"], 443)

    def test_details_and_duplicates(self):
        html = card() + "<details><summary>Ещё</summary>" + card() + card(secret="other") + "</details>"
        self.assertEqual(len(parser.extract_proxies_from_html(html)), 2)

    def test_qr_country_fallback(self):
        html = card(country="", qr="openQRModal({host:'proxy.example',country:'DE'})")
        self.assertEqual(parser.extract_proxies_from_html(html)[0]["country"], "DE")

    def test_changed_container(self):
        self.assertEqual(parser.extract_proxies_from_html(card().replace('class="proxy-item"', 'class="new-row"'))[0]["country"], "DE")

    def test_conflicting_country_rejected(self):
        with self.assertRaises(ValueError):
            parser.extract_proxies_from_html(card(qr="openQRModal({country:'PL'})"))

    def test_country_not_taken_from_other_row(self):
        with self.assertRaises(ValueError):
            parser.extract_proxies_from_html("<section>" + card(country="") + card(secret="other") + "</section>")

    def test_duplicate_query_params_rejected(self):
        with self.assertRaises(ValueError):
            parser.extract_proxies_from_html(card().replace("&amp;port=443", "&amp;port=443&amp;port=80"))

    def test_mtproto_scope(self):
        html = '<div id="raw">' + card(country="") + '</div><div id="mtproto">' + card() + '</div>'
        self.assertEqual(len(parser.extract_proxies_from_html(html)), 1)

    def test_fetch_multiple_scripts_and_new_filename(self):
        page = Mock(text='<script src="/other.js"></script><script src="/list-v2.js?v=1&amp;x=2"></script>', url=parser.PAGE_URL)
        script1 = Mock(text="const empty = true")
        script2 = Mock(text=uri_wrap(encoded([PROXY])))
        session = Mock()
        session.get.side_effect = [page, script1, script2]
        with patch.object(parser.requests, "Session") as factory:
            factory.return_value.__enter__.return_value = session
            self.assertEqual(parser.fetch_proxies(), [PROXY])
        self.assertEqual(session.get.call_args_list[-1].args[0], "https://mtpro.xyz/list-v2.js?v=1&x=2")
        for call in session.get.call_args_list:
            self.assertEqual(call.kwargs["timeout"], parser.REQUEST_TIMEOUT)
        for response in (page, script1, script2):
            response.raise_for_status.assert_called_once()

    def test_fetch_html_fallback(self):
        page = Mock(text=card(), url=parser.PAGE_URL)
        session = Mock()
        session.get.return_value = page
        with patch.object(parser.requests, "Session") as factory:
            factory.return_value.__enter__.return_value = session
            self.assertEqual(parser.fetch_proxies()[0]["host"], PROXY["host"])

    def test_http_error_not_parsed(self):
        response = Mock(status_code=503)
        response.raise_for_status.side_effect = parser.requests.HTTPError("503", response=response)
        with patch.object(parser.requests, "Session") as factory:
            factory.return_value.__enter__.return_value.get.return_value = response
            with patch.object(parser, "get_source_via_socks", side_effect=RuntimeError("no route")), self.assertRaisesRegex(RuntimeError, "HTTP 503"):
                parser.fetch_proxies()

    def test_empty_not_written_or_published(self):
        with patch.object(parser, "git") as git, patch.object(parser, "encrypt_payload") as encrypt:
            parser.write_and_commit([])
            git.assert_not_called()
            encrypt.assert_not_called()

    def test_stale_generated_output_is_restored_before_pull(self):
        clean = Mock(returncode=0, stdout=" M mtproxy.json\n", stderr="")
        ok = Mock(returncode=0, stdout="", stderr="")
        changed = Mock(returncode=0, stdout="M  mtproxy.json\n", stderr="")
        commit = Mock(returncode=0, stdout="", stderr="")
        push = Mock(returncode=0, stdout="", stderr="")
        calls = [clean, ok, ok, ok, changed, commit, push]
        test_dir = Path(self._testMethodName)
        test_dir.mkdir(exist_ok=True)
        try:
            with patch.object(parser, "git", side_effect=calls) as git, patch.object(parser, "encrypt_payload", return_value="encrypted"), patch.object(parser, "load_key", return_value=b"0" * 32), patch.object(parser, "WORK_DIR", test_dir):
                parser.write_and_commit([PROXY])
        finally:
            (test_dir / parser.OUTPUT_FILENAME).unlink(missing_ok=True)
            test_dir.rmdir()
        commands = [call.args[0] for call in git.call_args_list]
        self.assertEqual(commands[0], ["status", "--porcelain", "--", parser.OUTPUT_FILENAME])
        self.assertEqual(commands[1], ["restore", "--worktree", "--", parser.OUTPUT_FILENAME])
        self.assertEqual(commands[2][0:2], ["pull", "--rebase"])
        self.assertEqual(commands[-2][-2:], ["--", parser.OUTPUT_FILENAME])

    def test_secret_redaction(self):
        with patch.object(parser, "GIT_TOKEN", "test-git-token"), patch.object(parser, "ENC_KEY_B64", "test-key"):
            self.assertEqual(parser._safe("test-git-token test-key"), "*** ***")

    def test_git_is_noninteractive_and_timed(self):
        with patch.object(parser.subprocess, "run") as run:
            parser.git(["status"])
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["timeout"], parser.GIT_TIMEOUT)
        self.assertEqual(kwargs["env"]["GIT_TERMINAL_PROMPT"], "0")

    def test_pull_failure_stops_before_add(self):
        clean = Mock(returncode=0, stdout="", stderr="")
        failure = Mock(returncode=1, stderr="network error")
        test_dir = Path(self._testMethodName)
        test_dir.mkdir(exist_ok=True)
        try:
            with patch.object(parser, "git", side_effect=[clean, failure]) as git, patch.object(parser, "encrypt_payload", return_value="encrypted"), patch.object(parser, "load_key", return_value=b"0" * 32), patch.object(parser, "WORK_DIR", test_dir):
                with self.assertRaisesRegex(RuntimeError, "git pull failed"):
                    parser.write_and_commit([PROXY])
        finally:
            (test_dir / parser.OUTPUT_FILENAME).unlink(missing_ok=True)
            test_dir.rmdir()
        self.assertEqual(git.call_count, 2)

    def test_encryption_roundtrip_and_determinism(self):
        key = os.urandom(32)
        first = parser.encrypt_payload([PROXY], key)
        self.assertEqual(first, parser.encrypt_payload([PROXY], key))
        envelope = json.loads(first)
        plaintext = parser.AESGCM(key).decrypt(base64.b64decode(envelope["iv"]), base64.b64decode(envelope["ct"]), None)
        self.assertEqual(json.loads(plaintext), [PROXY])


if __name__ == "__main__":
    unittest.main(verbosity=2)
