import base64
import copy
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import urlencode

os.environ['PYTHON_DOTENV_DISABLED'] = '1'
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main as collector

NOW = int(datetime(2026, 10, 30, tzinfo=timezone.utc).timestamp())


def timestamp(value=NOW):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def row(index=1, checked=NOW, kind='mtproto', **changes):
    params = {'server': f'proxy-{index}.example', 'secret': 'ee' + 'a' * 32}
    if kind == 'mtproto':
        params['port'] = 443
    else:
        params['secret'] = 'a' * 32
    result = {'server': params['server'], 'port': 443 if kind == 'mtproto' else '', 'link': 'https://t.me/' + ('proxy' if kind == 'mtproto' else 'webproxy') + '?' + urlencode(params), 'kind': kind, 'country': 'DE', 'checked': timestamp(checked)}
    return {**result, **changes}


def payload(rows=None, updated=NOW):
    return {'updated': timestamp(updated), 'source': 'https://provider.example/', 'proxies': [row()] if rows is None else rows}


class JsonSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        for name, value in [('WORK_DIR', Path(self.temp.name)), ('ENC_KEY_B64', base64.b64encode(b'k' * 32).decode())]:
            active = patch.object(collector, name, value)
            active.start()
            self.addCleanup(active.stop)
        active = patch.object(collector.time, 'time', return_value=NOW)
        active.start()
        self.addCleanup(active.stop)

    def extract(self, data):
        return collector.extract_proxies_from_json_feed(data, now=NOW)

    def test_parses_feed_and_keeps_verified_timestamp(self):
        result = self.extract(payload())[0]
        self.assertEqual(result, {'host': 'proxy-1.example', 'port': 443, 'secret': 'ee' + 'a' * 32, 'country': 'DE', 'addTime': NOW})

    def test_z_timestamp(self):
        self.assertEqual(collector.parse_feed_timestamp('2026-10-30T00:00:00Z'), NOW)

    def test_timezone_offset(self):
        self.assertEqual(collector.parse_feed_timestamp('2026-10-30T03:00:00+03:00'), NOW)

    def test_rejects_missing_timestamp_timezone(self):
        with self.assertRaises(ValueError):
            collector.parse_feed_timestamp('2026-10-30T00:00:00')

    def test_rejects_non_string_timestamp(self):
        for value in (None, 123, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                collector.parse_feed_timestamp(value)

    def test_rejects_stale_feed(self):
        with self.assertRaises(ValueError):
            self.extract(payload(updated=NOW - collector.JSON_SOURCE_MAX_AGE_SECONDS - 1))

    def test_rejects_future_feed(self):
        with self.assertRaises(ValueError):
            self.extract(payload(updated=NOW + collector.JSON_SOURCE_FUTURE_TOLERANCE_SECONDS + 1))

    def test_accepts_clock_skew(self):
        self.assertEqual(len(self.extract(payload(updated=NOW + 60))), 1)

    def test_skips_stale_rows(self):
        result = self.extract(payload([row(1, checked=NOW - collector.JSON_SOURCE_MAX_AGE_SECONDS - 1), row(2)]))
        self.assertEqual([p['host'] for p in result], ['proxy-2.example'])

    def test_skips_future_rows(self):
        result = self.extract(payload([row(1, checked=NOW + collector.JSON_SOURCE_FUTURE_TOLERANCE_SECONDS + 1), row(2)]))
        self.assertEqual([p['host'] for p in result], ['proxy-2.example'])

    def test_row_cannot_exceed_feed_timestamp(self):
        result = self.extract(payload([row(1, checked=NOW), row(2, checked=NOW - 1000)], updated=NOW - 1000))
        self.assertEqual([p['host'] for p in result], ['proxy-2.example'])

    def test_skips_unsupported_types(self):
        self.assertEqual(len(self.extract(payload([row(1, kind='socks5'), row(2)]))), 1)

    def test_rejects_invalid_root_shapes(self):
        for data in ([], None, {}, {'updated': timestamp(), 'proxies': {}}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.extract(data)

    def test_empty_feed_rejected(self):
        with self.assertRaises(ValueError):
            self.extract(payload([]))

    def test_invalid_rows_do_not_discard_good_rows(self):
        self.assertEqual(len(self.extract(payload([None, [], {}, row(2)]))), 1)

    def test_unrelated_links_rejected(self):
        bad = row(1)
        bad['link'] = bad['link'].replace('https://t.me/', 'https://unrelated.example/')
        self.assertEqual(len(self.extract(payload([bad, row(2)]))), 1)

    def test_duplicate_parameters_rejected(self):
        bad = row(1)
        bad['link'] += '&server=other.example'
        self.assertEqual(len(self.extract(payload([bad, row(2)]))), 1)

    def test_missing_secret_rejected(self):
        bad = row(1)
        bad['link'] = 'https://t.me/proxy?server=proxy-1.example&port=443'
        self.assertEqual(len(self.extract(payload([bad, row(2)]))), 1)

    def test_non_string_link_does_not_discard_good_rows(self):
        self.assertEqual(len(self.extract(payload([row(1, link={}), row(2)]))), 1)

    def test_boolean_port_rejected(self):
        bad = row(1, port=True)
        bad['link'] = bad['link'].replace('port=443', 'port=1')
        self.assertEqual(len(self.extract(payload([bad, row(2)]))), 1)

    def test_mismatched_server_rejected(self):
        self.assertEqual(len(self.extract(payload([row(1, server='different.example'), row(2)]))), 1)

    def test_mismatched_port_rejected(self):
        self.assertEqual(len(self.extract(payload([row(1, port=8443), row(2)]))), 1)

    def test_invalid_country_rejected(self):
        self.assertEqual(len(self.extract(payload([row(1, country='unknown'), row(2)]))), 1)

    def test_invalid_secret_rejected(self):
        bad = row(1)
        bad['link'] = bad['link'].replace('ee' + 'a' * 32, 'invalid')
        self.assertEqual(len(self.extract(payload([bad, row(2)]))), 1)

    def test_tg_link_supported(self):
        value = row(1)
        value['link'] = value['link'].replace('https://t.me/proxy?', 'tg://proxy?')
        self.assertEqual(len(self.extract(payload([value]))), 1)

    def test_webproxy_supported(self):
        result = self.extract(payload([row(kind='webproxy')]))[0]
        self.assertEqual(result['port'], '')
        self.assertEqual(result['type'], 'webproxy')

    def test_route_must_match_kind(self):
        bad = row(kind='webproxy')
        bad['link'] = bad['link'].replace('/webproxy?', '/proxy?')
        self.assertEqual(len(self.extract(payload([bad, row(2)]))), 1)

    def test_sorted_deduplicated_and_capped(self):
        rows = [row(i, checked=NOW-i) for i in range(60)]
        rows.append(copy.deepcopy(rows[0]))
        result = self.extract(payload(rows))
        self.assertEqual(len(result), 50)
        self.assertEqual(result[0]['addTime'], NOW)
        self.assertEqual(result[-1]['addTime'], NOW - 49)

    def test_request_is_timed_and_http_failure_propagates(self):
        session = Mock()
        response = Mock()
        response.raise_for_status.side_effect = collector.requests.HTTPError('unavailable')
        session.get.return_value = response
        with self.assertRaises(collector.requests.HTTPError):
            collector.fetch_proxies_from_json_feed(session)
        self.assertEqual(session.get.call_args.kwargs['timeout'], collector.REQUEST_TIMEOUT)

    def test_response_size_limit(self):
        session = Mock()
        session.get.return_value.content = b'x' * (collector.SOURCE_MAX_BYTES + 1)
        with self.assertRaises(ValueError):
            collector.fetch_proxies_from_json_feed(session)

    def test_invalid_json_rejected(self):
        session = Mock()
        session.get.return_value.content = b'invalid'
        session.get.return_value.json.side_effect = ValueError('invalid json')
        with self.assertRaises(ValueError):
            collector.fetch_proxies_from_json_feed(session)

    def test_http_200_html_not_treated_as_empty_success(self):
        session = Mock()
        session.get.return_value = collector.source_response(collector.JSON_SOURCE_URL, b'<html>blocked</html>')
        with self.assertRaises(ValueError):
            collector.fetch_proxies_from_json_feed(session)

    def test_json_restores_collection_when_site_is_blocked(self):
        data = self.extract(payload())
        with patch.object(collector, 'fetch_proxies_from_site', side_effect=RuntimeError('HTTP 403')) as site, patch.object(collector, 'fetch_proxies_from_json_feed', return_value=data), patch.object(collector, 'fetch_proxies_from_telegram') as telegram:
            self.assertEqual(collector.fetch_proxies(), data)
        site.assert_called_once()
        telegram.assert_not_called()

    def test_json_failure_still_uses_telegram(self):
        data = self.extract(payload())
        with patch.object(collector, 'fetch_proxies_from_site', side_effect=RuntimeError('HTTP 403')) as site, patch.object(collector, 'fetch_proxies_from_json_feed', side_effect=RuntimeError('stale')), patch.object(collector, 'fetch_proxies_from_telegram', return_value=data):
            self.assertEqual(collector.fetch_proxies(), data)
        site.assert_called_once()

    def test_all_public_sources_down_uses_existing_socks_route(self):
        data = self.extract(payload())
        with patch.object(collector, 'fetch_proxies_from_site', side_effect=[RuntimeError('blocked'), data]) as site, patch.object(collector, 'fetch_proxies_from_json_feed', side_effect=ValueError('stale')), patch.object(collector, 'fetch_proxies_from_telegram', side_effect=ValueError('empty')):
            self.assertEqual(collector.fetch_proxies(), data)
        self.assertTrue(site.call_args.kwargs['allow_socks'])

    def test_empty_sources_do_not_modify_published_cache(self):
        existing = collector.encrypt_payload(self.extract(payload()), collector.load_key())
        output = collector.WORK_DIR / collector.OUTPUT_FILENAME
        output.write_text(existing)
        with patch.object(collector, 'fetch_proxies_from_site', side_effect=RuntimeError('blocked')), patch.object(collector, 'fetch_proxies_from_json_feed', side_effect=ValueError('empty')), patch.object(collector, 'fetch_proxies_from_telegram', side_effect=ValueError('empty')):
            with self.assertRaises(RuntimeError):
                collector.fetch_proxies()
        self.assertEqual(output.read_text(), existing)

    def test_refresh_preserves_newer_cached_data(self):
        current = self.extract(payload([row(1, checked=NOW)]))
        output = collector.WORK_DIR / collector.OUTPUT_FILENAME
        output.write_text(collector.encrypt_payload(current, collector.load_key()))
        older = self.extract(payload([row(1, checked=NOW-60)]))
        self.assertEqual(collector.merge_telegram_proxies(older), current)

    def test_encrypted_result_keeps_existing_envelope(self):
        data = self.extract(payload())
        encoded = collector.encrypt_payload(data, collector.load_key())
        envelope = json.loads(encoded)
        self.assertEqual(envelope['v'], 1)
        self.assertEqual(envelope['alg'], 'A256GCM')
        output = collector.WORK_DIR / collector.OUTPUT_FILENAME
        output.write_text(encoded)
        self.assertEqual(json.loads(collector.decrypt_file(output)), data)


if __name__ == '__main__':
    unittest.main()
