import base64
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

os.environ['PYTHON_DOTENV_DISABLED'] = '1'
spec = importlib.util.spec_from_file_location('telegram_candidate', Path(__file__).resolve().parents[1] / 'main.py')
parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parser)


def proxy(index, timestamp=100, secret='old', **values):
    return {'host': f'proxy-{index}.example', 'port': 443, 'secret': secret, 'country': 'DE', 'addTime': timestamp, **values}


def telegram_post(index):
    return (f'<div class="tgme_widget_message" data-post="mtpro_xyz/{index}">'
            '<code>DE</code>'
            f'<a href="https://t.me/proxy?server=proxy-{index}.example&amp;port=443&amp;secret=test">proxy</a>'
            '<time datetime="2026-10-14T12:00:00+00:00"></time></div>')


class TelegramMergeTests(unittest.TestCase):
    def setUp(self):
        feed_patch = patch.object(parser, "fetch_proxies_from_json_feed", side_effect=RuntimeError("unavailable"))
        feed_patch.start()
        self.addCleanup(feed_patch.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.key = b'k' * 32
        for name, value in [('WORK_DIR', Path(self.temp.name)), ('ENC_KEY_B64', base64.b64encode(self.key).decode())]:
            active = patch.object(parser, name, value)
            active.start()
            self.addCleanup(active.stop)
        self.file = parser.WORK_DIR / parser.OUTPUT_FILENAME

    def save(self, data):
        self.file.write_text(parser.encrypt_payload(data, self.key))

    def test_partial_collection_refreshes_cache(self):
        self.save([proxy(i, timestamp=100+i) for i in range(50)])
        data = [proxy(i, timestamp=1000+i, secret='new') for i in range(27)]
        result = parser.merge_telegram_proxies(data)
        self.assertEqual(len(result), 50)
        self.assertEqual(sum(p['secret'] == 'new' for p in result), 27)
        self.assertEqual(sum(p['secret'] == 'old' for p in result), 23)

    def test_rotated_secret_replaces_old_endpoint(self):
        self.save([proxy(1), proxy(2)])
        result = parser.merge_telegram_proxies([proxy(1, timestamp=200, secret='new')])
        self.assertEqual(result, [proxy(1, timestamp=200, secret='new'), proxy(2)])

    def test_older_telegram_post_cannot_rollback_current_record(self):
        current = proxy(1, timestamp=300, secret='current', country='FR')
        self.save([current])
        self.assertEqual(parser.merge_telegram_proxies([proxy(1, timestamp=200)]), [current])

    def test_latest_telegram_secret_wins(self):
        self.save([proxy(1)])
        result = parser.merge_telegram_proxies([proxy(1, timestamp=200, secret='intermediate'), proxy(1, timestamp=300, secret='latest')])
        self.assertEqual(result, [proxy(1, timestamp=300, secret='latest')])

    def test_current_multiple_secrets_survive_older_posts(self):
        current = [proxy(1, timestamp=300, secret='first'), proxy(1, timestamp=200, secret='second')]
        self.save(current)
        self.assertEqual(parser.merge_telegram_proxies([proxy(1, timestamp=150)]), current)

    def test_new_proxies_evict_oldest_at_limit(self):
        self.save([proxy(i, timestamp=i+1) for i in range(50)])
        result = parser.merge_telegram_proxies([proxy(50, timestamp=100), proxy(51, timestamp=101)])
        self.assertEqual(len(result), 50)
        self.assertEqual({p['host'] for p in result}, {proxy(i)['host'] for i in range(2, 52)})
        self.assertEqual(result[0]['addTime'], 101)

    def test_optional_metadata_retained_for_same_proxy(self):
        self.save([proxy(1, bot='@test', channel='@channel')])
        result = parser.merge_telegram_proxies([proxy(1, timestamp=200)])
        self.assertEqual(result, [proxy(1, timestamp=200, bot='@test', channel='@channel')])

    def test_port_string_matches_cached_endpoint(self):
        self.save([proxy(1)])
        result = parser.merge_telegram_proxies([proxy(1, port='443', timestamp=200, secret='new')])
        self.assertEqual(result, [proxy(1, timestamp=200, secret='new')])

    def test_missing_cache_accepts_one_proxy(self):
        self.assertEqual(parser.merge_telegram_proxies([proxy(1)]), [proxy(1)])

    def test_empty_cache_accepts_one_proxy(self):
        self.save([])
        self.assertEqual(parser.merge_telegram_proxies([proxy(1)]), [proxy(1)])

    def test_small_cache_remains_below_target(self):
        self.save([proxy(1)])
        self.assertEqual(len(parser.merge_telegram_proxies([proxy(2)])), 2)

    def test_repeated_merge_is_stable(self):
        self.save([proxy(1), proxy(2)])
        data = [proxy(1, timestamp=200, secret='new')]
        first = parser.merge_telegram_proxies(data)
        self.save(first)
        second = parser.merge_telegram_proxies(data)
        self.assertEqual(first, second)
        self.assertEqual(parser.encrypt_payload(first, self.key), parser.encrypt_payload(second, self.key))

    def test_empty_telegram_does_not_overwrite_cache(self):
        self.save([proxy(1)])
        before = self.file.read_bytes()
        with self.assertRaises(ValueError):
            parser.merge_telegram_proxies([])
        self.assertEqual(self.file.read_bytes(), before)

    def test_corrupt_cache_is_not_discarded(self):
        self.file.write_text('invalid-envelope')
        with self.assertRaises(ValueError):
            parser.merge_telegram_proxies([proxy(1)])
        self.assertEqual(self.file.read_text(), 'invalid-envelope')

    def test_partial_pages_are_accepted(self):
        session = Mock()
        session.get.side_effect = [parser.source_response(parser.TELEGRAM_CHANNEL_URL, telegram_post(3).encode()), parser.requests.ConnectTimeout()]
        self.assertEqual(len(parser.fetch_proxies_from_telegram(session)), 1)

    def test_first_page_error_propagates(self):
        session = Mock()
        session.get.side_effect = parser.requests.ConnectTimeout()
        with self.assertRaises(parser.requests.ConnectTimeout):
            parser.fetch_proxies_from_telegram(session)

    def test_empty_channel_rejected(self):
        session = Mock()
        session.get.return_value = parser.source_response(parser.TELEGRAM_CHANNEL_URL, b'<html></html>')
        with self.assertRaises(ValueError):
            parser.fetch_proxies_from_telegram(session)

    def test_backward_pagination_stops_on_repeat(self):
        session = Mock()
        session.get.return_value = parser.source_response(parser.TELEGRAM_CHANNEL_URL, telegram_post(3).encode())
        self.assertEqual(len(parser.fetch_proxies_from_telegram(session)), 1)
        self.assertEqual(session.get.call_count, 2)

    def test_blocked_site_uses_partial_telegram_and_existing_list(self):
        self.save([proxy(1), proxy(2)])
        with patch.object(parser, 'fetch_proxies_from_site', side_effect=RuntimeError('HTTP 403')) as site, patch.object(parser, 'fetch_proxies_from_telegram', return_value=[proxy(1, timestamp=200, secret='new')]):
            result = parser.fetch_proxies()
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['secret'], 'new')
        site.assert_called_once()

    def test_successful_site_replaces_without_cache_merge(self):
        self.save([proxy(1)])
        data = [proxy(2)]
        with patch.object(parser, 'fetch_proxies_from_site', return_value=data), patch.object(parser, 'merge_telegram_proxies') as merge:
            self.assertEqual(parser.fetch_proxies(), data)
        merge.assert_not_called()


class TelegramWebProxyTests(unittest.TestCase):
    setUp = TelegramMergeTests.setUp
    save = TelegramMergeTests.save
    def web_proxy(self, index=1, timestamp=200, secret='a' * 32):
        return proxy(index, timestamp=timestamp, port='', type='webproxy', secret=secret)

    def web_post(self, url):
        return ('<div class="tgme_widget_message" data-post="mtpro_xyz/1">'
                '<code>DE</code>'
                f'<a href="{url}">proxy</a>'
                '<time datetime="2026-10-14T07:30:55+00:00"></time></div>')

    def test_extracts_webproxy_without_port(self):
        data, ids = parser.extract_proxies_from_telegram(self.web_post('https://t.me/webproxy?server=proxy-1.example&amp;secret=' + 'a' * 32))
        self.assertEqual(ids, [1])
        self.assertEqual(data[0]['port'], '')
        self.assertEqual(data[0]['type'], 'webproxy')
        self.assertEqual(data[0]['secret'], 'a' * 32)

    def test_extracts_tg_webproxy(self):
        data, _ = parser.extract_proxies_from_telegram(self.web_post('tg://webproxy?server=proxy-1.example&amp;secret=' + 'a' * 32))
        self.assertEqual(data[0]['type'], 'webproxy')

    def test_mixed_types_normalize_and_sort(self):
        regular = proxy(1, timestamp=200)
        web = self.web_proxy()
        self.assertEqual(parser.normalize_proxies([regular, web], 'mixed'), [web, regular])

    def test_webproxy_secret_base64_canonicalized(self):
        secret = base64.urlsafe_b64encode(b'\x70' + bytes.fromhex('a' * 32)).decode().rstrip('=')
        result = parser.normalize_proxies([self.web_proxy(secret=secret)], 'web')
        self.assertEqual(result[0]['secret'], 'a' * 32)

    def test_webproxy_secret_case_canonicalized(self):
        result = parser.normalize_proxies([self.web_proxy(secret='A' * 32)], 'web')
        self.assertEqual(result[0]['secret'], 'a' * 32)

    def test_empty_port_requires_webproxy_marker(self):
        with self.assertRaises(ValueError):
            parser.normalize_proxies([proxy(1, port='')], 'invalid')

    def test_webproxy_with_numeric_port_rejected(self):
        with self.assertRaises(ValueError):
            parser.normalize_proxies([proxy(1, port=443, type='webproxy', secret='a' * 32)], 'invalid')

    def test_invalid_webproxy_secret_rejected(self):
        with self.assertRaises(ValueError):
            parser.normalize_proxies([self.web_proxy(secret='invalid')], 'invalid')

    def test_bad_post_does_not_discard_valid_post(self):
        html = self.web_post('https://t.me/webproxy?server=proxy-1.example&amp;secret=invalid') + telegram_post(2)
        data, _ = parser.extract_proxies_from_telegram(html)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['host'], 'proxy-2.example')

    def test_partial_webproxy_collection_merges_with_cache(self):
        self.save([proxy(i, timestamp=100+i) for i in range(50)])
        result = parser.merge_telegram_proxies([self.web_proxy(timestamp=1000)])
        self.assertEqual(len(result), 50)
        self.assertEqual(sum(p.get('type') == 'webproxy' for p in result), 1)
        self.assertEqual(result[0]['port'], '')

    def test_webproxy_pagination_accepts_missing_port(self):
        session = Mock()
        session.get.return_value = parser.source_response(parser.TELEGRAM_CHANNEL_URL, self.web_post('https://t.me/webproxy?server=proxy-1.example&amp;secret=' + 'a' * 32).encode())
        data = parser.fetch_proxies_from_telegram(session)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['type'], 'webproxy')


if __name__ == '__main__':
    unittest.main(verbosity=2)
