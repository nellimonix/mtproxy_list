import base64
import json
import unittest
from pathlib import Path
from unittest.mock import Mock

import importlib.util
import os
from pathlib import Path
os.environ["PYTHON_DOTENV_DISABLED"] = "1"
spec = importlib.util.spec_from_file_location("legacy_js_collector", Path(__file__).resolve().parents[1] / "main.py")
parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parser)


class TextDecoderTests(unittest.TestCase):
    proxy = {'host': 'proxy.example', 'port': 443, 'secret': 'test-secret', 'country': 'DE', 'addTime': 123}

    def wrapper(self, data, quote="'", spaced=False):
        code = 'const title = "Список прокси"; function getProxies() { return ' + json.dumps(data) + '; }'
        value = base64.b64encode(code.encode('utf-8')).decode()
        call = f'atob ({quote}{value}{quote})' if spaced else f'atob({quote}{value}{quote})'
        return f'eval(new TextDecoder().decode(Uint8Array.from({call}, c => c.charCodeAt(0))));'

    def test_textdecoder_utf8_wrapper(self):
        self.assertEqual(parser.extract_proxies_from_js(self.wrapper([self.proxy])), [self.proxy])

    def test_double_quotes_and_whitespace(self):
        self.assertEqual(parser.extract_proxies_from_js(self.wrapper([self.proxy], quote='"', spaced=True)), [self.proxy])

    def test_invalid_candidate_before_valid_wrapper(self):
        code = 'atob("/w==");' + self.wrapper([self.proxy])
        self.assertEqual(parser.extract_proxies_from_js(code), [self.proxy])

    def test_mismatched_quotes_rejected(self):
        code = self.wrapper([self.proxy]).replace("'),", '\"),')
        with self.assertRaises(RuntimeError):
            parser.extract_proxies_from_js(code)

    def test_site_fetch_uses_current_wrapper(self):
        session = Mock()
        html = '<script src="/list.js"></script>'
        session.get.side_effect = [parser.source_response(parser.PAGE_URL, html.encode()), parser.source_response(parser.BASE_URL + '/list.js', self.wrapper([self.proxy]).encode())]
        self.assertEqual(parser.fetch_proxies_from_site(session, allow_socks=False), [self.proxy])

    def test_full_list_encryption_roundtrip(self):
        source = self.wrapper([{**self.proxy, 'host': f'proxy-{i}.example'} for i in range(50)])
        data = parser.normalize_proxies(parser.extract_proxies_from_js(source), 'Snapshot')
        self.assertEqual(len(data), 50)
        self.assertTrue(all(p.get('addTime', 0) > 0 for p in data))
        key = b'k' * 32
        encrypted = json.loads(parser.encrypt_payload(data, key))
        plaintext = parser.AESGCM(key).decrypt(base64.b64decode(encrypted['iv']), base64.b64decode(encrypted['ct']), None)
        self.assertEqual(json.loads(plaintext), data)

if __name__ == '__main__':
    unittest.main(verbosity=2)