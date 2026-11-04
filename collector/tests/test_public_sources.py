import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import urlencode

os.environ['PYTHON_DOTENV_DISABLED'] = '1'
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main as collector
import public_sources as sources


def proxy(index, **changes):
    return {'host': f'proxy-{index}.example', 'port': 443, 'secret': 'dd' + 'a' * 32, 'country': 'ZZ', **changes}


def link(index=1, scheme='tg', **changes):
    values = {'server': f'proxy-{index}.example', 'port': '443', 'secret': 'dd' + 'a' * 32, **changes}
    prefix = 'tg://proxy?' if scheme == 'tg' else 'https://t.me/proxy?'
    return prefix + urlencode(values)


class SourceParsingTests(unittest.TestCase):
    def test_accepts_both_mtproto_link_formats(self):
        self.assertEqual(sources.proxy_from_link(link()), sources.proxy_from_link(link(scheme='https')))

    def test_deduplicates_buttons_and_host_case(self):
        html = f'<a href="{link(server="PROXY-1.EXAMPLE.")}">one</a><a href="{link(scheme="https")}">two</a>'
        self.assertEqual(sources.extract_site_proxies(html), [proxy(1)])

    def test_html_entities_and_encoded_secret(self):
        secret = base64.b64encode(b'\xff' * 16).decode()
        html = '<a href="' + link(secret=secret).replace('&', '&amp;') + '">connect</a>'
        self.assertEqual(sources.extract_site_proxies(html)[0]['secret'], secret)

    def test_rejects_socks5(self):
        self.assertEqual(sources.extract_site_proxies('<a href="tg://socks?server=proxy.example&port=1080">socks</a>'), [])

    def test_rejects_duplicate_parameters(self):
        with self.assertRaises(ValueError):
            sources.proxy_from_link(link() + '&server=other.example')

    def test_rejects_unrelated_https_host(self):
        with self.assertRaises(ValueError):
            sources.proxy_from_link(link(scheme='https').replace('t.me', 'unrelated.example'))

    def test_private_addresses_are_skipped(self):
        for address in ('127.0.0.1', '10.0.0.1', '192.168.1.1', '169.254.169.254', '999.1.1.1'):
            with self.subTest(address=address), self.assertRaises(ValueError):
                sources.proxy_from_link(link(server=address))

    def test_port_range_validated(self):
        for value in ('0', '-1', '65536', 'true', ''):
            with self.subTest(value=value), self.assertRaises(ValueError):
                sources.proxy_from_link(link(port=value))

    def test_plain_host_without_domain_is_rejected(self):
        with self.assertRaises(ValueError):
            sources.proxy_from_link(link(server='localhost'))

    def test_standard_proxy_cannot_contain_host_path(self):
        with self.assertRaises(ValueError):
            sources.proxy_from_link(link(server='proxy.example/path'))

    def test_invalid_secret_rejected(self):
        for value in ('', 'short', '!' * 32, 'a' * 21):
            with self.subTest(value=value), self.assertRaises(ValueError):
                sources.proxy_from_link(link(secret=value))

    def test_country_from_row_attribute(self):
        html = f'<tr data-country="de"><td><a href="{link()}">connect</a></td></tr>'
        self.assertEqual(sources.extract_site_proxies(html)[0]['country'], 'DE')

    def test_country_flag_and_duplicate_links_in_same_row(self):
        html = f'<tr><td>🇳🇱</td><td><a href="{link()}">connect</a><a href="{link(scheme="https")}">t.me</a></td></tr>'
        self.assertEqual(sources.extract_site_proxies(html)[0]['country'], 'NL')

    def test_country_from_flag_image(self):
        for image in ('https://flagcdn.com/w40/de.png', '/flags/de.svg'):
            html = f'<tr><td><img src="{image}"></td><td><a href="{link()}">connect</a></td></tr>'
            self.assertEqual(sources.extract_site_proxies(html)[0]['country'], 'DE')

    def test_country_does_not_leak_between_rows(self):
        html = f'<table><tr><td>🇩🇪</td><td><a href="{link(1)}">one</a></td></tr><tr><td><a href="{link(2)}">two</a></td></tr></table>'
        data = sources.extract_site_proxies(html)
        self.assertEqual({p['host']: p['country'] for p in data}, {'proxy-1.example':'DE','proxy-2.example':'ZZ'})

    def test_region_is_not_assigned_as_country(self):
        html = f'<div>Европа<a href="{link()}">connect</a></div>'
        self.assertEqual(sources.extract_site_proxies(html)[0]['country'], 'ZZ')

    def test_full_embedded_allmt_array(self):
        data = [{'server':p['host'],'port':str(p['port']),'secret':p['secret'],'link':link(i)} for i in range(50) for p in [proxy(i)]]
        html = '<a href="' + link() + '">first visible row</a><script>var allMT=' + json.dumps(data) + '; function showMore(){return allMT;}</script>'
        self.assertEqual(len(sources.extract_site_proxies(html)), 50)

    def test_json_ld_links(self):
        html = '<script type="application/ld+json">' + json.dumps({'itemListElement':[{'url':link()}]}) + '</script>'
        self.assertEqual(sources.extract_site_proxies(html), [proxy(1)])

    def test_javascript_is_never_executed(self):
        html = '<script>var allMT=someFunction(); throw new Error("must not execute");</script>'
        self.assertEqual(sources.extract_site_proxies(html), [])

    def test_bad_script_does_not_hide_valid_html(self):
        html = '<script>var allMT=[broken];</script><a href="' + link() + '">connect</a>'
        self.assertEqual(sources.extract_site_proxies(html), [proxy(1)])

    def test_base64_mtproto_secret_preserved(self):
        for value in ('7HQighJPBNMYVRNB6tdkVw', 'eeRigzNJvXrFGRMCIMJdEA', 'EERighJJvXrFGRMCIMjdCQ'):
            self.assertEqual(sources.proxy_from_link(link(secret=value))['secret'], value)

    def test_base64_padded_secret_is_canonicalized(self):
        secret = base64.urlsafe_b64encode(bytes.fromhex('dd'+'a'*32)).decode().rstrip('=')
        self.assertEqual(sources.proxy_from_link(link(secret=secret))['secret'],'dd'+'a'*32)

    def test_fake_tls_secret_requires_domain(self):
        self.assertFalse(sources.supported_proxy(proxy(1,secret='ee'+'a'*32)))
        self.assertTrue(sources.supported_proxy(proxy(1,secret='ee'+'a'*32+'example.com'.encode().hex())))

    def test_webproxy_format_preserved(self):
        value = 'https://t.me/webproxy?' + urlencode({'server':'proxy.example/path','secret':base64.urlsafe_b64encode(b'\x70'+b'a'*16).decode().rstrip('=')})
        record = sources.proxy_from_link(value)
        self.assertEqual(record['port'], '')
        self.assertEqual(record['type'], 'webproxy')
        self.assertEqual(record['secret'], (b'a'*16).hex())

    def test_json_api_extracts_open_records_only(self):
        data = [{'server':'proxy-1.example','port':443,'secret':'dd'+'a'*32},{'server':'proxy-2.example','port':443,'secret':None},{'server':'proxy-3.example','port':443,'secret':'dd'+'a'*32,'is_premium':True}]
        self.assertEqual(sources.extract_site_proxies(json.dumps(data),'json'), [proxy(1)])

    def test_empty_api_is_empty_source(self):
        self.assertEqual(sources.extract_site_proxies('[]','json'), [])

    def test_source_payload_limit(self):
        with self.assertRaises(ValueError):
            sources.extract_site_proxies('x' * (sources.MAX_SOURCE_BYTES+1))

    def test_record_limit(self):
        data = [{'link':link(i)} for i in range(sources.MAX_SOURCE_RECORDS+10)]
        self.assertEqual(len(sources.extract_site_proxies(json.dumps(data),'json')), sources.MAX_SOURCE_RECORDS)


class AssemblyTests(unittest.TestCase):
    def state(self):
        return {'v':1,'first_seen':{}}

    def test_collects_100_unique_records(self):
        batches = {f'source-{s}':[proxy(s*100+i) for i in range(50)] for s in range(4)}
        data, _ = sources.assemble_proxies(batches, [], self.state(), now=1000)
        self.assertEqual(len(data), 100)
        self.assertEqual(len({sources.proxy_key(p) for p in data}), 100)

    def test_source_diversity(self):
        batches = {'large':[proxy(i) for i in range(200)], 'small':[proxy(1000+i) for i in range(10)]}
        data, _ = sources.assemble_proxies(batches, [], self.state(), now=1000)
        self.assertEqual(sum(p['host'].startswith('proxy-10') and int(p['host'].split('-')[1].split('.')[0])>=1000 for p in data), 10)

    def test_cross_source_duplicates_removed(self):
        data, _ = sources.assemble_proxies({'a':[proxy(1)],'b':[proxy(1)]}, [], self.state(), now=1000)
        self.assertEqual(len(data), 1)

    def test_worker_completion_order_does_not_change_result(self):
        batches = {'newer':[proxy(1,addTime=900,country='ZZ')],'older':[proxy(1,addTime=800,country='DE')]}
        forward,_ = sources.assemble_proxies(batches,[],self.state(),now=1000)
        reverse,_ = sources.assemble_proxies(dict(reversed(list(batches.items()))),[],self.state(),now=1000)
        self.assertEqual(forward,reverse)
        self.assertEqual(forward[0]['addTime'],900)
        self.assertEqual(forward[0]['country'],'DE')

    def test_repeated_collection_keeps_original_discovery_time(self):
        batches = {'source':[proxy(i) for i in range(120)]}
        first, state = sources.assemble_proxies(batches, [], self.state(), now=1000)
        second, state2 = sources.assemble_proxies(batches, first, state, now=2000)
        self.assertEqual(first, second)
        self.assertEqual(state, state2)

    def test_previous_file_is_used_to_backfill(self):
        current = [proxy(i, addTime=100) for i in range(50)]
        data, _ = sources.assemble_proxies({'new':[proxy(1000+i) for i in range(20)]}, current, self.state(), now=1000)
        self.assertEqual(len(data), 70)
        self.assertEqual(sum(p['addTime']==100 for p in data), 50)

    def test_preserves_country_when_source_has_no_country(self):
        current = [proxy(1, addTime=100, country='DE')]
        data, _ = sources.assemble_proxies({'a':[proxy(1)]}, current, self.state(), now=1000)
        self.assertEqual(data[0]['country'], 'DE')
        self.assertEqual(data[0]['addTime'], 100)

    def test_rotation_replaces_old_cached_secret(self):
        current = [proxy(1, addTime=100), proxy(2, addTime=100)]
        data, _ = sources.assemble_proxies({'a':[proxy(1, secret='dd'+'b'*32)]}, current, self.state(), now=1000)
        self.assertEqual(len(data), 2)
        self.assertNotIn('dd'+'a'*32, [p['secret'] for p in data if p['host']=='proxy-1.example'])

    def test_older_source_cannot_restore_old_secret(self):
        current = [proxy(1, secret='dd'+'b'*32, addTime=200)]
        data, _ = sources.assemble_proxies({'a':[proxy(1, addTime=100),proxy(2)]}, current, self.state(), now=1000)
        self.assertIn('dd'+'b'*32, [p['secret'] for p in data])
        self.assertEqual(len(data), 2)

    def test_newer_cached_metadata_survives(self):
        current = [proxy(1, country='FR', addTime=200)]
        data, _ = sources.assemble_proxies({'a':[proxy(1, country='DE', addTime=100)]}, current, self.state(), now=1000)
        self.assertEqual(data[0]['country'], 'FR')

    def test_failed_sources_do_not_discard_successful_sources(self):
        def fail():
            raise sources.requests.Timeout()
        batches, statuses = sources.collect_source_batches([('failed', fail),('valid',lambda:[proxy(1)])])
        self.assertEqual(batches, {'valid':[proxy(1)]})
        self.assertEqual(statuses['failed']['status'], 'Timeout')

    def test_unexpected_adapter_error_is_isolated(self):
        def fail():
            raise TypeError('malformed source')
        batches, statuses = sources.collect_source_batches([('failed', fail),('valid',lambda:[proxy(1)])])
        self.assertIn('valid', batches)
        self.assertEqual(statuses['failed']['status'], 'TypeError')

    def test_empty_sources_do_not_republish_cache_as_new_data(self):
        with self.assertRaises(ValueError):
            sources.assemble_proxies({}, [proxy(1, addTime=100)], self.state(), now=1000)

    def test_input_state_not_mutated(self):
        original = self.state()
        sources.assemble_proxies({'a':[proxy(1)]}, [], original, now=1000)
        self.assertEqual(original, self.state())

    def test_plain_secrets_are_not_selected_for_consumer(self):
        data,_ = sources.assemble_proxies({'a':[proxy(1,secret='a'*32),proxy(2)]},[],self.state(),now=1000)
        self.assertEqual([p['host'] for p in data],['proxy-2.example'])

    def test_invalid_fake_tls_domain_is_not_selected(self):
        data,_ = sources.assemble_proxies({'a':[proxy(1,secret='ee'+'a'*32+'bad domain'.encode().hex()),proxy(2)]},[],self.state(),now=1000)
        self.assertEqual([p['host'] for p in data],['proxy-2.example'])

    def test_future_date_is_not_trusted(self):
        data, _ = sources.assemble_proxies({'a':[proxy(1, addTime=10000)]}, [], self.state(), now=1000)
        self.assertEqual(data[0]['addTime'], 1000)


class SourceRuntimeTests(unittest.TestCase):
    def setUp(self):
        country_patch = patch.object(collector, 'enrich_countries', side_effect=lambda records,*args: (records,{}))
        country_patch.start()
        self.addCleanup(country_patch.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def test_state_is_persisted_atomically(self):
        path = self.directory/'state.json'
        state = {'v':1,'first_seen':{'key':100}}
        sources.write_source_state(path, state)
        self.assertEqual(sources.load_source_state(path), state)
        self.assertFalse(path.with_name('state.json.next').exists())

    def test_invalid_state_is_not_silently_discarded(self):
        path = self.directory/'state.json'
        path.write_text('{"v":99}')
        with self.assertRaises(ValueError):
            sources.load_source_state(path)

    def test_request_timeout_and_response_size_are_bounded(self):
        response = Mock()
        response.iter_content.return_value = [b'x'*(sources.MAX_SOURCE_BYTES+1)]
        with patch.object(sources.requests.Session, 'get', return_value=response) as request:
            with sources.BoundedSourceSession() as session, self.assertRaises(ValueError):
                session.get('https://source.example/')
        self.assertEqual(request.call_args.kwargs['stream'], True)
        self.assertLessEqual(request.call_args.kwargs['timeout'][0], 5)
        response.close.assert_called_once()

    def test_main_pipeline_emits_100_with_compatible_encryption(self):
        key = b'k'*32
        batches = {'a':[proxy(i) for i in range(150)]}
        with patch.object(collector,'WORK_DIR',self.directory), patch.object(collector,'SOURCE_STATE_FILE',self.directory/'state.json'), patch.object(collector,'collect_source_batches',return_value=(batches,{'a':{'count':150,'status':'ok'}})), patch.object(collector,'ENC_KEY_B64',base64.b64encode(key).decode()):
            data = collector.fetch_proxies()
            self.assertEqual(len(data), 100)
            encrypted = collector.encrypt_payload(data, key)
            output = self.directory/collector.OUTPUT_FILENAME
            output.write_text(encrypted)
            self.assertEqual(len(json.loads(collector.decrypt_file(output))),100)
            repeated = collector.fetch_proxies()
            self.assertEqual(collector.encrypt_payload(repeated,key),encrypted)

    def test_failed_collection_preserves_published_file(self):
        output = self.directory/collector.OUTPUT_FILENAME
        key = b'k'*32
        output.write_text(collector.encrypt_payload([proxy(1,addTime=100)],key))
        before = output.read_bytes()
        with patch.object(collector,'WORK_DIR',self.directory), patch.object(collector,'SOURCE_STATE_FILE',self.directory/'state.json'), patch.object(collector,'collect_source_batches',return_value=({},{})), patch.object(collector,'ENC_KEY_B64',base64.b64encode(key).decode()), self.assertRaises(ValueError):
            collector.fetch_proxies()
        self.assertEqual(output.read_bytes(),before)

    def test_pending_push_is_retried_when_content_did_not_change(self):
        completed = Mock(returncode=0, stdout='', stderr='')
        with patch.object(collector,'WORK_DIR',self.directory), patch.object(collector,'git',return_value=completed) as git, patch.object(collector,'load_key',return_value=b'k'*32):
            collector.write_and_commit([proxy(1,addTime=100)])
        self.assertTrue(any(call.args[0][0]=='push' for call in git.call_args_list))
        self.assertFalse(any(call.args[0][0]=='commit' for call in git.call_args_list))

    def test_push_failure_is_reported(self):
        completed = Mock(returncode=0,stdout='',stderr='')
        failure = Mock(returncode=1,stdout='',stderr='network failed')
        def git(args):
            return failure if args[0]=='push' else completed
        with patch.object(collector,'WORK_DIR',self.directory), patch.object(collector,'git',side_effect=git), patch.object(collector,'load_key',return_value=b'k'*32), self.assertRaisesRegex(RuntimeError,'git push failed'):
            collector.write_and_commit([proxy(1,addTime=100)])


if __name__ == '__main__':
    unittest.main()
