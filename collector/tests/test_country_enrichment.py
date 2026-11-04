import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

os.environ['PYTHON_DOTENV_DISABLED']='1'
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import country_enrichment as geo
import main as collector


def proxy(index=1, **changes):
    return {'host':f'proxy-{index}.example','port':443,'secret':'dd'+'a'*32,'country':'ZZ','addTime':100,**changes}


class Answer(list):
    def __init__(self, addresses, ttl=300):
        super().__init__(SimpleNamespace(address=value) for value in addresses)
        self.rrset=SimpleNamespace(ttl=ttl)


class DnsCountryTests(unittest.TestCase):
    def test_ipv4_literal_bypasses_dns(self):
        with patch.object(geo.dns.resolver,'Resolver') as resolver:
            self.assertEqual(geo.resolve_public_ips('8.8.8.8')[0],['8.8.8.8'])
        resolver.assert_not_called()

    def test_ipv6_literal_bypasses_dns(self):
        with patch.object(geo.dns.resolver,'Resolver') as resolver:
            self.assertEqual(geo.resolve_public_ips('2001:4860:4860::8888')[0],['2001:4860:4860::8888'])
        resolver.assert_not_called()

    def test_private_ip_not_geolocated(self):
        self.assertEqual(geo.resolve_public_ips('127.0.0.1')[0],[])

    def test_dns_a_record_and_ttl(self):
        resolver=Mock()
        resolver.resolve.return_value=Answer(['8.8.8.8'],ttl=30)
        with patch.object(geo.dns.resolver,'Resolver',return_value=resolver):
            addresses,ttl=geo.resolve_public_ips('proxy.example')
        self.assertEqual(addresses,['8.8.8.8'])
        self.assertEqual(ttl,30)
        self.assertEqual(resolver.resolve.call_args.args[1],'A')
        self.assertLessEqual(resolver.resolve.call_args.kwargs['lifetime'],geo.DNS_TIMEOUT_SECONDS)
        self.assertFalse(resolver.resolve.call_args.kwargs['search'])

    def test_ipv6_fallback_after_missing_a(self):
        resolver=Mock()
        resolver.resolve.side_effect=[geo.dns.resolver.NoAnswer(),Answer(['2001:4860:4860::8888'])]
        with patch.object(geo.dns.resolver,'Resolver',return_value=resolver):
            self.assertEqual(geo.resolve_public_ips('proxy.example')[0],['2001:4860:4860::8888'])
        self.assertEqual(resolver.resolve.call_args.args[1],'AAAA')

    def test_nxdomain_stops_retry(self):
        resolver=Mock()
        resolver.resolve.side_effect=geo.dns.resolver.NXDOMAIN()
        with patch.object(geo.dns.resolver,'Resolver',return_value=resolver):
            self.assertEqual(geo.resolve_public_ips('proxy.example')[0],[])
        self.assertEqual(resolver.resolve.call_count,1)

    def test_filters_private_dns_answers_and_sorts_addresses(self):
        resolver=Mock()
        resolver.resolve.return_value=Answer(['8.8.8.8','127.0.0.1','1.1.1.1','8.8.8.8'])
        with patch.object(geo.dns.resolver,'Resolver',return_value=resolver):
            self.assertEqual(geo.resolve_public_ips('proxy.example')[0],['1.1.1.1','8.8.8.8'])

    def test_dns_ttl_is_capped(self):
        resolver=Mock()
        resolver.resolve.return_value=Answer(['8.8.8.8'],ttl=999999)
        with patch.object(geo.dns.resolver,'Resolver',return_value=resolver):
            self.assertEqual(geo.resolve_public_ips('proxy.example')[1],geo.DNS_CACHE_MAX_SECONDS)

    def test_expired_deadline_does_not_query_dns(self):
        with patch.object(geo.dns.resolver,'Resolver') as resolver:
            self.assertEqual(geo.resolve_public_ips('proxy.example',deadline=0)[0],[])
        resolver.return_value.resolve.assert_not_called()


class CountryApiTests(unittest.TestCase):
    def fetch(self,payload,addresses=None,status=200):
        response=Mock(status_code=status)
        response.iter_content.return_value=[json.dumps(payload).encode()]
        session=Mock()
        session.get.return_value=response
        context=Mock()
        context.__enter__=Mock(return_value=session)
        context.__exit__=Mock(return_value=False)
        with patch.object(geo.requests,'Session',return_value=context):
            result=geo.lookup_country_batch(addresses or ['8.8.8.8','1.1.1.1'])
        response.close.assert_called_once()
        return result,session

    def test_bulk_response_maps_country_by_ip(self):
        result,session=self.fetch([{'ip':'1.1.1.1','country':'DE'},{'ip':'8.8.8.8','country':'US'}])
        self.assertEqual(result,{'1.1.1.1':'DE','8.8.8.8':'US'})
        self.assertEqual(session.get.call_args.kwargs['params']['ip'],'1.1.1.1,8.8.8.8')
        self.assertTrue(session.get.call_args.args[0].startswith('https://'))

    def test_single_object_response_supported(self):
        result,_=self.fetch({'ip':'8.8.8.8','country':'US'})
        self.assertEqual(result,{'8.8.8.8':'US'})

    def test_unknown_country_codes_ignored(self):
        for country in ('ZZ','XX','EU','',None,'Germany','ß'):
            with self.subTest(country=country):
                result,_=self.fetch({'ip':'8.8.8.8','country':country})
                self.assertEqual(result,{})

    def test_unrequested_addresses_ignored(self):
        result,_=self.fetch({'ip':'9.9.9.9','country':'DE'})
        self.assertEqual(result,{})

    def test_conflicting_country_answers_ignored(self):
        result,_=self.fetch([{'ip':'8.8.8.8','country':'US'},{'ip':'8.8.8.8','country':'DE'}])
        self.assertEqual(result,{})

    def test_non_object_rows_ignored(self):
        result,_=self.fetch([None,[],{'ip':'8.8.8.8','country':'us'}])
        self.assertEqual(result,{'8.8.8.8':'US'})

    def test_redirect_not_treated_as_country_response(self):
        with self.assertRaises(ValueError):
            self.fetch({},status=302)

    def test_private_addresses_not_sent_to_provider(self):
        with patch.object(geo.requests,'Session') as session:
            self.assertEqual(geo.lookup_country_batch(['127.0.0.1','192.168.1.1']),{})
        session.assert_not_called()


class CountryEnrichmentTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory=Path(self.temp.name)
        self.path=self.directory/'country-cache.json'

    def enrich(self,records,now=1000,explicit=None,ips=None,countries=None):
        with patch.object(geo,'resolve_public_ips',return_value=(ips or ['8.8.8.8'],300)) as dns, patch.object(geo,'lookup_country_batch',return_value=countries or {'8.8.8.8':'DE'}) as api:
            result,stats=geo.enrich_countries(records,self.path,explicit=explicit,now=now)
        return result,stats,dns,api

    def test_fills_missing_country(self):
        result,stats,_,_=self.enrich([proxy()])
        self.assertEqual(result[0]['country'],'DE')
        self.assertEqual(stats['unknown_before'],1)
        self.assertEqual(stats['unknown_after'],0)

    def test_preserves_existing_source_country(self):
        result,_,dns,api=self.enrich([proxy(country='NL')])
        self.assertEqual(result[0]['country'],'NL')
        dns.assert_not_called()
        api.assert_not_called()

    def test_queries_shared_ip_once(self):
        result,_,dns,api=self.enrich([proxy(i) for i in range(10)])
        self.assertEqual(dns.call_count,10)
        self.assertEqual(api.call_count,1)
        self.assertEqual(api.call_args.args[0],['8.8.8.8'])
        self.assertTrue(all(p['country']=='DE' for p in result))

    def test_resolves_shared_domain_once(self):
        first=proxy()
        second=proxy(secret='dd'+'b'*32)
        _,_,dns,_=self.enrich([first,second])
        self.assertEqual(dns.call_count,1)

    def test_dns_and_geoip_cache_reused(self):
        first,_,_,_=self.enrich([proxy()])
        second,stats,dns,api=self.enrich(first,now=1100)
        self.assertEqual(first,second)
        self.assertEqual(stats['dns_cache_hits'],1)
        dns.assert_not_called()
        api.assert_not_called()

    def test_country_cache_reused_after_dns_expiry(self):
        first,_,_,_=self.enrich([proxy()])
        second,_,dns,api=self.enrich(first,now=1400)
        self.assertEqual(first,second)
        dns.assert_called_once()
        api.assert_not_called()

    def test_dns_ip_change_refreshes_inferred_country(self):
        first,_,_,_=self.enrich([proxy()])
        second,_,_,_=self.enrich(first,now=1400,ips=['1.1.1.1'],countries={'1.1.1.1':'NL'})
        self.assertEqual(second[0]['country'],'NL')

    def test_rotating_dns_reuses_previous_ip_country(self):
        first,_,_,_=self.enrich([proxy()])
        second,_,_,_=self.enrich(first,now=1400,ips=['1.1.1.1'],countries={'1.1.1.1':'NL'})
        third,_,_,api=self.enrich(second,now=1800,ips=['8.8.8.8'])
        self.assertEqual(third[0]['country'],'DE')
        api.assert_not_called()

    def test_source_country_overrides_previous_inference(self):
        self.enrich([proxy()])
        current=proxy(country='NL')
        key=geo.record_identity(current)
        result,_,dns,api=self.enrich([current],explicit={key},now=1400)
        self.assertEqual(result[0]['country'],'NL')
        dns.assert_not_called()
        api.assert_not_called()

    def test_explicit_same_country_removes_inference_marker(self):
        first,_,_,_=self.enrich([proxy()])
        key=geo.record_identity(first[0])
        self.enrich(first,explicit={key},now=1400)
        self.assertNotIn(key,geo.load_country_cache(self.path)['inferred'])

    def test_webproxy_dns_uses_domain_without_path(self):
        value=proxy(host='proxy.example/api/path',port='',type='webproxy',secret='a'*32)
        result,_,dns,_=self.enrich([value])
        self.assertEqual(dns.call_args.args[0],'proxy.example')
        self.assertEqual(result[0]['host'],'proxy.example/api/path')
        self.assertEqual(result[0]['port'],'')

    def test_dns_failure_keeps_records(self):
        with patch.object(geo,'resolve_public_ips',side_effect=geo.dns.exception.Timeout()), patch.object(geo,'lookup_country_batch') as api:
            result,stats=geo.enrich_countries([proxy()],self.path,now=1000)
        self.assertEqual(result,[proxy()])
        self.assertEqual(stats['unknown_after'],1)
        api.assert_not_called()

    def test_geoip_failure_keeps_records(self):
        with patch.object(geo,'resolve_public_ips',return_value=(['8.8.8.8'],300)), patch.object(geo,'lookup_country_batch',side_effect=geo.requests.Timeout()):
            result,_=geo.enrich_countries([proxy()],self.path,now=1000)
        self.assertEqual(result,[proxy()])

    def test_negative_cache_limits_retries(self):
        with patch.object(geo,'resolve_public_ips',return_value=(['8.8.8.8'],300)), patch.object(geo,'lookup_country_batch',side_effect=geo.requests.Timeout()):
            first,_=geo.enrich_countries([proxy()],self.path,now=1000)
        _,_,dns,api=self.enrich(first,now=1100)
        dns.assert_not_called()
        api.assert_not_called()

    def test_expired_negative_cache_is_retried(self):
        with patch.object(geo,'resolve_public_ips',return_value=(['8.8.8.8'],300)), patch.object(geo,'lookup_country_batch',side_effect=geo.requests.Timeout()):
            first,_=geo.enrich_countries([proxy()],self.path,now=1000)
        result,_,_,api=self.enrich(first,now=2000)
        self.assertEqual(result[0]['country'],'DE')
        api.assert_called_once()

    def test_partial_ip_answers_fill_available_countries(self):
        result,_,_,_=self.enrich([proxy()],ips=['1.1.1.1','8.8.8.8'],countries={'8.8.8.8':'DE'})
        self.assertEqual(result[0]['country'],'DE')

    def test_old_inferred_country_survives_temporary_failure(self):
        first,_,_,_=self.enrich([proxy()])
        with patch.object(geo,'resolve_public_ips',side_effect=geo.dns.exception.Timeout()):
            result,_=geo.enrich_countries(first,self.path,now=1400)
        self.assertEqual(result[0]['country'],'DE')

    def test_corrupt_cache_does_not_break_enrichment(self):
        self.path.write_text('broken')
        result,_,_,_=self.enrich([proxy()])
        self.assertEqual(result[0]['country'],'DE')

    def test_malformed_nested_cache_entries_are_ignored(self):
        self.path.write_text(json.dumps({'v':1,'dns':{'proxy-1.example':{'ips':None,'expires':9999}},'ips':{'8.8.8.8':'bad'},'inferred':{geo.record_identity(proxy()):[]}}))
        result,_,_,_=self.enrich([proxy()])
        self.assertEqual(result[0]['country'],'DE')

    def test_input_records_not_mutated(self):
        original=[proxy()]
        self.enrich(original)
        self.assertEqual(original,[proxy()])

    def test_preserves_count_and_identity(self):
        original=[proxy(i) for i in range(100)]
        result,_,_,_=self.enrich(original)
        self.assertEqual(len(result),100)
        self.assertEqual([geo.record_identity(p) for p in original],[geo.record_identity(p) for p in result])

    def test_missing_country_includes_reserved_codes(self):
        result,_,_,_=self.enrich([proxy(i,country=country) for i,country in enumerate(('ZZ','XX','EU',None))])
        self.assertEqual([p['country'] for p in result],['DE']*4)

    def test_cache_write_failure_does_not_block_result(self):
        with patch.object(geo,'save_country_cache',side_effect=PermissionError()):
            result,_,_,_=self.enrich([proxy()])
        self.assertEqual(result[0]['country'],'DE')

    def test_explicit_country_keys_canonicalize_secrets(self):
        encoded=base64.urlsafe_b64encode(bytes.fromhex('dd'+'a'*32)).decode().rstrip('=')
        keys=geo.explicit_country_keys({'a':[proxy(country='NL',secret=encoded),proxy(2)]})
        self.assertEqual(keys,{geo.record_identity(proxy())})

    def test_bad_source_record_does_not_break_country_provenance(self):
        keys=geo.explicit_country_keys({'a':[None,[],proxy(country='NL')]})
        self.assertEqual(keys,{geo.record_identity(proxy())})

    def test_existing_pipeline_country_lookup_integration(self):
        batches={'source':[proxy(i) for i in range(100)]}
        with patch.object(collector,'WORK_DIR',self.directory), patch.object(collector,'SOURCE_STATE_FILE',self.directory/'sources.json'), patch.object(collector,'COUNTRY_CACHE_FILE',self.path), patch.object(collector,'collect_source_batches',return_value=(batches,{})), patch.object(geo,'resolve_public_ips',return_value=(['8.8.8.8'],300)), patch.object(geo,'lookup_country_batch',return_value={'8.8.8.8':'DE'}):
            result=collector.fetch_proxies()
        self.assertEqual(len(result),100)
        self.assertTrue(all(p['country']=='DE' for p in result))


if __name__=='__main__':
    unittest.main()
