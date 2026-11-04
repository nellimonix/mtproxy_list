import concurrent.futures
import ipaddress
import json
import os
import re
import time
from pathlib import Path

import dns.exception
import dns.resolver
import requests

from public_sources import canonical_host, canonical_secret, proxy_key

COUNTRY_API_URL = "https://get.geojs.io/v1/ip/country.json"
DNS_TIMEOUT_SECONDS = 4
DNS_CACHE_MAX_SECONDS = 6 * 60 * 60
IP_CACHE_SECONDS = 7 * 24 * 60 * 60
FAILURE_CACHE_SECONDS = 15 * 60
ENRICHMENT_TIMEOUT_SECONDS = 25
GEOIP_BATCH_SIZE = 50
UNKNOWN_COUNTRIES = {"ZZ", "XX", "EU", "AP"}


def known_country(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z]{2}", value)) and value.upper() not in UNKNOWN_COUNTRIES


def public_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return str(address) if address.is_global else None


def record_identity(proxy):
    return json.dumps(proxy_key(proxy), separators=(",", ":"))


def explicit_country_keys(batches):
    keys = set()
    for records in batches.values():
        for item in records:
            if not isinstance(item, dict) or not known_country(item.get("country")):
                continue
            try:
                proxy = dict(item)
                proxy["secret"] = canonical_secret(proxy["secret"], proxy.get("type") == "webproxy")
                keys.add(record_identity(proxy))
            except (KeyError, TypeError, ValueError):
                continue
    return keys


def resolve_public_ips(host, deadline=None):
    direct = public_ip(host)
    if direct:
        return [direct], DNS_CACHE_MAX_SECONDS
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return [], FAILURE_CACHE_SECONDS
    deadline = min(deadline if deadline is not None else float("inf"), time.monotonic() + DNS_TIMEOUT_SECONDS)
    resolver = dns.resolver.Resolver()
    for record_type in ("A", "AAAA"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            answer = resolver.resolve(host, record_type, lifetime=remaining, search=False)
            addresses = {address for record in answer if (address := public_ip(record.address))}
            if addresses:
                addresses = sorted(addresses, key=lambda value: int(ipaddress.ip_address(value)))[:8]
                return addresses, max(1, min(int(answer.rrset.ttl), DNS_CACHE_MAX_SECONDS))
        except dns.resolver.NXDOMAIN:
            break
        except dns.exception.DNSException:
            continue
    return [], FAILURE_CACHE_SECONDS


def lookup_country_batch(addresses, deadline=None):
    requested = {address for value in addresses if (address := public_ip(value))}
    if not requested:
        return {}
    remaining = 8 if deadline is None else min(8, deadline - time.monotonic())
    if remaining <= 0:
        raise requests.Timeout("Country lookup deadline exceeded")
    with requests.Session() as session:
        response = session.get(COUNTRY_API_URL, params={"ip": ",".join(sorted(requested))}, timeout=(min(3, remaining), min(5, remaining)), stream=True, allow_redirects=False)
        try:
            response.raise_for_status()
            if response.status_code != 200:
                raise ValueError("Unexpected country API status")
            chunks = []
            size = 0
            for chunk in response.iter_content(16384):
                size += len(chunk)
                if size > 128 * 1024:
                    raise ValueError("Country API response exceeds size limit")
                if deadline is not None and time.monotonic() >= deadline:
                    raise requests.Timeout("Country lookup deadline exceeded")
                chunks.append(chunk)
            payload = json.loads(b"".join(chunks))
        finally:
            response.close()
    rows = payload if isinstance(payload, list) else [payload]
    answers = {}
    for item in rows:
        if not isinstance(item, dict) or not isinstance(item.get("ip"), str):
            continue
        address = public_ip(item["ip"])
        country = item.get("country")
        if address not in requested or not known_country(country):
            continue
        answers.setdefault(address, set()).add(country.upper())
    return {address: next(iter(countries)) for address, countries in answers.items() if len(countries) == 1}


def load_country_cache(path):
    empty = {"v": 1, "dns": {}, "ips": {}, "inferred": {}}
    path = Path(path)
    if not path.exists():
        return empty
    try:
        if path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("Country cache exceeds size limit")
        cache = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(cache, dict) or cache.get("v") != 1 or any(not isinstance(cache.get(name), dict) for name in ("dns", "ips", "inferred")):
            raise ValueError("Invalid country cache format")
        cache["dns"] = {host: entry for host, entry in cache["dns"].items() if isinstance(entry, dict) and isinstance(entry.get("ips"), list) and all(isinstance(value, str) and public_ip(value) for value in entry["ips"])}
        cache["ips"] = {address: entry for address, entry in cache["ips"].items() if isinstance(entry, dict) and public_ip(address)}
        cache["inferred"] = {identity: entry for identity, entry in cache["inferred"].items() if isinstance(entry, dict)}
        return cache
    except (OSError, ValueError) as error:
        print(f"[!] Country cache unavailable: {type(error).__name__}")
        return empty


def save_country_cache(path, cache):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".next")
    with temporary.open("w", encoding="utf-8") as output:
        json.dump(cache, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
    temporary.chmod(0o600)
    os.replace(temporary, path)


def fresh_entry(value, now):
    return isinstance(value, dict) and type(value.get("expires")) in (int, float) and value["expires"] > now


def enrich_countries(records, cache_path, explicit=None, now=None):
    now = int(time.time() if now is None else now)
    deadline = time.monotonic() + ENRICHMENT_TIMEOUT_SECONDS
    result = [dict(proxy) for proxy in records]
    cache = load_country_cache(cache_path)
    explicit = set() if explicit is None else explicit
    eligible = {}
    active_hosts = set()
    active_identities = set()
    stats = {"unknown_before": sum(not known_country(p.get("country")) for p in result), "updated": 0, "dns_queries": 0, "ip_queries": 0, "dns_cache_hits": 0, "ip_cache_hits": 0}
    for proxy in result:
        try:
            identity = record_identity(proxy)
            host = canonical_host(proxy["host"], proxy.get("type") == "webproxy").partition("/")[0]
        except (KeyError, ValueError, TypeError):
            continue
        active_hosts.add(host)
        active_identities.add(identity)
        inferred = cache["inferred"].get(identity, {})
        if identity in explicit:
            cache["inferred"].pop(identity, None)
            continue
        if known_country(proxy.get("country")) and inferred.get("country") != proxy["country"]:
            cache["inferred"].pop(identity, None)
            continue
        eligible.setdefault(host, []).append((proxy, identity))
    addresses_by_host = {}
    unresolved = []
    for host in eligible:
        saved = cache["dns"].get(host)
        if fresh_entry(saved, now) and isinstance(saved.get("ips"), list) and all(isinstance(value, str) and public_ip(value) for value in saved["ips"]):
            addresses_by_host[host] = list(dict.fromkeys(saved["ips"]))
            stats["dns_cache_hits"] += 1
        else:
            unresolved.append(host)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        pending = {pool.submit(resolve_public_ips, host, deadline): host for host in unresolved}
        for future in concurrent.futures.as_completed(pending):
            host = pending[future]
            stats["dns_queries"] += 1
            try:
                addresses, ttl = future.result()
            except Exception:
                addresses, ttl = [], FAILURE_CACHE_SECONDS
            addresses = list(dict.fromkeys(address for value in addresses if (address := public_ip(value))))
            addresses_by_host[host] = addresses
            cache["dns"][host] = {"ips": addresses, "expires": now + max(1, min(int(ttl), DNS_CACHE_MAX_SECONDS))}
    countries = {}
    missing_ips = []
    for address in sorted({value for values in addresses_by_host.values() for value in values}):
        saved = cache["ips"].get(address)
        if fresh_entry(saved, now):
            stats["ip_cache_hits"] += 1
            if known_country(saved.get("country")):
                countries[address] = saved["country"].upper()
        else:
            missing_ips.append(address)
    for start in range(0, len(missing_ips), GEOIP_BATCH_SIZE):
        if time.monotonic() >= deadline:
            break
        batch = missing_ips[start:start + GEOIP_BATCH_SIZE]
        stats["ip_queries"] += len(batch)
        try:
            found = lookup_country_batch(batch, deadline)
        except (requests.RequestException, ValueError, OSError):
            found = {}
        for address in batch:
            country = found.get(address)
            valid = known_country(country)
            cache["ips"][address] = {"country": country.upper() if valid else "", "expires": now + (IP_CACHE_SECONDS if valid else FAILURE_CACHE_SECONDS)}
            if valid:
                countries[address] = country.upper()
    for host, targets in eligible.items():
        resolved = [(address, countries[address]) for address in addresses_by_host.get(host, []) if address in countries]
        if not resolved:
            continue
        address, country = resolved[0]
        for proxy, identity in targets:
            stats["updated"] += proxy.get("country") != country
            proxy["country"] = country
            cache["inferred"][identity] = {"country": country, "ip": address}
    cache["dns"] = {host: entry for host, entry in cache["dns"].items() if host in active_hosts}
    active_ips = {address for entry in cache["dns"].values() if isinstance(entry, dict) for address in entry.get("ips", []) if isinstance(address, str)}
    cache["inferred"] = {identity: entry for identity, entry in cache["inferred"].items() if identity in active_identities}
    active_ips.update(entry["ip"] for entry in cache["inferred"].values() if isinstance(entry, dict) and isinstance(entry.get("ip"), str))
    retained_ips = [(address, entry) for address, entry in cache["ips"].items() if address in active_ips or fresh_entry(entry, now)]
    retained_ips.sort(key=lambda item: (item[0] in active_ips, item[1].get("expires", 0) if type(item[1].get("expires")) in (int, float) else 0), reverse=True)
    cache["ips"] = dict(retained_ips[:4096])
    try:
        save_country_cache(cache_path, cache)
    except OSError as error:
        print(f"[!] Country cache write failed: {type(error).__name__}")
    stats["unknown_after"] = sum(not known_country(p.get("country")) for p in result)
    return result, stats
