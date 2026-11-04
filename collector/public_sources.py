import base64
import concurrent.futures
import ipaddress
import json
import os
import re
import time
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import requests


PUBLIC_SOURCES = (
    ("coatsectorclamp", "https://coatsectorclamp.github.io/", "html"),
    ("auditorcrater", "https://auditorcrater.github.io/", "html"),
    ("mtproxy_fyi", "https://mtproxy.fyi/", "html"),
    ("tgproxy_fyi", "https://tgproxy.fyi/", "html"),
    ("prichal", "https://prichal.xyz/api/v1/proxies", "json"),
    ("toproxylab", "https://toproxylab.com/ru/proksi-dlya-tg", "html"),
    ("gproxy", "https://gproxy.net/ru/blog/free-socks5-proxy-for-telegram/", "html"),
)
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_SOURCE_RECORDS = 1000
SOURCE_DEADLINE_SECONDS = 25


class SourcePage(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.nodes = []
        self.root = {"tag": "", "attrs": {}, "children": [], "parent": None}
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = {"tag": tag, "attrs": dict(attrs), "children": [], "parent": self.stack[-1]}
        self.stack[-1]["children"].append(node)
        self.nodes.append(node)
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index]["tag"] == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        self.stack[-1]["children"].append(data)


def node_text(node):
    return " ".join(child if isinstance(child, str) else node_text(child) for child in node["children"])


def descendants(node):
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        pending.extend(child for child in current["children"] if isinstance(child, dict))


def canonical_host(value, webproxy=False):
    if not isinstance(value, str) or not value or any(c.isspace() for c in value):
        raise ValueError("Invalid proxy host")
    host, separator, path = value.partition("/")
    if separator and (not webproxy or not re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", path)):
        raise ValueError("Invalid proxy host path")
    host = host.rstrip(".").lower()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or "." not in host or all(label.isdigit() for label in host.split(".")) or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
            raise ValueError("Invalid proxy hostname")
    else:
        if not address.is_global:
            raise ValueError("Proxy address is not public")
        host = str(address)
    return host + ("/" + path if separator else "")


def canonical_secret(value, webproxy=False):
    if not isinstance(value, str) or not 20 <= len(value) <= 512:
        raise ValueError("Invalid proxy secret")
    if re.fullmatch(r"[0-9a-fA-F]+", value) and len(value) >= 32 and len(value) % 2 == 0:
        decoded = bytes.fromhex(value)
        result = value.lower()
    else:
        if not re.fullmatch(r"[A-Za-z0-9_+/=-]+", value):
            raise ValueError("Invalid proxy secret encoding")
        try:
            decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        except ValueError:
            raise ValueError("Invalid proxy secret encoding") from None
        if not 16 <= len(decoded) <= 256:
            raise ValueError("Invalid proxy secret length")
        result = value
        if webproxy:
            if not decoded.startswith(b"\x70"):
                raise ValueError("Invalid webproxy secret prefix")
            decoded = decoded[1:]
            result = decoded.hex()
        elif len(decoded) == 17 and decoded.startswith(b"\xdd") or len(decoded) > 17 and decoded.startswith(b"\xee"):
            result = decoded.hex()
    if webproxy and not (len(decoded) == 16 or len(decoded) == 17 and decoded.startswith(b"\xdd")):
        raise ValueError("Invalid webproxy secret length")
    return result


def supported_proxy(proxy):
    secret = proxy["secret"]
    if proxy.get("type") == "webproxy":
        return True
    if re.fullmatch(r"dd[0-9a-f]{32}", secret):
        return True
    match = re.fullmatch(r"ee[0-9a-f]{32}([0-9a-f]+)", secret)
    if not match or len(match.group(1)) % 2:
        return False
    try:
        domain = bytes.fromhex(match.group(1)).decode("ascii").rstrip(".")
    except (ValueError, UnicodeDecodeError):
        return False
    return bool(domain) and len(domain) <= 253 and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label, re.IGNORECASE) for label in domain.split("."))


def proxy_key(proxy):
    return (canonical_host(proxy["host"], proxy.get("type") == "webproxy"), proxy["port"], proxy["secret"])


def proxy_from_link(value, country="ZZ"):
    if not isinstance(value, str):
        raise ValueError("Invalid proxy link")
    for _ in range(2):
        value = unescape(value)
    url = urlsplit(value)
    route = url.netloc if url.scheme == "tg" and not url.path else url.path.lstrip("/")
    if not ((url.scheme == "tg" and not url.path) or (url.scheme == "https" and url.netloc.lower() in {"t.me", "telegram.me", "telegram.dog"})) or route not in {"proxy", "webproxy"}:
        raise ValueError("Unsupported proxy link")
    params = parse_qs(url.query, keep_blank_values=True, max_num_fields=32)
    required = {"server", "secret"} | ({"port"} if route == "proxy" else set())
    if not required.issubset(params) or any(len(values) != 1 for values in params.values()):
        raise ValueError("Invalid proxy link parameters")
    webproxy = route == "webproxy"
    port = "" if webproxy else params["port"][0]
    if not webproxy:
        if not re.fullmatch(r"[0-9]{1,5}", port) or not 1 <= int(port) <= 65535:
            raise ValueError("Invalid proxy port")
        port = int(port)
    country = country.upper() if isinstance(country, str) and re.fullmatch(r"[A-Za-z]{2}", country) else "ZZ"
    result = {"host": canonical_host(params["server"][0], webproxy), "port": port, "secret": canonical_secret(params["secret"][0], webproxy), "country": country}
    if webproxy:
        result["type"] = "webproxy"
    return result


def country_from_node(node):
    countries = set()
    for child in descendants(node):
        value = child["attrs"].get("data-country", "")
        if re.fullmatch(r"[A-Za-z]{2}", value):
            countries.add(value.upper())
        if child["tag"] == "img":
            match = re.search(r"(?:flagcdn\.com/(?:[^/]+/)?|/flags/)([a-z]{2})\.(?:png|svg|webp)", child["attrs"].get("src", ""))
            if match:
                countries.add(match.group(1).upper())
    text = node_text(node)
    countries.update(match.upper() for match in re.findall(r"#([A-Za-z]{2})(?![A-Za-z])", text))
    for match in re.findall(r"[\U0001f1e6-\U0001f1ff]{2}", text):
        countries.add("".join(chr(ord(character) - 0x1F1E6 + ord("A")) for character in match))
    return next(iter(countries)) if len(countries) == 1 else "ZZ"


def country_for_link(node):
    current = node
    for _ in range(5):
        if current is None or current["tag"] in {"", "body", "html", "table", "tbody"}:
            break
        keys = set()
        for child in descendants(current):
            if child["tag"] == "a":
                try:
                    keys.add(proxy_key(proxy_from_link(child["attrs"].get("href", ""))))
                except (ValueError, TypeError):
                    pass
        if len(keys) > 1:
            break
        country = country_from_node(current)
        if country != "ZZ":
            return country
        current = current["parent"]
    return "ZZ"


def records_from_json(payload):
    records = []
    pending = [(payload, 0)]
    visited = 0
    while pending and len(records) < MAX_SOURCE_RECORDS:
        item, depth = pending.pop()
        visited += 1
        if visited > 10000 or depth > 12:
            continue
        if isinstance(item, list):
            pending.extend((value, depth + 1) for value in reversed(item[:MAX_SOURCE_RECORDS]))
        elif isinstance(item, dict):
            if item.get("is_premium") is True:
                continue
            link = item.get("link", item.get("url"))
            try:
                if link:
                    records.append(proxy_from_link(link, item.get("country", "ZZ")))
                elif all(key in item for key in ("server", "port", "secret")):
                    from urllib.parse import urlencode
                    webproxy = item.get("type") == "webproxy" or item["port"] == ""
                    route = "webproxy" if webproxy else "proxy"
                    values = {key: item[key] for key in ("server", "secret")}
                    if not webproxy:
                        values["port"] = item["port"]
                    records.append(proxy_from_link("tg://" + route + "?" + urlencode(values), item.get("country", "ZZ")))
            except (ValueError, TypeError):
                pass
            pending.extend((value, depth + 1) for value in item.values() if isinstance(value, (dict, list)))
    return records


def extract_site_proxies(text, format="html"):
    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError("Invalid source size")
    if format == "json":
        records = records_from_json(json.loads(text))
    else:
        page = SourcePage()
        page.feed(text)
        records = []
        for node in page.nodes:
            if node["tag"] == "a":
                try:
                    records.append(proxy_from_link(node["attrs"].get("href", ""), country_for_link(node)))
                except (ValueError, TypeError):
                    pass
            elif node["tag"] == "script":
                code = node_text(node)
                if node["attrs"].get("type") in {"application/json", "application/ld+json"}:
                    try:
                        records.extend(records_from_json(json.loads(code)))
                    except (ValueError, TypeError):
                        pass
                for match in re.finditer(r"\b(?:var|let|const)\s+(?:allMT|proxies|servers)\s*=\s*(\[)", code):
                    try:
                        payload, _ = json.JSONDecoder().raw_decode(code[match.start(1):])
                        records.extend(records_from_json(payload))
                    except (ValueError, TypeError):
                        pass
            if len(records) > MAX_SOURCE_RECORDS * 4:
                break
    unique = {}
    for proxy in records:
        key = proxy_key(proxy)
        if key not in unique or unique[key]["country"] == "ZZ":
            unique[key] = proxy
    return list(unique.values())[:MAX_SOURCE_RECORDS]


class BoundedSourceSession(requests.Session):
    def __init__(self):
        super().__init__()
        self.deadline = time.monotonic() + SOURCE_DEADLINE_SECONDS

    def get(self, url, **kwargs):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise requests.Timeout("Source deadline exceeded")
        kwargs["timeout"] = (min(5, remaining), min(10, remaining))
        kwargs["stream"] = True
        response = super().get(url, **kwargs)
        try:
            response.raise_for_status()
            chunks = []
            size = 0
            for chunk in response.iter_content(16384):
                size += len(chunk)
                if size > MAX_SOURCE_BYTES:
                    raise ValueError("Source response exceeds size limit")
                if time.monotonic() > self.deadline:
                    raise requests.Timeout("Source deadline exceeded")
                chunks.append(chunk)
            response._content = b"".join(chunks)
            response._content_consumed = True
            response.encoding = "utf-8"
            return response
        finally:
            response.close()


def fetch_public_source(source):
    name, url, format = source
    with BoundedSourceSession() as session:
        response = session.get(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json,text/html;q=0.9"})
        records = extract_site_proxies(response.text, format)
    return records


def collect_source_batches(tasks):
    results = {}
    statuses = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        pending = {pool.submit(task): name for name, task in tasks}
        for future in concurrent.futures.as_completed(pending):
            name = pending[future]
            try:
                records = future.result()
                if records:
                    results[name] = records
                statuses[name] = {"count": len(records), "status": "ok" if records else "empty"}
            except Exception as error:
                statuses[name] = {"count": 0, "status": type(error).__name__}
    return results, statuses


def load_source_state(path):
    path = Path(path)
    if not path.exists():
        return {"v": 1, "first_seen": {}}
    state = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(state, dict) or state.get("v") != 1 or not isinstance(state.get("first_seen"), dict):
        raise ValueError("Invalid collector source state")
    return state


def write_source_state(path, state):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".next")
    with temporary.open("w", encoding="utf-8") as output:
        json.dump(state, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
    temporary.chmod(0o600)
    os.replace(temporary, path)


def assemble_proxies(batches, current, state, target=100, now=None):
    now = int(time.time() if now is None else now)
    state = {"v": 1, "first_seen": dict(state["first_seen"])}
    previous = {}
    for item in current:
        try:
            proxy = dict(item)
            proxy["host"] = canonical_host(proxy["host"], proxy.get("type") == "webproxy")
            proxy["secret"] = canonical_secret(proxy["secret"], proxy.get("type") == "webproxy")
            if not supported_proxy(proxy):
                continue
            previous[proxy_key(proxy)] = proxy
        except (ValueError, TypeError, KeyError):
            continue
    previous_times = {}
    for proxy in previous.values():
        endpoint = (proxy["host"], proxy["port"])
        previous_times[endpoint] = max(previous_times.get(endpoint, 0), proxy.get("addTime", 0))
    prepared = {}
    candidates = {}
    for source in sorted(batches):
        records = batches[source]
        keys = []
        for item in records:
            try:
                proxy = dict(item)
                proxy["host"] = canonical_host(proxy["host"], proxy.get("type") == "webproxy")
                proxy["secret"] = canonical_secret(proxy["secret"], proxy.get("type") == "webproxy")
                if not supported_proxy(proxy):
                    continue
                key = proxy_key(proxy)
            except (ValueError, TypeError, KeyError):
                continue
            encoded_key = json.dumps(key, separators=(",", ":"))
            old = previous.get(key, {})
            first_seen = state["first_seen"].setdefault(encoded_key, old.get("addTime", now))
            if type(first_seen) is not int or not 0 <= first_seen <= now + 300:
                first_seen = now
                state["first_seen"][encoded_key] = now
            added = proxy.get("addTime", first_seen)
            if type(added) is not int or not 0 <= added <= now + 300:
                added = first_seen
            if key not in previous and added < previous_times.get((proxy["host"], proxy["port"]), 0):
                continue
            if old.get("addTime", 0) > added:
                proxy = {**proxy, **old}
            proxy["addTime"] = max(added, old.get("addTime", 0))
            if proxy.get("country", "ZZ") == "ZZ" and old.get("country"):
                proxy["country"] = old["country"]
            if key not in candidates:
                candidates[key] = {**old, **proxy}
            else:
                existing = candidates[key]
                best, alternate = (proxy, existing) if proxy["addTime"] > existing["addTime"] else (existing, proxy)
                combined = {**old, **best}
                if combined.get("country") == "ZZ" and alternate.get("country") != "ZZ":
                    combined["country"] = alternate["country"]
                candidates[key] = combined
            keys.append(key)
        prepared[source] = list(dict.fromkeys(keys))
    if not candidates:
        raise ValueError("No valid proxy records collected")
    selected = {}
    positions = {source: 0 for source in prepared}
    for source, keys in prepared.items():
        keys.sort(key=lambda key: (-candidates[key]["addTime"], key[0], str(key[1]), key[2]))
    while len(selected) < target:
        progress = False
        for source in sorted(prepared):
            keys = prepared[source]
            while positions[source] < len(keys):
                key = keys[positions[source]]
                positions[source] += 1
                if key not in selected:
                    selected[key] = candidates[key]
                    progress = True
                    break
            if len(selected) == target:
                break
        if not progress:
            break
    replacements = {}
    for proxy in selected.values():
        endpoint = (proxy["host"], proxy["port"])
        replacements[endpoint] = max(replacements.get(endpoint, 0), proxy["addTime"])
    for key, proxy in sorted(previous.items(), key=lambda item: (-item[1].get("addTime", 0), item[0][0], str(item[0][1]), item[0][2])):
        if len(selected) >= target:
            break
        if key not in selected and proxy.get("addTime", 0) > replacements.get((proxy["host"], proxy["port"]), -1):
            selected[key] = proxy
    result = list(selected.values())
    result.sort(key=lambda proxy: (-proxy["addTime"], proxy["host"], str(proxy["port"]), proxy["secret"]))
    active_keys = {json.dumps(key, separators=(",", ":")) for key in candidates.keys() | previous.keys()}
    state["first_seen"] = {key: value for key, value in state["first_seen"].items() if key in active_keys}
    return result, state
