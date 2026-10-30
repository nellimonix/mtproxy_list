

import base64
import concurrent.futures
import hashlib
import hmac
import ipaddress
import json
import os
import random
import re
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, unquote, urljoin, urlsplit

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv()


PAGE_URL = "https://mtpro.xyz/mtproto-ru"
BASE_URL = "https://mtpro.xyz"
HTTP_RELAY_URL = os.getenv("MTPROXY_HTTP_RELAY_URL", "").rstrip("/")
SOCKS_LIST_URL = "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt"
TELEGRAM_CHANNEL_URL = "https://t.me/s/mtpro_xyz"
TELEGRAM_TARGET_PROXIES = 50
TELEGRAM_MAX_PAGES = 4
JSON_SOURCE_URL = "https://raw.githubusercontent.com/tgproxypink/telegram-proxy-list/main/proxies.json"
JSON_SOURCE_MAX_AGE_SECONDS = 6 * 60 * 60
JSON_SOURCE_FUTURE_TOLERANCE_SECONDS = 5 * 60
SOURCE_PROXY_CURL_CONFIG = os.getenv("MTPROXY_SOURCE_PROXY_CURL_CONFIG", "")

ATOB_RE = re.compile(r"\batob\s*\(\s*(['\"])([A-Za-z0-9+/=]+)\1\s*\)")
EVAL_URI_RE = re.compile(
    r"eval\(\s*decodeURIComponent\(\s*(['\"])([^'\"\\]*)\1\s*\)\s*\)"
)
GIT_REMOTE = os.getenv("GIT_REMOTE", "https://github.com/nellimonix/mtproxy_list.git")
GIT_TOKEN = os.getenv("GIT_TOKEN", "")
WORK_DIR = Path(os.getenv("WORK_DIR", "./mtproxy_list")).resolve()
OUTPUT_FILENAME = os.getenv("OUTPUT_FILENAME", "mtproxy.json")
GIT_BRANCH = os.getenv("GIT_BRANCH", "main")
GIT_USER_NAME = os.getenv("GIT_USER_NAME", "your-name")
GIT_USER_EMAIL = os.getenv("GIT_USER_EMAIL", "you@example.com")


ENC_KEY_B64 = os.getenv("MTPROXY_ENC_KEY", "")
NONCE_LABEL = b"mtproxy-nonce-v1"

INTERVAL_SECONDS = 30 * 60
REQUEST_TIMEOUT = 30
GIT_TIMEOUT = 60
SOCKS_CONNECT_TIMEOUT = 4
SOCKS_REQUEST_TIMEOUT = 9
SOCKS_BATCH_SIZE = 10
SOCKS_MAX_ATTEMPTS = 200
SOCKS_CANDIDATE_TTL = 20 * 60
SOURCE_MAX_BYTES = 2 * 1024 * 1024
SOURCE_PROXY_ATTEMPTS = 5

_socks_candidates = []
_socks_candidates_loaded = 0.0
_working_socks_proxy = None

HEADERS = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    "cache-control": "no-cache",
    "pragma": "no-cache",
    "user-agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/146.0.0.0 Safari/537.36"
    ),
}



class PageParser(HTMLParser):
    VOID_TAGS = set("area base br col embed hr img input link meta param source track wbr".split())

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = {"tag": "", "attrs": {}, "parent": None, "children": []}
        self.stack = [self.root]
        self.nodes = []

    def handle_starttag(self, tag, attrs):
        node = {"tag": tag, "attrs": dict(attrs), "parent": self.stack[-1], "children": []}
        self.stack[-1]["children"].append(node)
        self.nodes.append(node)
        if tag not in self.VOID_TAGS:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in self.VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index]["tag"] == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        self.stack[-1]["children"].append(data)


def node_text(node: dict) -> str:
    return "".join(child if isinstance(child, str) else node_text(child)
                   for child in node["children"])


def child_nodes(node: dict):
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        pending.extend(child for child in current["children"] if isinstance(child, dict))


def normalize_proxies(data: list[dict], source: str, emit_log: bool = True) -> list[dict]:
    if not isinstance(data, list) or not data:
        raise ValueError(f"{source}: пустой список или неверный формат")
    unique = {}
    for index, item in enumerate(data, 1):
        if not isinstance(item, dict):
            raise ValueError(f"{source}: запись {index} не является объектом")
        proxy = dict(item)
        host = proxy.get("host", proxy.get("server"))
        if not isinstance(host, str) or not host or any(c.isspace() for c in host):
            raise ValueError(f"{source}: запись {index}, некорректный host")
        port = proxy.get("port")
        if proxy.get("type") == "webproxy":
            if port != "":
                raise ValueError(f"{source}: запись {index}, webproxy содержит port")
        else:
            if type(port) is not int and not (isinstance(port, str) and re.fullmatch(r"[0-9]+", port)):
                raise ValueError(f"{source}: запись {index}, некорректный port")
            port = int(port)
            if not 1 <= port <= 65535:
                raise ValueError(f"{source}: запись {index}, port вне диапазона")
        secret = proxy.get("secret")
        if not isinstance(secret, str) or not secret or any(c.isspace() for c in secret):
            raise ValueError(f"{source}: запись {index}, некорректный secret")
        if proxy.get("type") == "webproxy":
            if not re.fullmatch(r"(?:[0-9a-fA-F]{32}|[dD]{2}[0-9a-fA-F]{32})", secret):
                try:
                    raw = base64.b64decode(secret + "=" * (-len(secret) % 4), altchars=b"-_", validate=True)
                except ValueError:
                    raise ValueError(f"{source}: запись {index}, некорректный webproxy secret") from None
                if not raw.startswith(b"\x70"):
                    raise ValueError(f"{source}: запись {index}, некорректный webproxy secret")
                secret = raw[1:].hex()
                if not re.fullmatch(r"(?:[0-9a-fA-F]{32}|dd[0-9a-fA-F]{32})", secret):
                    raise ValueError(f"{source}: запись {index}, некорректный webproxy secret")
            proxy["secret"] = secret.lower()
        country = proxy.get("country")
        if not isinstance(country, str) or not re.fullmatch(r"[A-Za-z]{2}", country):
            raise ValueError(f"{source}: запись {index}, некорректный country")
        if "addTime" in proxy and (type(proxy["addTime"]) is not int or proxy["addTime"] < 0):
            raise ValueError(f"{source}: запись {index}, некорректный addTime")
        proxy.update(host=host, port=port, country=country.upper())
        key = (host, port, proxy["secret"])
        if key not in unique or proxy.get("addTime", 0) > unique[key].get("addTime", 0):
            unique[key] = proxy
    result = list(unique.values())
    result.sort(key=lambda p: (-p.get("addTime", 0), p["host"], 0 if p["port"] == "" else p["port"], p["secret"]))
    if emit_log:
        print(f"[*] {source}: найдено {len(data)}, уникальных {len(result)}, дубликатов {len(data) - len(result)}")
    return result


def extract_proxies_from_html(html: str) -> list[dict]:
    page = PageParser()
    page.feed(html)
    data = []
    scope = next((n for n in page.nodes if n["attrs"].get("id") == "mtproto"), None)
    for node in page.nodes:
        if node["tag"] != "a":
            continue
        if scope is not None:
            ancestor = node
            while ancestor is not None and ancestor is not scope:
                ancestor = ancestor["parent"]
            if ancestor is None:
                continue
        url = urlsplit(node["attrs"].get("href", ""))
        if url.scheme != "tg" or url.netloc != "proxy":
            continue
        params = parse_qs(url.query, keep_blank_values=True, max_num_fields=32)
        if any(len(values) != 1 for values in params.values()):
            raise ValueError("HTML: повторяющиеся параметры ссылки")
        proxy = {key: values[0] for key, values in params.items()
                 if key in {"server", "port", "secret", "bot", "channel", "country"}}
        proxy["host"] = proxy.pop("server", "")
        row = node["parent"]
        countries = set()
        while row is not None and row["tag"] not in {"body", "html", ""}:
            links = []
            pending = [row]
            qr_countries = set()
            while pending:
                child = pending.pop()
                if child["tag"] == "a" and child["attrs"].get("href", "").startswith("tg://proxy?"):
                    links.append(child)
                onclick = child["attrs"].get("onclick", "")
                if re.match(r"\s*openQRModal\s*\(", onclick):
                    qr_countries.update(re.findall(r"\bcountry\s*:\s*['\"]([A-Za-z]{2})['\"]", onclick))
                pending.extend(c for c in child["children"] if isinstance(c, dict))
            if len(links) != 1:
                break
            countries.update(c.upper() for c in re.findall(r"#([A-Za-z]{2})(?![A-Za-z])", node_text(row)))
            countries.update(c.upper() for c in qr_countries)
            if countries:
                break
            row = row["parent"]
        if proxy.get("country"):
            countries.add(proxy["country"].upper())
        if len(countries) != 1:
            raise ValueError("HTML: страна отсутствует или противоречит QR/ссылке")
        proxy["country"] = countries.pop()
        data.append(proxy)
    return normalize_proxies(data, "HTML")


def extract_array_after_return(code: str) -> list[dict]:
    match = re.search(r"\breturn\s*(\[)", code)
    if match is None:
        raise ValueError("`return [` не найден в декодированном коде")
    start = match.start(1)

    depth, in_str, escape = 0, False, False
    for i in range(start, len(code)):
        ch = code[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return json.loads(code[start : i + 1])
    raise ValueError("Не удалось сбалансировать [...]")


def extract_proxies_from_js(js: str) -> list[dict]:
    sources = [js]
    seen = {js}
    for _ in range(4):
        decoded_sources = []
        for source in sources:
            for match in EVAL_URI_RE.finditer(source):
                decoded = unquote(match.group(2), encoding="utf-8", errors="strict")
                if decoded not in seen:
                    seen.add(decoded)
                    decoded_sources.append(decoded)
        if not decoded_sources:
            break
        if len(seen) > 32:
            raise ValueError("JS: слишком много decodeURIComponent-блоков")
        sources = decoded_sources
    js = "\n".join(sorted(seen))
    last_err = None
    for m in ATOB_RE.finditer(js):
        b64 = m.group(2)
        try:
            decoded = base64.b64decode(b64, validate=True).decode("utf-8")
        except Exception as e:
            last_err = e
            continue
        if not re.search(r"\breturn\s*\[", decoded) or '"host"' not in decoded:
            continue
        try:
            return extract_array_after_return(decoded)
        except Exception as e:
            last_err = e
            continue
    reason = type(last_err).__name__ if last_err else "нет подходящего atob с массивом host"
    raise RuntimeError(f"Массив прокси не найден в JS: {reason}; проверено слоёв: {len(seen)}")


def source_response(url: str, content: bytes) -> requests.Response:
    response = requests.Response()
    response.status_code = 200
    response.url = url
    response.encoding = "utf-8"
    response._content = content
    return response


def load_socks_candidates(session: requests.Session) -> list[str]:
    global _socks_candidates, _socks_candidates_loaded
    if _socks_candidates and time.monotonic() - _socks_candidates_loaded < SOCKS_CANDIDATE_TTL:
        return list(_socks_candidates)
    response = session.get(SOCKS_LIST_URL, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    if len(response.content) > SOURCE_MAX_BYTES:
        raise ValueError("SOCKS5-список превышает допустимый размер")
    candidates = []
    for line in response.text.splitlines():
        try:
            host, port_text = line.strip().rsplit(":", 1)
            address = ipaddress.ip_address(host)
            port = int(port_text)
        except ValueError:
            continue
        if address.is_global and 1 <= port <= 65535:
            candidates.append(f"{address}:{port}")
    if not candidates:
        raise ValueError("SOCKS5-список не содержит допустимых адресов")
    _socks_candidates = list(dict.fromkeys(candidates))
    _socks_candidates_loaded = time.monotonic()
    return list(_socks_candidates)


def curl_via_socks(url: str, proxy: str):
    command = [
        "curl", "--fail", "--silent", "--show-error", "--compressed",
        "--proto", "=https", "--connect-timeout", str(SOCKS_CONNECT_TIMEOUT),
        "--max-time", str(SOCKS_REQUEST_TIMEOUT), "--max-filesize", str(SOURCE_MAX_BYTES),
        "--socks5-hostname", proxy,
    ]
    for name, value in HEADERS.items():
        command.extend(["--header", f"{name}: {value}"])
    try:
        result = subprocess.run(
            [*command, url],
            check=False,
            capture_output=True,
            timeout=SOCKS_REQUEST_TIMEOUT + 3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not result.stdout or len(result.stdout) > SOURCE_MAX_BYTES:
        return None
    return source_response(url, result.stdout)


def curl_via_configured_proxy(url: str):
    if not SOURCE_PROXY_CURL_CONFIG:
        return None
    source = urlsplit(url)
    if source.scheme != "https" or source.netloc != urlsplit(PAGE_URL).netloc:
        raise ValueError("Настроенный SOCKS5: недопустимый источник")
    config = Path(SOURCE_PROXY_CURL_CONFIG)
    try:
        config_stat = config.stat()
    except OSError as error:
        raise RuntimeError(f"Настроенный SOCKS5: конфиг недоступен ({type(error).__name__})") from None
    if not stat.S_ISREG(config_stat.st_mode) or stat.S_IMODE(config_stat.st_mode) & 0o077:
        raise ValueError("Настроенный SOCKS5: конфиг должен быть обычным файлом с правами 0600")
    command = [
        "curl", "--config", str(config), "--fail", "--silent", "--show-error", "--compressed",
        "--proto", "=https", "--connect-timeout", str(SOCKS_CONNECT_TIMEOUT),
        "--max-time", str(REQUEST_TIMEOUT), "--max-filesize", str(SOURCE_MAX_BYTES),
    ]
    for name, value in HEADERS.items():
        command.extend(["--header", f"{name}: {value}"])
    last_error = ""
    for _ in range(SOURCE_PROXY_ATTEMPTS):
        try:
            result = subprocess.run(
                [*command, url],
                check=False,
                capture_output=True,
                timeout=REQUEST_TIMEOUT + 3,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            last_error = type(error).__name__
            continue
        if result.returncode == 0 and result.stdout and len(result.stdout) <= SOURCE_MAX_BYTES:
            return source_response(url, result.stdout)
        last_error = f"curl завершился с кодом {result.returncode}"
    raise RuntimeError(f"Настроенный SOCKS5: {last_error} после {SOURCE_PROXY_ATTEMPTS} попыток")


def get_source_via_socks(session: requests.Session, url: str):
    global _working_socks_proxy
    source = urlsplit(url)
    if source.scheme != "https" or source.netloc != urlsplit(PAGE_URL).netloc:
        raise ValueError("SOCKS5-резерв: недопустимый источник")
    candidates = load_socks_candidates(session)
    if _working_socks_proxy:
        response = curl_via_socks(url, _working_socks_proxy)
        if response is not None:
            return response
        _working_socks_proxy = None
    random.SystemRandom().shuffle(candidates)
    for start in range(0, min(len(candidates), SOCKS_MAX_ATTEMPTS), SOCKS_BATCH_SIZE):
        batch = candidates[start:start + SOCKS_BATCH_SIZE]
        with concurrent.futures.ThreadPoolExecutor(max_workers=SOCKS_BATCH_SIZE) as pool:
            results = list(pool.map(lambda proxy: curl_via_socks(url, proxy), batch))
        for proxy, response in zip(batch, results):
            if response is not None:
                _working_socks_proxy = proxy
                print(f"[!] SOCKS5-резерв: выбран рабочий маршрут после {start + len(batch)} попыток")
                return response
    attempted = min(len(candidates), SOCKS_MAX_ATTEMPTS)
    raise RuntimeError(f"SOCKS5-резерв: рабочий маршрут не найден среди {attempted} адресов")


def get_source(session: requests.Session, url: str, allow_socks: bool = True):
    errors = []
    try:
        response = session.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response
    except requests.RequestException as error:
        status = error.response.status_code if error.response is not None else None
        if status is not None and status not in {403, 429, 500, 502, 503, 504}:
            raise
        reason = f"HTTP {status}" if status is not None else type(error).__name__
        errors.append(reason)
    if HTTP_RELAY_URL:
        source = urlsplit(url)
        relay = urlsplit(HTTP_RELAY_URL)
        if source.scheme != "https" or source.netloc != urlsplit(PAGE_URL).netloc:
            raise ValueError("HTTP-резерв: недопустимый источник")
        if (relay.scheme not in {"http", "https"} or not relay.netloc
                or relay.username or relay.password or relay.query or relay.fragment):
            raise ValueError("Некорректный MTPROXY_HTTP_RELAY_URL")
        target = HTTP_RELAY_URL + source.path
        if source.query:
            target += "?" + source.query
        print(f"[!] Источник: {reason}; запрос через HTTP-релей")
        try:
            response = session.get(target, headers=HEADERS, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            response.url = url
            return response
        except requests.RequestException as error:
            status = error.response.status_code if error.response is not None else None
            errors.append(f"HTTP-релей {status}" if status is not None else f"HTTP-релей {type(error).__name__}")
    if SOURCE_PROXY_CURL_CONFIG:
        print("[!] HTTP-источники недоступны; пробую настроенный SOCKS5")
        try:
            response = curl_via_configured_proxy(url)
            if response is not None:
                return response
        except (RuntimeError, ValueError) as error:
            errors.append(str(error))
    if not allow_socks:
        raise RuntimeError("Источник недоступен: " + ", ".join(errors))
    print("[!] HTTP-источники недоступны; пробую SOCKS5-резерв")
    try:
        return get_source_via_socks(session, url)
    except (requests.RequestException, RuntimeError, ValueError) as error:
        raise RuntimeError("Источник недоступен: " + ", ".join(errors + [str(error)])) from None


def extract_proxies_from_telegram(html: str) -> tuple[list[dict], list[int]]:
    page = PageParser()
    page.feed(html)
    data = []
    post_ids = []
    for post in page.nodes:
        post_ref = post["attrs"].get("data-post", "")
        classes = post["attrs"].get("class", "").split()
        if "tgme_widget_message" not in classes or not post_ref.startswith("mtpro_xyz/"):
            continue
        try:
            post_id = int(post_ref.rsplit("/", 1)[1])
        except ValueError:
            continue
        post_ids.append(post_id)
        links = []
        countries = set()
        timestamps = set()
        for child in child_nodes(post):
            if child["tag"] == "code":
                country = node_text(child).strip().upper()
                if re.fullmatch(r"[A-Z]{2}", country):
                    countries.add(country)
            if child["tag"] == "time" and child["attrs"].get("datetime"):
                try:
                    timestamps.add(int(datetime.fromisoformat(child["attrs"]["datetime"].replace("Z", "+00:00")).timestamp()))
                except ValueError:
                    pass
            if child["tag"] != "a":
                continue
            href = child["attrs"].get("href", "")
            for _ in range(2):
                decoded = unescape(href)
                if decoded == href:
                    break
                href = decoded
            url = urlsplit(href)
            if url.scheme == "https" and url.netloc.lower() in {"t.me", "telegram.me"} and url.path in {"/proxy", "/webproxy"}:
                links.append(url)
            elif url.scheme == "tg" and url.netloc in {"proxy", "webproxy"} and not url.path:
                links.append(url)
        unique_links = {url.geturl(): url for url in links}
        if len(unique_links) != 1 or len(countries) != 1 or len(timestamps) != 1:
            continue
        url = next(iter(unique_links.values()))
        params = parse_qs(url.query, keep_blank_values=True, max_num_fields=32)
        if any(len(values) != 1 for values in params.values()):
            continue
        webproxy = url.path == "/webproxy" or (url.scheme == "tg" and url.netloc == "webproxy")
        required = ("server", "secret") if webproxy else ("server", "port", "secret")
        if not all(key in params for key in required):
            continue
        proxy = {
            "host": params["server"][0],
            "port": "" if webproxy else params["port"][0],
            "secret": params["secret"][0],
            "country": countries.pop(),
            "addTime": timestamps.pop(),
        }
        if webproxy:
            proxy["type"] = "webproxy"
        try:
            normalize_proxies([proxy], "Telegram", emit_log=False)
        except ValueError:
            continue
        data.append(proxy)
    return data, post_ids


def fetch_proxies_from_telegram(session: requests.Session) -> list[dict]:
    data = []
    before = None
    pages = 0
    for _ in range(TELEGRAM_MAX_PAGES):
        params = {"before": before} if before is not None else None
        try:
            response = session.get(TELEGRAM_CHANNEL_URL, params=params, headers=HEADERS, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            if len(response.content) > SOURCE_MAX_BYTES:
                raise ValueError("Telegram: страница превышает допустимый размер")
            page_data, post_ids = extract_proxies_from_telegram(response.text)
        except (requests.RequestException, ValueError) as error:
            if not data:
                raise
            print(f"[!] Telegram: загрузка страницы {pages + 1} прервана ({type(error).__name__}); использую собранные записи")
            break
        pages += 1
        data.extend(page_data)
        unique_count = len({(p["host"], int(p["port"]) if p["port"] != "" else "", p["secret"]) for p in data})
        if unique_count >= TELEGRAM_TARGET_PROXIES:
            break
        next_before = min(post_ids) if post_ids else None
        if next_before is None or (before is not None and next_before >= before):
            break
        before = next_before
    result = normalize_proxies(data, "Telegram")[:TELEGRAM_TARGET_PROXIES]
    print(f"[*] Telegram: использовано {len(result)} прокси, страниц {pages}")
    return result


def fetch_proxies_from_site(session: requests.Session, allow_socks: bool) -> list[dict]:
        r = get_source(session, PAGE_URL, allow_socks=allow_socks)
        page = PageParser()
        page.feed(r.text)
        errors = []
        scripts = [n for n in page.nodes if n["tag"] == "script"]
        scripts.sort(key=lambda n: "autoptimize" not in n["attrs"].get("src", ""))
        visited = set()
        for node in scripts:
            src = node["attrs"].get("src")
            if src:
                url = urljoin(r.url, src)
                if urlsplit(url).scheme != "https" or urlsplit(url).netloc != urlsplit(PAGE_URL).netloc:
                    continue
                if url in visited:
                    continue
                visited.add(url)
            try:
                if src:
                    response = get_source(session, url, allow_socks=allow_socks)
                    code = response.text
                else:
                    code = node_text(node)
                return normalize_proxies(extract_proxies_from_js(code), "JS")
            except (requests.RequestException, ValueError, RuntimeError) as error:
                errors.append(f"script {len(errors) + 1}: {_safe(str(error))}")
        try:
            data = extract_proxies_from_html(r.text)
        except ValueError as error:
            raise RuntimeError("Источник прокси не распознан; " + "; ".join(errors + [str(error)])) from None
        print("[!] HTML-резерв: addTime может отсутствовать; состав списка может включать рекламу")
        return data


def merge_telegram_proxies(data: list[dict], source: str = "Telegram") -> list[dict]:
    incoming = normalize_proxies(data, f"{source}-обновление")
    output_file = WORK_DIR / OUTPUT_FILENAME
    current = []
    if output_file.exists():
        saved = json.loads(decrypt_file(output_file))
        if saved != []:
            current = normalize_proxies(saved, "Опубликованный список")
    current_times = {}
    incoming_times = {}
    current_by_key = {(p["host"], p["port"], p["secret"]): p for p in current}
    for proxy in current:
        endpoint = (proxy["host"], proxy["port"])
        current_times[endpoint] = max(current_times.get(endpoint, 0), proxy.get("addTime", 0))
    for proxy in incoming:
        endpoint = (proxy["host"], proxy["port"])
        incoming_times[endpoint] = max(incoming_times.get(endpoint, 0), proxy.get("addTime", 0))
    fresh = []
    for proxy in incoming:
        endpoint = (proxy["host"], proxy["port"])
        timestamp = proxy.get("addTime", 0)
        if timestamp != incoming_times[endpoint] or timestamp < current_times.get(endpoint, 0):
            continue
        key = (proxy["host"], proxy["port"], proxy["secret"])
        fresh.append({**current_by_key.get(key, {}), **proxy})
    replaced_endpoints = {(p["host"], p["port"]) for p in fresh}
    retained = [p for p in current if (p["host"], p["port"]) not in replaced_endpoints]
    result = normalize_proxies(fresh + retained, f"{source} + опубликованный список")[:TELEGRAM_TARGET_PROXIES]
    result_by_key = {(p["host"], p["port"], p["secret"]): p for p in result}
    added = len(result_by_key.keys() - current_by_key.keys())
    updated = sum(current_by_key[key] != result_by_key[key] for key in current_by_key.keys() & result_by_key.keys())
    print(f"[*] {source}-резерв: собрано {len(incoming)}, добавлено {added}, обновлено {updated}, итог {len(result)}")
    return result


def parse_feed_timestamp(value: str) -> int:
    if not isinstance(value, str):
        raise ValueError("JSON source: invalid timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("JSON source: timestamp has no timezone")
    return int(parsed.timestamp())


def extract_proxies_from_json_feed(payload: dict, now: float = None) -> list[dict]:
    if not isinstance(payload, dict) or not isinstance(payload.get("proxies"), list):
        raise ValueError("JSON source: invalid response format")
    now = time.time() if now is None else now
    oldest = now - JSON_SOURCE_MAX_AGE_SECONDS
    newest = now + JSON_SOURCE_FUTURE_TOLERANCE_SECONDS
    updated = parse_feed_timestamp(payload.get("updated"))
    if not oldest <= updated <= newest:
        raise ValueError("JSON source: stale or future-dated response")
    data = []
    for item in payload["proxies"]:
        try:
            if not isinstance(item, dict) or item.get("kind") not in {"mtproto", "webproxy"}:
                continue
            checked = parse_feed_timestamp(item.get("checked"))
            if not oldest <= checked <= min(newest, updated + JSON_SOURCE_FUTURE_TOLERANCE_SECONDS):
                continue
            if not isinstance(item.get("link"), str):
                continue
            url = urlsplit(item["link"])
            webproxy = item["kind"] == "webproxy"
            route = "webproxy" if webproxy else "proxy"
            if not ((url.scheme == "https" and url.netloc.lower() in {"t.me", "telegram.me"} and url.path == "/" + route)
                    or (url.scheme == "tg" and url.netloc == route and not url.path)):
                continue
            params = parse_qs(url.query, keep_blank_values=True, max_num_fields=32)
            required = ("server", "secret") if webproxy else ("server", "port", "secret")
            if any(len(values) != 1 for values in params.values()) or not all(key in params for key in required):
                continue
            host = params["server"][0]
            port = "" if webproxy else int(params["port"][0])
            if host != item.get("server") or (not webproxy and (type(item.get("port")) is not int or port != item["port"])):
                continue
            secret = params["secret"][0]
            if not webproxy and (not re.fullmatch(r"[0-9a-fA-F]{32,512}", secret) or len(secret) % 2):
                continue
            proxy = {"host": host, "port": port, "secret": secret, "country": item["country"], "addTime": checked}
            if webproxy:
                proxy["type"] = "webproxy"
            data.extend(normalize_proxies([proxy], "JSON source", emit_log=False))
        except (ValueError, TypeError, KeyError, OverflowError):
            continue
    return normalize_proxies(data, "JSON source")[:TELEGRAM_TARGET_PROXIES]


def fetch_proxies_from_json_feed(session: requests.Session) -> list[dict]:
    response = session.get(JSON_SOURCE_URL, headers={**HEADERS, "accept": "application/json"}, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    if len(response.content) > SOURCE_MAX_BYTES:
        raise ValueError("JSON source: response exceeds size limit")
    return extract_proxies_from_json_feed(response.json())


def fetch_proxies() -> list[dict]:
    with requests.Session() as session:
        errors = []
        try:
            return fetch_proxies_from_site(session, allow_socks=False)
        except (requests.RequestException, RuntimeError, ValueError) as error:
            errors.append(f"сайт: {error}")
        try:
            return merge_telegram_proxies(fetch_proxies_from_json_feed(session), source="JSON")
        except (requests.RequestException, RuntimeError, ValueError) as error:
            errors.append(f"JSON source: {error}")
        print("[!] Сайт недоступен; пробую официальный Telegram-канал")
        try:
            return merge_telegram_proxies(fetch_proxies_from_telegram(session))
        except (requests.RequestException, RuntimeError, ValueError) as error:
            errors.append(f"Telegram: {error}")
        print("[!] Telegram недоступен; пробую SOCKS5 к сайту")
        try:
            return fetch_proxies_from_site(session, allow_socks=True)
        except (requests.RequestException, RuntimeError, ValueError) as error:
            raise RuntimeError("Все источники недоступны; " + "; ".join(errors + [f"SOCKS5: {error}"])) from None


def load_key() -> bytes:
    if not ENC_KEY_B64:
        raise RuntimeError("MTPROXY_ENC_KEY не задан — отказываюсь публиковать прокси открыто")
    key = base64.b64decode(ENC_KEY_B64)
    if len(key) not in (16, 24, 32):
        raise ValueError("MTPROXY_ENC_KEY: после base64 ожидаю 16/24/32 байта")
    return key


def encrypt_payload(data: list[dict], key: bytes) -> str:
    plaintext = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    nonce = hmac.new(key, NONCE_LABEL + plaintext, hashlib.sha256).digest()[:12]
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    envelope = {
        "v": 1,
        "alg": "A256GCM",
        "iv": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
    }
    return json.dumps(envelope, indent=2) + "\n"


def decrypt_file(path: Path) -> str:
    env = json.loads(path.read_text(encoding="utf-8"))
    nonce = base64.b64decode(env["iv"])
    ct = base64.b64decode(env["ct"])
    return AESGCM(load_key()).decrypt(nonce, ct, None).decode("utf-8")


def git(args: list[str], cwd: Path = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    return subprocess.run(
        ["git", *args],
        cwd=cwd or WORK_DIR,
        check=False,
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT,
        env=env,
    )


def authed_remote() -> str:
    if not GIT_TOKEN or "://" not in GIT_REMOTE:
        return GIT_REMOTE
    scheme, rest = GIT_REMOTE.split("://", 1)
    if "@" in rest.split("/", 1)[0]:
        return GIT_REMOTE
    return f"{scheme}://{GIT_USER_NAME}:{GIT_TOKEN}@{rest}"


def _safe(s: str) -> str:
    for secret in (GIT_TOKEN, ENC_KEY_B64):
        if secret:
            s = s.replace(secret, "***")
    return s


def ensure_repo() -> None:
    if (WORK_DIR / ".git").exists():
        return

    WORK_DIR.parent.mkdir(parents=True, exist_ok=True)
    remote = authed_remote()
    print(_safe(f"[*] Клонирую {GIT_REMOTE} → {WORK_DIR}"))
    res = subprocess.run(
        ["git", "clone", "--branch", GIT_BRANCH, remote, str(WORK_DIR)],
        check=False, capture_output=True, text=True,
    )
    if res.returncode != 0:
        print("[!] Клон с --branch не удался, пробую без ветки:", _safe(res.stderr.strip()))
        res2 = subprocess.run(
            ["git", "clone", remote, str(WORK_DIR)],
            check=False, capture_output=True, text=True,
        )
        if res2.returncode != 0:
            raise RuntimeError(f"git clone failed: {_safe(res2.stderr)}")
        git(["checkout", "-B", GIT_BRANCH])

    git(["remote", "set-url", "origin", GIT_REMOTE])
    git(["config", "user.name", GIT_USER_NAME])
    git(["config", "user.email", GIT_USER_EMAIL])
    print("[✓] Репозиторий готов")


def write_and_commit(data: list[dict]) -> None:
    if not data:
        print("[!] Пустой список, коммит пропущен")
        return

    output_file = WORK_DIR / OUTPUT_FILENAME
    content = encrypt_payload(data, load_key())
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    remote = authed_remote()

    pending = git(["status", "--porcelain", "--", OUTPUT_FILENAME])
    if pending.returncode != 0:
        raise RuntimeError(f"git status failed: {_safe(pending.stderr.strip())}")
    if pending.stdout.strip():
        print("[!] Git: восстанавливаю незавершённое обновление выходного файла")
        restore = git(["restore", "--worktree", "--", OUTPUT_FILENAME])
        if restore.returncode != 0:
            raise RuntimeError(f"git restore failed: {_safe(restore.stderr.strip())}")

    print("[*] Git: pull --rebase")
    pull = git(["pull", "--rebase", remote, GIT_BRANCH])
    if pull.returncode != 0:
        raise RuntimeError(f"git pull failed: {_safe(pull.stderr.strip())}")

    output_file.write_text(content, encoding="utf-8")
    git_add = git(["add", OUTPUT_FILENAME])
    if git_add.returncode != 0:
        raise RuntimeError(f"git add failed: {_safe(git_add.stderr.strip())}")

    status = git(["status", "--porcelain", "--", OUTPUT_FILENAME])
    if status.returncode != 0:
        raise RuntimeError(f"git status failed: {_safe(status.stderr.strip())}")
    if not status.stdout.strip():
        print(f"[=] {ts}: изменений нет")
        return

    commit = git(["commit", "-m", f"chore(proxy): update encrypted proxy list ({len(data)} entries)", "--", OUTPUT_FILENAME])
    if commit.returncode != 0:
        print("[x] git commit:", _safe(commit.stderr))
        return

    push = git(["push", remote, GIT_BRANCH])
    if push.returncode != 0:
        print("[x] git push:", _safe(push.stderr))
    else:
        print(f"[✓] {ts}: запушено {len(data)} прокси")


def main() -> None:
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "genkey":
            print(base64.b64encode(os.urandom(32)).decode())
            return
        if cmd == "decrypt":
            src = Path(sys.argv[2]) if len(sys.argv) > 2 else WORK_DIR / OUTPUT_FILENAME
            print(decrypt_file(src))
            return
        raise SystemExit(f"Неизвестная команда: {cmd}")

    load_key()
    if not GIT_TOKEN and "@" not in GIT_REMOTE:
        print("[!] GIT_TOKEN не задан — push без авторизации может не пройти")
    ensure_repo()
    while True:
        try:
            data = fetch_proxies()
            print(f"[+] Получено {len(data)} прокси")
            write_and_commit(data)
        except Exception as e:
            print(f"[x] Ошибка: {_safe(repr(e))}")
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
