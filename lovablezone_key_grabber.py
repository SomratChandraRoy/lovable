#!/usr/bin/env python3
"""
LovableZone free-trial key grabber

Features:
  - Full device fingerprint rotation every request
  - Proxy rotation from proxy.txt (any common format)
  - Optional RANDOM PORT: each try swaps proxy host onto a random port
  - Dynamic wait, dead-proxy quarantine, IP rate-limit handling
  - Optional dedupe of saved keys, verbose mode
"""

from __future__ import annotations

import argparse
import json
import random
import re
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse, quote, urlunparse

import urllib.request
import urllib.error
import http.cookiejar
import ssl

ENDPOINT = (
    "https://www.lovablezone.xyz/_serverFn/"
    "60e11d0f7e53cf5d4a4b3abed26577421d41dc982cf5b8396172a9bf106611f5"
)
ORIGIN = "https://www.lovablezone.xyz"
DEFAULT_OUT = Path(__file__).resolve().parent / "license.txt"
DEFAULT_PROXY_FILE = Path(__file__).resolve().parent / "proxy.txt"

# Common HTTP / SOCKS / gateway ports to try when --random-port is ON
RANDOM_PORTS = [
    80, 443, 1080, 1081, 3128, 8000, 8001, 8080, 8081, 8082, 8888, 8889,
    9050, 9051, 9090, 9999, 3129, 8118, 8443, 9443, 10000, 18080, 3127,
    4145, 4153, 10808, 7890, 7891, 10809, 20170, 20171, 42000, 60088,
]

BD_OPS = ["13", "14", "15", "16", "17", "18", "19"]

RESOLUTIONS = [
    (1366, 768), (1440, 900), (1536, 864), (1600, 900),
    (1920, 1080), (2560, 1440), (1280, 720), (1680, 1050),
]

TIMEZONES = [
    "Asia/Dhaka", "Asia/Kolkata", "Asia/Dubai", "Asia/Bangkok",
    "Asia/Jakarta", "Asia/Singapore", "Asia/Karachi", "Asia/Riyadh",
    "Europe/London", "Europe/Berlin", "America/New_York", "America/Guatemala",
    "Africa/Cairo", "Australia/Sydney",
]

UA_PROFILES = [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", "Chrome", False),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0", "Edge", False),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", "Brave", False),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", "Chrome", False),
    ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", "Chrome", False),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0", "Firefox", False),
    ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36", "Chrome", True),
    ("Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36", "Chrome", True),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1", "Safari", True),
    ("Mozilla/5.0 (Linux; Android 16; Pixel 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Mobile Safari/537.36", "Brave", True),
]

ACCEPT_LANGS = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,bn;q=0.8",
    "bn-BD,bn;q=0.9,en-US;q=0.8,en;q=0.7",
    "en-US,en;q=0.8,hi;q=0.6",
]


# ---------------------------------------------------------------------------
# Proxy normalize / mutate port
# ---------------------------------------------------------------------------

def normalize_proxy(line: str, default_scheme: str = "http") -> str | None:
    s = line.strip()
    if not s or s.startswith("#") or s.startswith("//"):
        return None
    s = s.strip(" '\"\t\r")

    if re.match(r"^(https?|socks4|socks5|socks5h)://", s, re.I):
        return s

    if "@" in s and "://" not in s:
        return f"{default_scheme}://{s}"

    parts = s.split(":")
    if len(parts) == 2:
        host, port = parts
        if not port.isdigit():
            return None
        return f"{default_scheme}://{host}:{port}"
    if len(parts) == 4:
        a, b, c, d = parts
        if b.isdigit():
            user, password = quote(c, safe=""), quote(d, safe="")
            return f"{default_scheme}://{user}:{password}@{a}:{b}"
        if d.isdigit():
            user, password = quote(a, safe=""), quote(b, safe="")
            return f"{default_scheme}://{user}:{password}@{c}:{d}"
    if len(parts) == 3 and parts[1].isdigit():
        return None
    return None


def load_proxies(path: Path, default_scheme: str = "http") -> list[str]:
    if not path.exists():
        return []
    out: list[str] = []
    seen = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        url = normalize_proxy(line, default_scheme=default_scheme)
        if url and url not in seen:
            seen.add(url)
            out.append(url)
    return out


def proxy_label(url: str) -> str:
    try:
        p = urlparse(url)
        host = p.hostname or "?"
        port = p.port or ""
        scheme = p.scheme or "http"
        auth = "auth@" if p.username else ""
        return f"{scheme}://{auth}{host}:{port}"
    except Exception:
        return url[:48]


def with_random_port(proxy_url: str, ports: list[int] | None = None) -> str:
    """
    Keep host + auth + scheme, replace port with a random one.
    SKIP (return original) when:
      - proxy has username/password (auth gateways like decodo/brightdata break on wrong port)
      - hostname looks like a known sticky gateway
    Original port is always kept in the candidate set.
    """
    ports = ports or RANDOM_PORTS
    p = urlparse(proxy_url)
    if not p.hostname:
        return proxy_url

    host = (p.hostname or "").lower()
    # Auth / residential gateways: port is part of the product endpoint — do not randomize
    gateway_markers = (
        "decodo.", "brightdata.", "luminati.", "oxylabs.", "smartproxy.",
        "iproyal.", "soax.", "netnut.", "packetstream.", "proxy-seller.",
        "webshare.", "geonode.", "proxyrack.", "stormproxy.", "infatica.",
        "gate.", "gw.", "resi.", "residential.", "premium.",
    )
    if p.username is not None or any(m in host for m in gateway_markers):
        return proxy_url

    candidates = list(ports)
    if p.port and p.port not in candidates:
        candidates.append(p.port)
    new_port = random.choice(candidates)
    if p.port and new_port == p.port:
        return proxy_url
    if p.username is not None:
        user = quote(p.username, safe="")
        if p.password is not None:
            password = quote(p.password, safe="")
            netloc = f"{user}:{password}@{p.hostname}:{new_port}"
        else:
            netloc = f"{user}@{p.hostname}:{new_port}"
    else:
        netloc = f"{p.hostname}:{new_port}"
    return urlunparse((p.scheme or "http", netloc, "", "", "", ""))


# ---------------------------------------------------------------------------
# Fingerprint helpers
# ---------------------------------------------------------------------------

def random_bd_whatsapp() -> str:
    op = random.choice(BD_OPS)
    sub = "".join(str(random.randint(0, 9)) for _ in range(8))
    return f"+880{op}{sub}"


def random_device_id() -> str:
    return uuid.uuid4().hex


def random_hw(browser_tag: str, mobile: bool) -> str:
    if mobile:
        w, h = random.choice([(390, 844), (412, 915), (360, 800), (393, 873), (414, 896)])
        cores = random.choice([4, 6, 8])
        mem = random.choice([4, 6, 8])
    else:
        w, h = random.choice(RESOLUTIONS)
        cores = random.choice([4, 6, 8, 12, 16])
        mem = random.choice([8, 16, 32])
    depth = random.choice([24, 30])
    dpr_ish = random.choice([1, 2, 3])
    flag = random.choice([0, 1])
    tz = random.choice(TIMEZONES)
    return f"{w}|{h}|{depth}|{dpr_ish}|{mem}|{cores}|{flag}|{tz}|{browser_tag}"


def build_payload(whatsapp: str, device_id: str, hw: str) -> dict:
    return {
        "t": {
            "t": 10,
            "i": 0,
            "p": {
                "k": ["data"],
                "v": [
                    {
                        "t": 10,
                        "i": 1,
                        "p": {
                            "k": ["deviceId", "hw", "whatsapp"],
                            "v": [
                                {"t": 1, "s": device_id},
                                {"t": 1, "s": hw},
                                {"t": 1, "s": whatsapp},
                            ],
                        },
                        "o": 0,
                    }
                ],
            },
            "o": 0,
        },
        "f": 127,
        "m": [],
    }


def decode_val(v):
    if isinstance(v, dict):
        if "s" in v:
            return v["s"]
        if "p" in v and isinstance(v["p"], dict) and "k" in v["p"] and "v" in v["p"]:
            return {kk: decode_val(vv) for kk, vv in zip(v["p"]["k"], v["p"]["v"])}
    return v


def as_bool(x):
    if x in (True, 1, "1", 2, "2"):
        return True
    if x in (False, 0, "0", 3, "3"):
        return False
    return bool(x) if x is not None else False


def parse_response(raw: str) -> dict:
    out = {"ok": False, "key": None, "name": None, "reused": None, "error": None, "raw": raw}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return out
    try:
        top_keys = data.get("p", {}).get("k", [])
        top_vals = data.get("p", {}).get("v", [])
        top = {k: decode_val(v) for k, v in zip(top_keys, top_vals)}
        result = top.get("result") if isinstance(top.get("result"), dict) else {}
        out["key"] = result.get("key")
        out["name"] = result.get("name")
        if result.get("reused") is not None:
            out["reused"] = as_bool(result.get("reused"))
        out["error"] = result.get("error")
        out["ok"] = bool(out["key"])
    except Exception:
        pass
    return out


def make_headers(ua: str, mobile: bool) -> dict:
    lang = random.choice(ACCEPT_LANGS)
    h = {
        "accept": "application/x-tss-framed, application/x-ndjson, application/json",
        "accept-language": lang,
        "content-type": "application/json",
        "origin": ORIGIN,
        "referer": ORIGIN + "/",
        "user-agent": ua,
        "x-tsr-serverfn": "true",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "priority": "u=1, i",
    }
    if "Chrome" in ua or "Brave" in ua or "Edg" in ua:
        ver = "131"
        for part in ua.split():
            if part.startswith("Chrome/"):
                ver = part.split("/")[1].split(".")[0]
                break
        h["sec-ch-ua"] = f'"Chromium";v="{ver}", "Not_A Brand";v="24", "Google Chrome";v="{ver}"'
        h["sec-ch-ua-mobile"] = "?1" if mobile else "?0"
        h["sec-ch-ua-platform"] = (
            '"Android"' if mobile and "Android" in ua
            else '"iOS"' if mobile
            else '"Windows"' if "Windows" in ua
            else '"macOS"' if "Mac" in ua
            else '"Linux"'
        )
    return h


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class FingerprintSession:
    def __init__(self, proxy_url: str | None = None):
        self.proxy_url = proxy_url
        self.cj = http.cookiejar.CookieJar()
        handlers: list = [urllib.request.HTTPCookieProcessor(self.cj)]

        if proxy_url:
            parsed = urlparse(proxy_url)
            scheme = (parsed.scheme or "http").lower()
            if scheme in ("socks5", "socks5h", "socks4"):
                try:
                    import socks  # type: ignore
                    from sockshandler import SocksiPyHandler  # type: ignore

                    sock_type = socks.SOCKS5 if scheme.startswith("socks5") else socks.SOCKS4
                    handlers.insert(
                        0,
                        SocksiPyHandler(
                            sock_type,
                            parsed.hostname,
                            parsed.port or 1080,
                            username=parsed.username,
                            password=parsed.password,
                        ),
                    )
                except ImportError:
                    handlers.insert(
                        0,
                        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}),
                    )
            else:
                handlers.insert(
                    0,
                    urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}),
                )

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self.opener = urllib.request.build_opener(*handlers)

    def post(self, whatsapp: str | None = None, timeout: float = 40.0) -> dict:
        ua, tag, mobile = random.choice(UA_PROFILES)
        device_id = random_device_id()
        hw = random_hw(tag, mobile)
        wa = whatsapp or random_bd_whatsapp()
        headers = make_headers(ua, mobile)
        body = json.dumps(build_payload(wa, device_id, hw)).encode("utf-8")
        req = urllib.request.Request(ENDPOINT, data=body, method="POST", headers=headers)

        meta = {
            "whatsapp": wa,
            "device_id": device_id,
            "hw": hw,
            "proxy": proxy_label(self.proxy_url) if self.proxy_url else "direct",
        }
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                parsed = parse_response(raw)
                parsed["status"] = resp.status
                parsed.update(meta)
                return parsed
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace") if e.fp else ""
            parsed = parse_response(raw)
            parsed.update(meta)
            parsed["status"] = e.code
            if not parsed.get("error"):
                parsed["error"] = str(e)
            parsed["raw"] = raw
            return parsed
        except Exception as e:
            return {
                "ok": False,
                "key": None,
                "name": None,
                "reused": None,
                "error": str(e),
                "raw": "",
                "status": None,
                **meta,
            }


def append_license(path: Path, whatsapp: str, key: str, name, reused, proxy: str, seen_keys: set[str] | None) -> bool:
    """Return False if duplicate key skipped."""
    if seen_keys is not None:
        if key in seen_keys:
            return False
        seen_keys.add(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(f"{whatsapp}\t{key}\t{name or ''}\treused={reused}\tproxy={proxy}\n")
    return True


def load_existing_keys(path: Path) -> set[str]:
    keys: set[str] = set()
    if not path.exists():
        return keys
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[1].startswith("LOVABLEZONE-"):
            keys.add(parts[1])
    return keys


def dynamic_wait(base: float, attempt: int, success: bool, rate_limited: bool, proxy_dead: bool) -> float:
    if proxy_dead:
        return random.uniform(0.2, 0.8)
    if rate_limited:
        return random.uniform(1.5, 4.0)
    if success:
        return base * random.uniform(0.7, 1.2)
    return base * random.uniform(1.0, 1.8) + min(attempt * 0.1, 3.0)


class ProxyPool:
    def __init__(self, proxies: list[str], random_port: bool = False, port_list: list[int] | None = None):
        self.base_proxies = list(proxies)
        self.bad: set[str] = set()          # exact URL (with port) marked bad
        self.bad_hosts: set[str] = set()    # host fully dead
        self.idx = 0
        self.random_port = random_port
        self.port_list = port_list or RANDOM_PORTS
        random.shuffle(self.base_proxies)

    def _host(self, url: str) -> str:
        try:
            return (urlparse(url).hostname or url).lower()
        except Exception:
            return url

    def next(self) -> str | None:
        alive_base = [
            p for p in self.base_proxies
            if self._host(p) not in self.bad_hosts
        ]
        if not alive_base:
            self.bad_hosts.clear()
            self.bad.clear()
            alive_base = list(self.base_proxies)
        if not alive_base:
            return None

        self.idx = (self.idx + 1) % len(alive_base)
        base = alive_base[self.idx]

        if self.random_port:
            # try up to 8 random ports until one not in bad set
            for _ in range(8):
                candidate = with_random_port(base, self.port_list)
                if candidate not in self.bad:
                    return candidate
            return with_random_port(base, self.port_list)

        if base in self.bad:
            # skip to another base
            for _ in range(len(alive_base)):
                self.idx = (self.idx + 1) % len(alive_base)
                base = alive_base[self.idx]
                if base not in self.bad:
                    return base
            return base
        return base

    def mark_bad(self, proxy: str | None, kill_host: bool = False) -> None:
        if not proxy:
            return
        self.bad.add(proxy)
        if kill_host:
            self.bad_hosts.add(self._host(proxy))

    def __len__(self) -> int:
        return len(self.base_proxies)

    def alive_hosts(self) -> int:
        hosts = {self._host(p) for p in self.base_proxies}
        return len(hosts - self.bad_hosts)


def is_proxy_dead_error(err: str) -> bool:
    err = err.lower()
    keys = (
        "timed out", "timeout", "connection refused", "network is unreachable",
        "tunnel connection failed", "proxy error", "503", "407", "errno",
        "reset by peer", "temporarily unavailable", "connection aborted",
        "name or service not known", "nodename nor servname", "broken pipe",
        "cannot connect to proxy", "max retries", "ssl:",
    )
    return any(k in err for k in keys)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="LovableZone key grabber — proxy rotation + optional random port"
    )
    ap.add_argument("-n", "--count", type=int, default=10, help="requests (default 10)")
    ap.add_argument("-d", "--delay", type=float, default=2.0, help="base delay seconds")
    ap.add_argument("-o", "--output", type=str, default=str(DEFAULT_OUT), help="license.txt path")
    ap.add_argument("-p", "--proxy-file", type=str, default=str(DEFAULT_PROXY_FILE), help="proxy list file")
    ap.add_argument(
        "--proxy-scheme",
        type=str,
        default="http",
        choices=["http", "https", "socks5", "socks4"],
        help="default scheme when line has no scheme",
    )
    ap.add_argument("--number", type=str, default=None, help="fixed WhatsApp e.g. +8801541204552")
    ap.add_argument("--no-proxy", action="store_true", help="direct connection only")

    # ---- random port feature (ON / OFF) ----
    ap.add_argument(
        "--random-port",
        action="store_true",
        default=False,
        help="ON: randomize port on IP:PORT proxies only (skipped for user:pass / gateway hosts). Default OFF",
    )
    ap.add_argument(
        "--no-random-port",
        action="store_true",
        help="explicitly force random-port OFF",
    )
    ap.add_argument(
        "--ports",
        type=str,
        default="",
        help="comma-separated port list for --random-port (default built-in list)",
    )

    ap.add_argument("--max-proxy-retries", type=int, default=4, help="retries per attempt on dead proxy")
    ap.add_argument("--dedupe", action="store_true", default=True, help="skip saving duplicate keys (default on)")
    ap.add_argument("--no-dedupe", action="store_true", help="allow duplicate keys in license.txt")
    ap.add_argument("-v", "--verbose", action="store_true", help="print hw / deviceId each try")
    args = ap.parse_args()

    random_port = bool(args.random_port) and not bool(args.no_random_port)
    port_list = RANDOM_PORTS
    if args.ports.strip():
        port_list = []
        for x in args.ports.split(","):
            x = x.strip()
            if x.isdigit():
                port_list.append(int(x))
        if not port_list:
            port_list = RANDOM_PORTS

    out = Path(args.output)
    proxy_path = Path(args.proxy_file)
    proxies: list[str] = []
    if not args.no_proxy:
        proxies = load_proxies(proxy_path, default_scheme=args.proxy_scheme)

    pool = ProxyPool(proxies, random_port=random_port, port_list=port_list)
    dedupe = args.dedupe and not args.no_dedupe
    seen_keys = load_existing_keys(out) if dedupe else None

    print(f"[*] endpoint     : {ENDPOINT}")
    print(f"[*] count        : {args.count}")
    print(f"[*] base delay   : {args.delay}s (dynamic)")
    print(f"[*] output       : {out}")
    print(f"[*] proxy file   : {proxy_path}  ({len(pool)} loaded)")
    print(f"[*] random-port  : {'ON' if random_port else 'OFF'}"
          + (f"  ports={port_list[:8]}{'...' if len(port_list) > 8 else ''}" if random_port else ""))
    print(f"[*] dedupe keys  : {'ON' if dedupe else 'OFF'}")
    if pool:
        print(f"[*] sample proxy : {proxy_label(pool.base_proxies[0])}")
    else:
        print("[!] no proxies — direct IP (24h free-key limit per IP)")
    print(f"[*] rotates      : proxy{' +port' if random_port else ''}, deviceId, hw, UA, lang, cookies, WhatsApp")
    if random_port and pool:
        authish = 0
        for u in pool.base_proxies:
            pu = urlparse(u)
            if pu.username or any(x in (pu.hostname or "").lower() for x in ("gate.", "decodo", "bright", "oxy", "resi")):
                authish += 1
        if authish:
            print(f"[!] note         : {authish}/{len(pool)} proxies look like auth gateways — random-port auto-skipped for those")
    print("-" * 64)

    saved = 0
    for i in range(1, args.count + 1):
        res = None
        used_proxy = None
        tries = max(1, args.max_proxy_retries if pool else 1)
        last_dead = False

        for attempt in range(tries):
            used_proxy = pool.next() if pool else None
            session = FingerprintSession(proxy_url=used_proxy)
            res = session.post(whatsapp=args.number)

            err = res.get("error") or ""
            if is_proxy_dead_error(err) and used_proxy:
                # if random-port: only mark this host:port bad, keep host
                # after many port fails on same host, kill host
                kill_host = (not random_port) or (attempt >= tries - 1)
                pool.mark_bad(used_proxy, kill_host=kill_host)
                last_dead = True
                print(
                    f"[{i}/{args.count}] dead {proxy_label(used_proxy)} "
                    f"-> retry ({pool.alive_hosts()} hosts alive)"
                )
                continue
            last_dead = False
            break

        assert res is not None
        rate_limited = bool(res.get("error") and "24 hours" in str(res.get("error")))

        if args.verbose:
            print(f"         hw={res.get('hw')} device={res.get('device_id')}")

        if res.get("key"):
            wrote = append_license(
                out,
                res["whatsapp"],
                res["key"],
                res.get("name"),
                res.get("reused"),
                res.get("proxy", "direct"),
                seen_keys,
            )
            if wrote:
                saved += 1
                print(
                    f"[{i}/{args.count}] OK  {res['whatsapp']} -> {res['key']}  "
                    f"| {res.get('name')} | {res.get('proxy')}"
                )
            else:
                print(
                    f"[{i}/{args.count}] DUP {res['whatsapp']} -> {res['key']} (skipped)"
                )
        else:
            print(
                f"[{i}/{args.count}] FAIL {res.get('whatsapp')} | {res.get('error')} | {res.get('proxy')}"
            )

        if i < args.count:
            wait = dynamic_wait(
                args.delay,
                i,
                success=bool(res.get("key")),
                rate_limited=rate_limited,
                proxy_dead=last_dead,
            )
            time.sleep(wait)

    print("-" * 64)
    print(f"[*] saved {saved}/{args.count} -> {out}")
    print(f"[*] proxy hosts alive: {pool.alive_hosts()}/{len(pool)}")


if __name__ == "__main__":
    main()
