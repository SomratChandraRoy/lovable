# LovableZone Key Grabber

Python tool that requests free-trial license keys from `lovablezone.xyz` by POSTing the same `_serverFn` endpoint the website uses. Each request uses a random BD WhatsApp number + rotated device fingerprint. Optional proxy rotation for multiple exit IPs.

## Files

| File | Purpose |
|------|---------|
| `lovablezone_key_grabber.py` | Main script |
| `proxy.txt` | Your proxy list (one per line) |
| `license.txt` | Output: WhatsApp, key, name, proxy |

## Requirements

- Python 3.9+
- For **SOCKS5** proxies (Decodo, etc.):

```bash
pip install PySocks
```

## proxy.txt formats

Any of these (mixed OK). Lines starting with `#` are ignored.

```text
ip:port
ip:port:user:pass
user:pass@ip:port
http://ip:port
http://user:pass@ip:port
socks5://user:pass@host:port
socks5h://user:pass@gate.decodo.com:10000
```

**Decodo example (use real username and password):**

```text
socks5://YOUR_USER:YOUR_PASS@gate.decodo.com:10000
```

If scheme is missing, set it with `--proxy-scheme socks5`.

## Basic usage

```powershell
# Direct (no proxy) — 1 free key per public IP / 24h
python lovablezone_key_grabber.py -n 5 -d 2 --no-proxy

# With proxy file (HTTP)
python lovablezone_key_grabber.py -n 20 -d 2 -p proxy.txt

# Decodo / SOCKS5 — RECOMMENDED default for your setup
python lovablezone_key_grabber.py -n 30 -d 2 -p proxy.txt --proxy-scheme socks5
```

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `-n / --count` | 10 | How many requests |
| `-d / --delay` | 2 | Base delay (actual wait is dynamic) |
| `-o / --output` | `license.txt` | Where keys are saved |
| `-p / --proxy-file` | `proxy.txt` | Proxy list path |
| `--proxy-scheme` | `http` | Scheme if line has none (`http`/`socks5`/`socks4`) |
| `--number` | random | Fixed WhatsApp like `+8801541204552` |
| `--no-proxy` | off | Ignore proxy file, use your IP |
| `--random-port` | **OFF** | Randomize port on plain `ip:port` only |
| `--session-rot` | **OFF** | Rewrite username session-id on gateways |
| `--session-format` | `{user}-session-{sess}` | Pattern for `--session-rot` |
| `--ports` | built-in list | Custom ports for `--random-port` |
| `--max-proxy-retries` | 4 | Retries on dead proxy per attempt |
| `--dedupe` | ON | Skip duplicate keys already in license.txt |
| `--no-dedupe` | | Allow duplicate keys |
| `-v / --verbose` | off | Print device fingerprint each try |

## Important: Decodo / auth gateways

### Why `SOCKS5 authentication failed` happened

`--session-rot` (or older builds that always rewrote the username) changed:

```text
YOUR_USER:PASS@gate.decodo.com:10000
```

into:

```text
YOUR_USER-session-abc123:PASS@gate.decodo.com:10000
```

Decodo then rejected the modified username → **authentication failed**.

### Correct settings for Decodo

```powershell
python lovablezone_key_grabber.py -n 30 -d 2 -p proxy.txt --proxy-scheme socks5
```

- Do **not** use `--session-rot` unless you know Decodo’s exact session username format.
- Do **not** use `--random-port` for Decodo (port `10000` is fixed).

### How to get new exit IPs on Decodo

1. **Multiple endpoints / ports from dashboard** — put each as its own line in `proxy.txt` (e.g. different ports or backconnect hosts).
2. **Provider session format** — if Decodo docs say username must be like `user-session-ID` or `user-country-us-session-ID`, enable:

```powershell
python lovablezone_key_grabber.py -n 30 -p proxy.txt --proxy-scheme socks5 --session-rot --session-format "{user}-session-{sess}"
```

Or country sticky example:

```powershell
--session-rot --session-format "{user}-country-us-session-{sess}"
```

Only enable this after confirming the format in your Decodo dashboard/docs. Wrong format = auth failed.

3. **More proxy lines** — 10 different Decodo credentials/endpoints ≈ more independent IPs.

## Site limits (what the server checks)

| Check | Notes |
|-------|--------|
| Client IP | ~1 free key per IP / 24 hours |
| WhatsApp number | Bound to issued key; reused number may return same key |
| deviceId + hw | Rotated every request by the script |
| Headers / UA | Rotated every request |

Proxies exist so each request can appear from a **different IP**. Fingerprint rotation alone is not enough after the IP quota is used.

## Output format (`license.txt`)

```text
+8801XXXXXXXXX    LOVABLEZONE-XXXX-XXXX-XXXX    Free Trial ....    reused=False    proxy=socks5h://auth@host:port
```

## Typical workflow

1. Put working proxies in `proxy.txt` (real user/pass).
2. `pip install PySocks` if using SOCKS.
3. Run without session-rot first and confirm OK keys.
4. If you hit `24 hours` on every line, you need **more distinct exit IPs** (more proxies or provider session rotation with correct format).
5. Keys accumulate in `license.txt` (duplicates skipped by default).

## Troubleshooting

| Error | Fix |
|-------|-----|
| `SOCKS5 authentication failed` | Username/password wrong, or `--session-rot` broke username — turn session-rot OFF |
| `connection timed out` | Dead proxy / wrong port — script marks dead and retries |
| `24 hours` rate limit | Same exit IP used again — need new IP (more proxies or valid session-rot) |
| `No proxies loaded` | Empty/invalid `proxy.txt` — check formats |
| `PySocks` / SOCKS errors | `pip install PySocks` |
| `--random-port` unrecognized | Old script file — re-download latest `lovablezone_key_grabber.py` |

## Safe default command (your setup)

```powershell
python lovablezone_key_grabber.py -n 30 -d 2 -p proxy.txt --proxy-scheme socks5
```
