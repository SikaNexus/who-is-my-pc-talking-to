#!/usr/bin/env python3
"""
WHO IS MY PC TALKING TO?  -  by Sika Nexus

A live dashboard that shows every internet connection your own computer makes,
which app owns it, and where in the world it goes.

    pip install psutil
    python who_is_my_pc_talking_to.py

Then open http://127.0.0.1:8765 (it opens automatically).

PRIVACY - read this:
  * The dashboard only listens on 127.0.0.1 (your own machine). Nobody else can open it.
  * To place connections on the map, the remote IP addresses your PC talks to are sent to
    the free service ip-api.com (plain HTTP, no account). Your own public IP is also seen
    by that service, as with any web request. Use --no-geo to disable it completely
    (you still get the live list, just no map).
  * Nothing is written to disk. Reverse hostname lookups use your system DNS resolver
    and can send the remote IP to that resolver.

Options:
    --port N        port to use (default 8765)
    --no-geo        never contact ip-api.com
    --no-browser    do not open the browser automatically
    --demo          show sample connections and locations
"""
import argparse
import ipaddress
import json
import random
import secrets
import socket
import sys
import threading
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

try:
    import psutil
except ImportError:
    sys.exit("Missing dependency. Run:  pip install psutil")

HOST = "127.0.0.1"
GEO_URL = "http://ip-api.com/batch?fields=status,country,countryCode,city,lat,lon,org,isp,query"
ORIGIN_URL = "http://ip-api.com/json/?fields=status,country,countryCode,city,lat,lon,query"
POLL_CACHE_SECONDS = 1.0

# ------------------------------------------------------------------ shared state
lock = threading.Lock()
geo_cache = {}        # ip -> dict(cc, country, city, lat, lon, org)  or {"fail": True}
geo_pending = set()
dns_cache = {}        # ip -> hostname ("" if none)
dns_started = set()
proc_names = {}       # pid -> name
origin = {"info": None, "tries": 0}
geo_state = {"fail": 0}   # consecutive failed requests to ip-api.com
dns_pool = ThreadPoolExecutor(max_workers=8)
snap_cache = {"t": 0.0, "data": None}


# --------------------------------------------------------------------- scanning
def proc_name(pid):
    if pid is None:
        return "unknown"
    n = proc_names.get(pid)
    if n is None:
        try:
            n = psutil.Process(pid).name()
        except (psutil.Error, OSError):
            n = "pid %d" % pid
        if n.lower().endswith(".exe"):
            n = n[:-4]
        proc_names[pid] = n
    return n


def raw_connections():
    """Yield (pid, raddr_ip, raddr_port, proto) for every connection that has a remote end."""
    try:
        conns = psutil.net_connections(kind="inet")
        for c in conns:
            yield c.pid, c
        return
    except (psutil.AccessDenied, PermissionError):
        pass
    # macOS without root: ask each process for its own connections
    for p in psutil.process_iter():
        try:
            fn = getattr(p, "net_connections", None) or p.connections
            for c in fn(kind="inet"):
                yield p.pid, c
        except (psutil.Error, OSError):
            continue


def scan_real():
    rows, local = [], 0
    for pid, c in raw_connections():
        if not c.raddr:
            continue
        proto = "UDP" if c.type == socket.SOCK_DGRAM else "TCP"
        if proto == "TCP" and c.status != psutil.CONN_ESTABLISHED:
            continue
        ip_s = c.raddr.ip.split("%")[0]
        try:
            ip = ipaddress.ip_address(ip_s)
        except ValueError:
            continue
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        if not ip.is_global:
            local += 1
            continue
        rows.append({"proc": proc_name(pid), "pid": pid, "ip": str(ip), "port": c.raddr.port, "proto": proto})
    return rows, local


DEMO_DESTS = [
    ("US", "United States", "Ashburn", 39.04, -77.49, "Example Cloud A"),
    ("US", "United States", "San Jose", 37.34, -121.89, "Example CDN B"),
    ("IE", "Ireland", "Dublin", 53.35, -6.26, "Example Cloud C"),
    ("DE", "Germany", "Frankfurt", 50.11, 8.68, "Example CDN B"),
    ("NL", "Netherlands", "Amsterdam", 52.37, 4.90, "Example Hosting D"),
    ("GB", "United Kingdom", "London", 51.51, -0.13, "Example Cloud A"),
    ("FR", "France", "Paris", 48.86, 2.35, "Example Hosting E"),
    ("JP", "Japan", "Tokyo", 35.68, 139.69, "Example Cloud C"),
    ("SG", "Singapore", "Singapore", 1.35, 103.82, "Example Cloud A"),
    ("BR", "Brazil", "Sao Paulo", -23.55, -46.63, "Example CDN B"),
    ("AU", "Australia", "Sydney", -33.87, 151.21, "Example Cloud C"),
    ("IN", "India", "Mumbai", 19.08, 72.88, "Example Hosting D"),
    ("AE", "United Arab Emirates", "Dubai", 25.20, 55.27, "Example Cloud A"),
    ("ZA", "South Africa", "Johannesburg", -26.20, 28.05, "Example CDN B"),
]
DEMO_APPS = ["browser", "chat-app", "game-launcher", "music-app", "code-editor", "cloud-sync", "python", "system"]


def scan_demo():
    rnd = random.Random(int(time.time() // 7))
    rows = []
    for app in DEMO_APPS:
        for _ in range(rnd.randint(2, 6)):
            d = rnd.randrange(len(DEMO_DESTS))
            ip = "203.0.113.%d" % (d * 10 + rnd.randint(1, 9))   # TEST-NET-3, reserved for documentation
            rows.append({"proc": app, "pid": 1000 + DEMO_APPS.index(app), "ip": ip, "port": rnd.choice([443, 443, 443, 80, 5228]), "proto": "TCP"})
    return rows, rnd.randint(3, 12)


# ---------------------------------------------------------------- lookups (background)
def resolve_dns(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        name = ""
    dns_cache[ip] = name


def http_json(url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = Request(url, data=data, headers={"User-Agent": "sika-nexus-who-is-my-pc-talking-to/1.0", "Content-Type": "application/json"})
    with urlopen(req, timeout=6) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def geo_worker(args):
    while True:
        try:
            if origin["info"] is None and origin["tries"] < 5:
                origin["tries"] += 1
                try:
                    o = http_json(ORIGIN_URL)
                    if o.get("status") == "success":
                        origin["info"] = {"lat": o["lat"], "lon": o["lon"], "city": o.get("city", ""), "country": o.get("country", "")}
                except Exception:
                    geo_state["fail"] += 1
            with lock:
                batch = [ip for ip in list(geo_pending)[:100]]
                for ip in batch:
                    geo_pending.discard(ip)
            if batch:
                try:
                    res = http_json(GEO_URL, batch)
                except Exception:
                    geo_state["fail"] += 1
                    with lock:
                        geo_pending.update(batch)
                    time.sleep(20)
                    continue
                geo_state["fail"] = 0
                for item in res:
                    ip = item.get("query")
                    if not ip:
                        continue
                    if item.get("status") == "success":
                        geo_cache[ip] = {"cc": item.get("countryCode", "??"), "country": item.get("country", ""),
                                         "city": item.get("city", ""), "lat": item["lat"], "lon": item["lon"],
                                         "org": item.get("org") or item.get("isp") or ""}
                    else:
                        geo_cache[ip] = {"fail": True}
        except Exception:
            time.sleep(10)
        time.sleep(5)   # ip-api free tier allows 15 batch requests per minute


def snapshot(args):
    now = time.time()
    if snap_cache["data"] is not None and now - snap_cache["t"] < POLL_CACHE_SECONDS:
        return snap_cache["data"]
    rows, local = scan_demo() if args.demo else scan_real()
    out = []
    pending = 0
    for r in rows:
        ip = r["ip"]
        if args.demo:
            d = DEMO_DESTS[(int(ip.split(".")[-1]) // 10) % len(DEMO_DESTS)]
            geo = {"cc": d[0], "country": d[1], "city": d[2], "lat": d[3], "lon": d[4], "org": d[5]}
            host = ""
        else:
            if ip not in dns_started:
                dns_started.add(ip)
                dns_pool.submit(resolve_dns, ip)
            host = dns_cache.get(ip, "")
            geo = None
            if not args.no_geo:
                g = geo_cache.get(ip)
                if g is None:
                    pending += 1
                    with lock:
                        geo_pending.add(ip)
                elif not g.get("fail"):
                    geo = g
        out.append({"proc": r["proc"], "pid": r["pid"], "ip": ip, "port": r["port"], "proto": r["proto"], "host": host, "geo": geo})
    data = {
        "ts": now,
        "demo": bool(args.demo),
        "geo_enabled": (not args.no_geo) and not bool(args.demo),
        # Use a neutral offshore point in demo mode; never imply the user's location.
        "origin": {"lat": 0.0, "lon": -30.0, "city": "", "country": ""} if args.demo else origin["info"],
        "local_count": local,
        "pending": pending,
        "geo_unreachable": geo_state["fail"] >= 2,
        "connections": out,
    }
    snap_cache.update(t=now, data=data)
    return data


# ------------------------------------------------------------------------ server
class Handler(BaseHTTPRequestHandler):
    server_version = "SikaNexus"
    sys_version = ""
    args = None
    allowed_hosts = set()

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype, extra=None):
        b = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        # Block DNS-rebinding: only answer requests addressed to localhost / 127.0.0.1
        if (self.headers.get("Host") or "").lower() not in self.allowed_hosts:
            return self._send(403, "Forbidden", "text/plain; charset=utf-8")
        path = self.path.split("?", 1)[0]
        if path == "/":
            nonce = secrets.token_urlsafe(16)
            csp = ("default-src 'none'; script-src 'nonce-%s'; style-src 'nonce-%s'; connect-src 'self'; "
                   "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" % (nonce, nonce))
            html = PAGE.replace("__NONCE__", nonce)
            return self._send(200, html, "text/html; charset=utf-8", {"Content-Security-Policy": csp})
        if path == "/api/connections":
            return self._send(200, json.dumps(snapshot(self.args)), "application/json; charset=utf-8")
        return self._send(404, "Not found", "text/plain; charset=utf-8")

    def do_POST(self):
        if (self.headers.get("Host") or "").lower() not in self.allowed_hosts:
            return self._send(403, "Forbidden", "text/plain; charset=utf-8")
        origin = (self.headers.get("Origin") or "").lower()
        if origin not in ("http://127.0.0.1:%d" % self.server.server_port, "http://localhost:%d" % self.server.server_port):
            return self._send(403, "Forbidden", "text/plain; charset=utf-8")
        if self.path.split("?", 1)[0] != "/shutdown":
            return self._send(404, "Not found", "text/plain; charset=utf-8")
        self._send(200, "Dashboard stopped. You can close this tab.", "text/plain; charset=utf-8")
        threading.Thread(target=self.server.shutdown, daemon=True).start()


def main():
    ap = argparse.ArgumentParser(description="Live map of every connection your PC makes.")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-geo", action="store_true", help="never contact ip-api.com; live scans show the list without a map")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--demo", action="store_true", help="fake sample data")
    args = ap.parse_args()
    if not 1 <= args.port <= 65535:
        ap.error("--port must be between 1 and 65535")

    Handler.args = args
    Handler.allowed_hosts = {"%s:%d" % (HOST, args.port), "localhost:%d" % args.port}
    try:
        srv = ThreadingHTTPServer((HOST, args.port), Handler)
    except OSError as e:
        sys.exit("Cannot start on port %d (%s). Try --port 8800" % (args.port, e))

    if not args.demo and not args.no_geo:
        threading.Thread(target=geo_worker, args=(args,), daemon=True).start()

    url = "http://%s:%d" % (HOST, args.port)
    print("")
    print("  WHO IS MY PC TALKING TO?  -  Sika Nexus")
    print("  Dashboard: " + url + "   (only reachable from this computer)")
    if args.demo:
        print("  DEMO MODE: all data is fake.")
    elif args.no_geo:
        print("  Geo lookup is OFF. No requests are sent to ip-api.com.")
    else:
        print("  Heads-up: to draw the map, the remote IPs your PC connects to are sent to")
        print("  ip-api.com (plain HTTP). Use --no-geo to disable.")
    print("  Press Ctrl+C to stop.")
    print("")
    if not args.no_browser:
        threading.Timer(0.8, webbrowser.open, [url]).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
    finally:
        srv.server_close()
        dns_pool.shutdown(wait=False, cancel_futures=True)


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Who is my PC talking to? - Sika Nexus</title>
<style nonce="__NONCE__">
:root{--bg:#030817;--panel:#071230;--line:#12306e;--cyan:#00d4ff;--blue:#2f6bff;--text:#d7e4ff;--dim:#6f86b8;--warn:#ffb020}
*{box-sizing:border-box}
html,body{margin:0;height:100%;background:var(--bg);color:var(--text);font:13px/1.4 system-ui,Segoe UI,Roboto,sans-serif;overflow:hidden}
.mono{font-family:Consolas,"SF Mono",Menlo,monospace}
#app{display:grid;grid-template-columns:1fr 310px;grid-template-rows:auto 1fr 210px auto;height:100vh;
  background:radial-gradient(1200px 600px at 40% 20%,#0a1a45 0%,var(--bg) 70%)}
header{grid-column:1/3;display:flex;align-items:center;gap:18px;padding:10px 18px;border-bottom:1px solid var(--line);background:rgba(3,8,23,.7)}
.brand{font-weight:800;letter-spacing:.12em;font-size:15px}
.brand b{color:var(--cyan)}
.title{flex:1;text-align:center;letter-spacing:.28em;font-size:12px;color:var(--dim);text-transform:uppercase}
#status{padding:3px 10px;border:1px solid var(--cyan);border-radius:999px;color:var(--cyan);font-size:11px;letter-spacing:.15em}
#stop{border:1px solid #ff4d6d;border-radius:6px;background:transparent;color:#ff7387;padding:5px 9px;cursor:pointer;font:inherit;font-size:11px}#stop:hover{background:#4a1728}
#status.off{border-color:#ff4d6d;color:#ff4d6d}
#status.paused{border-color:var(--warn);color:var(--warn)}
#status.demo{border-color:var(--warn);color:var(--warn)}
#mapwrap{grid-column:1;grid-row:2;position:relative;min-height:0}
#map{width:100%;height:100%;display:block}
#land{fill:#0b1f4d;stroke:#2a62e8;stroke-width:.25;stroke-opacity:.8}
.grat{stroke:#16336f;stroke-width:.15;opacity:.6}
path.base{fill:none;stroke-width:.35;opacity:.28}
path.arc{fill:none;stroke-width:.8;stroke-linecap:round;stroke-dasharray:1.5 7;animation:flow 1.1s linear infinite}
@keyframes flow{to{stroke-dashoffset:-17}}
.ring{transform-box:fill-box;transform-origin:center;animation:pulse 2.2s ease-out infinite;fill:none;stroke-width:.4}
@keyframes pulse{0%{transform:scale(.5);opacity:.9}100%{transform:scale(3.2);opacity:0}}
.dim{opacity:.07}
.dot{cursor:pointer}
#stats{position:absolute;left:14px;top:12px;display:flex;gap:10px}
.stat{background:rgba(7,18,48,.82);border:1px solid var(--line);border-radius:8px;padding:6px 12px;min-width:92px}
.stat b{display:block;font-size:22px;color:var(--cyan);font-family:Consolas,"SF Mono",Menlo,monospace}
.stat span{font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--dim)}
#note{position:absolute;left:14px;bottom:10px;color:var(--warn);font-size:12px;max-width:60%}
#tip{position:fixed;pointer-events:none;display:none;background:rgba(3,8,23,.95);border:1px solid var(--blue);border-radius:8px;padding:8px 10px;max-width:340px;z-index:10;box-shadow:0 0 24px rgba(47,107,255,.35)}
#tip h4{margin:0 0 4px;color:var(--cyan);font-size:13px}
#tip div{color:var(--text);font-size:12px}
#tip .d{color:var(--dim)}
#side{grid-column:2;grid-row:2/4;border-left:1px solid var(--line);background:rgba(7,18,48,.55);overflow:auto;padding:12px}
#side h2{margin:0 0 8px;font-size:11px;letter-spacing:.22em;color:var(--dim);text-transform:uppercase}
#apps{list-style:none;margin:0;padding:0}
#apps li{display:grid;grid-template-columns:10px 1fr auto;gap:8px;align-items:center;padding:7px 8px;border-radius:8px;cursor:pointer;border:1px solid transparent}
#apps li:hover{background:#0b1c4a}
#apps li.sel{border-color:var(--cyan);background:#0b1c4a}
.sw{width:10px;height:10px;border-radius:50%;box-shadow:0 0 8px currentColor;background:currentColor}
.an{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cnt{font-family:Consolas,monospace;color:var(--cyan)}
.cc{grid-column:2/4;color:var(--dim);font-size:11px;font-family:Consolas,monospace}
#tablewrap{grid-column:1;grid-row:3;overflow:auto;border-top:1px solid var(--line);background:rgba(3,8,23,.6)}
table{width:100%;border-collapse:collapse;font-size:12px}
th{position:sticky;top:0;background:#071230;text-align:left;padding:6px 10px;color:var(--dim);font-weight:600;letter-spacing:.1em;font-size:10px;text-transform:uppercase}
td{padding:4px 10px;border-top:1px solid #0c1d48;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:320px}
footer{grid-column:1/3;padding:6px 18px;border-top:1px solid var(--line);color:var(--dim);font-size:11px;display:flex;justify-content:space-between;gap:12px}
footer kbd{border:1px solid var(--line);border-radius:4px;padding:0 5px;color:var(--text)}
body.clean header,body.clean #side,body.clean #tablewrap,body.clean footer{display:none}
body.clean #app{grid-template-columns:1fr;grid-template-rows:1fr}
body.clean #mapwrap{grid-column:1;grid-row:1}
body.notable #tablewrap{display:none}
body.notable #app{grid-template-rows:auto 1fr 0 auto}
@media(max-width:900px){#app{grid-template-columns:minmax(0,1fr) 250px;grid-template-rows:auto minmax(220px,1fr) 190px auto}.brand{font-size:12px}.title{letter-spacing:.12em;font-size:10px}#stats{gap:5px}.stat{min-width:70px;padding:5px 8px}.stat b{font-size:18px}td{max-width:190px}}
@media(max-width:640px){html,body{overflow:auto;min-height:100%;height:auto}#app{height:auto;min-height:100vh;grid-template-columns:1fr;grid-template-rows:auto minmax(300px,55vh) auto minmax(200px,35vh) auto}header{grid-column:1;gap:8px;padding:9px}.title{display:none}#mapwrap{grid-column:1;grid-row:2}#side{grid-column:1;grid-row:3;border-left:0;border-top:1px solid var(--line);max-height:180px}#tablewrap{grid-column:1;grid-row:4}footer{grid-column:1;flex-wrap:wrap;padding:8px}#note{max-width:85%}#stats{left:8px;top:8px;flex-wrap:wrap}.stat{min-width:64px}.stat span{font-size:8px}table{font-size:11px}th,td{padding:5px 7px}}
</style>
</head>
<body>
<div id="app">
  <header>
    <div class="brand mono">SIKA <b>NEXUS</b></div>
    <div class="title">Who is my PC talking to?</div>
    <div id="status" class="mono">CONNECTING</div>
    <button id="stop" type="button" title="Stop the local dashboard">STOP</button>
  </header>
  <section id="mapwrap">
    <svg id="map" viewBox="0 0 1000 394.4" preserveAspectRatio="xMidYMid meet" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <filter id="glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="1.2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
      </defs>
      <g id="grat"></g>
      <path id="land" d="M1000.0,278.0 1000.0,279.3 996.5,280.6 996.1,279.6ZM994.8,282.0 995.5,281.5 996.4,282.3 996.0,283.8 994.3,284.1 992.7,283.8 992.5,282.6 993.5,281.6ZM594.2,236.0 604.7,241.9 604.9,243.5 608.9,246.3 607.6,249.7 607.8,251.3 609.6,252.3 608.9,254.7 608.9,256.9 611.0,261.4 612.0,262.0 609.8,263.6 606.7,264.7 605.1,264.6 604.1,265.5 601.4,265.9 598.1,265.1 596.0,265.3 595.2,261.6 593.7,259.5 591.0,259.0 585.4,256.5 583.9,253.0 582.3,251.4 581.7,249.8 582.0,248.4 581.5,245.8 582.6,245.7 585.4,242.7 584.6,240.0 585.4,239.7 585.6,238.1 584.5,236.5 585.5,236.2ZM475.9,156.5 475.9,161.4 466.8,161.3 466.8,168.4 464.2,168.7 463.6,170.1 464.1,174.1 453.2,174.1 452.6,175.0 452.7,173.8 459.0,173.6 460.5,171.4 461.4,167.5 465.3,164.5 466.6,161.0 467.4,160.8 468.4,158.7 470.7,158.4 473.0,158.7 473.9,158.1 475.6,158.0 475.5,156.5ZM158.8,97.2 151.0,93.3 146.0,92.1 144.5,89.7 144.9,88.0 141.3,86.8 140.8,84.6 137.5,82.5 137.4,81.1 138.9,79.8 138.9,78.0 134.1,76.2 129.6,71.1 125.2,68.7 123.7,67.3 120.9,68.2 118.2,69.7 113.8,66.7 111.1,65.9 108.3,65.8 108.4,39.7 120.8,41.9 123.3,40.8 126.6,39.9 130.8,40.3 134.9,39.0 139.5,38.4 141.4,39.5 143.4,38.9 144.1,37.5 146.0,37.8 150.7,40.3 154.4,38.4 154.8,40.6 158.2,40.1 159.2,39.3 162.6,39.5 166.8,40.6 173.3,41.6 177.1,42.1 179.9,41.9 183.6,43.3 179.7,44.7 184.7,45.3 192.2,45.0 194.6,44.5 197.6,46.2 200.6,44.8 197.7,43.6 199.5,42.6 205.1,42.2 210.2,44.4 213.3,44.2 218.2,45.4 226.5,45.1 226.2,43.3 228.7,42.8 233.0,43.8 233.0,46.4 234.8,44.2 237.0,44.3 238.2,41.5 235.3,39.8 232.0,38.6 232.2,35.6 235.5,33.6 239.2,34.0 242.0,35.2 245.8,38.4 243.3,39.7 248.5,40.3 248.5,43.1 252.2,40.9 255.5,42.7 254.7,44.8 257.4,46.7 260.3,44.7 262.3,42.3 262.4,39.2 270.5,39.8 274.2,41.2 274.4,42.6 272.3,44.1 274.3,45.6 273.9,46.9 268.5,48.9 264.6,49.3 261.8,48.4 260.9,49.8 257.4,53.4 254.2,55.3 250.2,55.5 248.0,56.6 247.9,58.4 244.6,58.8 241.2,61.0 238.2,64.2 237.1,66.4 237.0,69.6 241.1,70.0 243.6,74.8 247.5,74.2 252.7,75.4 255.4,76.5 257.4,77.8 263.9,79.7 271.5,80.1 271.0,82.5 271.9,85.3 273.9,88.5 278.0,91.1 280.2,90.2 281.7,87.3 280.2,82.9 278.3,81.5 282.7,80.2 285.8,78.2 287.4,76.3 287.2,74.4 285.3,72.1 281.9,70.0 285.2,67.1 284.0,64.6 283.0,60.2 285.0,59.6 292.6,60.6 294.9,59.9 300.9,62.4 301.7,63.5 306.7,63.7 306.6,66.1 307.5,69.6 310.1,70.0 312.1,71.6 316.1,70.1 318.8,67.0 320.6,65.7 329.5,75.1 328.3,76.8 332.0,78.4 334.5,80.0 339.0,80.7 340.7,81.6 341.8,83.9 344.0,84.3 345.1,85.4 345.3,88.5 341.3,90.5 336.7,91.5 333.2,93.8 328.5,94.2 322.6,93.6 315.6,93.8 313.2,95.8 309.7,97.0 302.5,103.3 304.8,102.8 309.3,99.2 315.1,96.9 319.3,96.6 321.7,97.9 319.1,99.8 320.9,104.9 324.5,106.3 329.1,105.9 331.9,102.8 332.1,104.8 333.9,105.8 330.4,107.6 321.5,110.4 318.4,112.4 316.3,112.2 316.2,109.8 321.0,107.5 313.5,108.0 311.7,106.4 311.7,102.6 310.5,101.8 308.6,102.3 307.7,101.5 305.6,103.6 303.7,107.1 301.7,107.6 301.4,108.3 292.0,108.3 287.5,111.1 286.6,112.1 281.3,112.2 280.1,112.6 280.7,114.3 277.1,115.6 274.2,116.1 271.0,117.6 269.1,116.7 271.8,112.3 270.7,107.4 267.8,106.1 268.1,105.6 267.0,105.2 266.3,104.1 265.0,104.3 265.2,104.1 264.5,103.8 264.2,103.1 254.5,99.2 252.0,99.9 247.7,99.2 245.4,99.6 242.7,98.8 238.0,98.1 237.1,97.7 236.6,96.1 235.7,96.2 235.7,97.2ZM266.7,59.9 268.7,58.6 272.6,58.6 272.5,59.1 269.3,60.7 267.3,60.6ZM278.4,31.1 275.3,29.6 275.5,28.6 276.8,28.4 283.2,28.7 287.9,30.3 288.2,31.0ZM276.9,60.9 278.0,60.0 279.1,60.1 279.8,60.7 278.7,62.1 277.5,61.9ZM240.0,25.1 238.5,26.1 234.4,25.9 231.1,25.2 232.5,24.0 236.5,23.2 239.0,24.2ZM239.3,18.0 232.9,17.9 232.1,17.1 237.7,17.2 239.7,17.7ZM231.2,14.5 234.6,15.5 233.8,16.5 229.7,17.1 227.4,16.4 226.2,15.4 226.0,14.2ZM255.1,26.7 243.3,25.5 242.0,22.5 239.2,21.3 233.4,21.0 230.2,20.1 231.3,19.0 237.0,19.2 240.1,20.1 245.5,20.1 247.9,21.0 247.3,22.0 252.3,23.3 260.1,23.7 264.5,23.1 274.6,23.0 277.6,24.1 278.2,25.2 276.5,26.0 272.4,26.5 268.8,26.2ZM190.9,16.2 194.8,16.7 193.9,17.5 188.7,18.3 184.6,17.4 186.9,16.5ZM191.8,14.4 195.4,15.0 192.0,15.5 187.4,15.5 187.4,15.1 190.3,14.3ZM345.6,90.8 342.2,95.0 344.0,94.0 345.9,94.6 344.9,95.6 347.4,96.4 348.7,95.7 351.5,96.5 350.6,98.6 352.5,98.1 353.8,101.3 352.6,103.7 349.5,103.3 350.1,101.0 349.3,100.7 346.1,103.1 344.5,103.0 346.4,101.7 343.7,101.0 335.4,101.1 334.9,100.3 336.7,99.3 335.5,98.5 337.8,96.9 340.7,92.4 342.4,90.9 344.8,89.9 346.1,90.0ZM267.0,52.5 273.2,54.3 273.5,55.6 275.5,55.4 277.5,56.3 275.0,57.2 270.7,56.5 269.1,55.3 262.4,58.2 261.5,56.6 257.7,56.8 260.1,55.5 261.4,50.7 263.4,51.0 264.0,52.2 265.4,51.7ZM281.2,32.4 283.8,31.3 293.8,34.0 294.2,35.2 299.3,34.6 302.2,36.3 308.9,37.4 311.3,38.6 314.0,41.1 308.9,42.4 315.4,44.3 319.8,44.9 323.8,47.4 328.2,47.6 327.3,49.6 322.4,52.8 319.0,51.6 314.7,48.9 311.1,49.3 310.7,50.9 318.6,54.5 320.4,57.2 319.4,59.2 308.9,56.3 315.8,60.3 316.2,61.3 308.7,60.2 302.7,58.6 299.3,57.2 300.3,56.4 292.1,53.7 292.2,54.5 284.1,54.9 281.8,54.0 283.6,51.9 294.6,51.5 293.6,50.5 294.6,49.1 298.2,46.4 296.4,44.3 292.1,42.9 286.5,42.0 288.3,41.3 285.3,39.5 282.9,39.4 280.7,38.4 279.2,39.2 274.2,39.6 264.0,39.0 253.7,37.7 251.4,36.8 254.3,35.5 250.3,35.5 249.4,32.7 251.6,30.2 254.4,29.1 261.6,28.3 259.5,30.1 261.7,31.8 264.3,29.6 271.3,28.5 276.1,31.3 275.7,33.2ZM237.5,27.4 243.3,27.5 248.6,28.2 244.4,30.6 241.1,31.2 238.1,33.3 235.0,33.2 233.2,30.7 233.3,29.3 234.7,28.2ZM158.7,21.9 163.5,19.8 169.2,18.0 177.2,17.7 176.8,19.8 174.7,20.7 162.5,22.5ZM131.4,83.2 134.0,83.0 133.2,86.2 135.6,88.4 134.5,88.4 130.4,85.0 129.9,83.7 130.1,82.9ZM207.0,13.1 219.9,14.4 223.1,16.9 218.6,16.6 214.0,15.7 207.8,15.6 210.5,14.8 207.2,14.1ZM156.9,98.6 155.5,99.0 151.0,97.7 150.1,96.7 147.6,95.7 147.1,95.0 144.3,94.5 143.2,92.9 143.4,92.3 150.7,93.6 153.0,95.9 155.8,97.0ZM162.4,26.5 166.4,27.1 173.5,27.3 179.1,29.2 168.8,31.9 165.4,33.8 165.4,35.0 158.1,36.4 156.6,35.2 150.2,33.7 155.7,28.7 153.0,27.0ZM200.5,22.7 203.0,22.2 205.9,22.3 206.4,23.7 204.7,25.0 195.3,25.4 188.3,26.6 184.0,26.7 183.7,25.8 189.5,24.5 176.9,24.9 173.0,24.4 176.8,21.7 179.4,20.9 187.2,21.8 192.2,23.5 197.0,23.7 193.1,21.0 195.6,20.0 198.5,20.3ZM204.1,30.3 207.2,31.5 209.8,36.1 219.5,38.8 219.2,40.0 214.6,40.3 216.4,41.3 215.5,42.4 205.7,41.2 197.2,42.3 185.2,43.0 183.7,41.6 179.9,40.9 177.5,41.2 174.1,39.0 187.7,37.9 182.4,37.2 172.5,37.4 171.0,36.4 177.5,35.3 173.2,35.3 168.3,34.6 172.6,31.4 180.0,29.7 182.9,30.2 181.5,31.5 187.7,30.7 191.5,32.1 194.7,30.7 197.2,31.6 199.5,34.3 200.9,33.2 198.9,30.3 201.3,29.9ZM221.0,31.4 217.9,29.6 221.2,28.2 224.5,28.8 229.5,28.4 230.2,29.3 227.6,30.6 231.8,31.8 231.3,34.3 226.8,35.4 224.1,35.1 222.2,34.1 215.3,31.9 215.3,31.0ZM203.9,28.9 207.6,28.8 209.7,29.4 207.3,31.2 202.9,29.3ZM226.4,20.2 228.5,21.5 228.6,22.9 227.3,25.0 222.8,25.3 219.8,24.8 219.8,23.2 215.3,23.4 215.1,21.3 218.1,21.4 222.3,20.4 226.2,20.6ZM233.3,9.4 235.2,8.6 238.1,8.4 236.8,7.8 243.3,7.6 246.9,9.1 256.1,10.2 258.3,12.1 261.6,13.0 257.8,13.8 252.7,15.9 242.0,15.7 239.0,14.6 239.1,13.6 241.3,12.8 236.2,12.9 233.1,11.9 231.4,10.7ZM245.6,5.8 258.4,4.8 262.5,3.7 265.9,3.9 268.9,4.7 271.1,3.2 279.7,2.4 289.7,2.6 297.7,2.1 317.1,2.7 328.2,3.8 328.1,4.6 312.1,6.9 318.1,6.9 307.0,9.4 302.3,11.7 296.5,12.1 294.8,12.7 286.4,13.0 290.2,13.3 288.3,13.8 290.6,15.2 287.9,16.2 283.6,16.9 282.3,18.0 278.4,18.9 278.8,19.5 283.6,19.4 283.6,20.1 276.2,21.7 269.0,21.0 260.8,21.4 251.4,20.9 251.1,19.6 256.2,18.9 254.8,16.9 256.5,16.7 264.0,17.9 260.2,16.2 255.7,15.6 257.9,14.6 262.8,13.9 263.6,12.9 259.7,11.8 258.5,10.4 268.3,10.8 272.6,9.8 256.7,9.7 251.8,8.7 249.4,7.6 246.2,6.8ZM291.1,46.0 289.3,46.8 286.1,46.9 285.5,45.6 286.6,44.0 289.2,43.6 291.3,44.4ZM232.6,40.3 234.3,41.4 232.6,42.3 228.8,41.5 226.6,41.8 222.8,40.6 227.2,38.5ZM320.8,94.8 321.7,94.6 325.4,95.3 328.2,96.4 328.3,96.9 323.4,96.1ZM322.2,102.7 323.2,104.0 327.7,104.3 326.4,105.5 325.3,105.6 321.8,104.5 321.1,103.5ZM158.8,97.2 235.7,97.2 235.7,96.2 236.6,96.1 237.1,97.7 238.0,98.1 242.7,98.8 245.4,99.6 247.7,99.2 252.0,99.9 254.5,99.2 264.2,103.1 264.5,103.8 265.2,104.1 265.0,104.3 266.3,104.1 267.0,105.2 268.1,105.6 267.8,106.1 270.7,107.4 271.8,112.3 269.1,116.4 269.4,117.1 270.3,117.6 280.7,114.3 280.1,112.6 281.3,112.2 286.6,112.1 287.5,111.1 292.0,108.3 301.4,108.3 301.7,107.6 303.7,107.1 305.6,103.6 307.7,101.5 308.6,102.3 310.5,101.8 311.7,102.6 311.7,106.4 314.0,108.9 305.2,112.0 303.3,114.3 303.3,115.7 304.2,117.2 305.3,117.3 305.0,116.3 305.9,116.9 305.7,117.7 297.6,118.8 295.2,119.6 299.3,119.1 300.2,119.6 296.3,120.5 294.5,120.5 294.6,120.1 293.7,120.9 294.5,121.0 293.9,123.0 291.9,125.2 291.7,124.5 290.2,123.6 290.8,125.1 291.5,125.6 291.5,126.7 289.1,130.0 289.7,128.0 288.2,126.9 287.9,124.6 287.4,125.8 288.0,127.5 286.1,127.1 288.1,128.0 288.2,130.6 289.0,130.8 289.6,134.6 287.9,136.6 285.0,137.5 283.2,139.1 281.8,139.3 280.4,140.3 280.0,141.2 276.9,143.0 274.1,146.0 273.6,148.0 274.1,149.9 276.3,154.2 276.3,155.4 277.6,158.7 277.4,161.6 276.7,163.3 275.9,163.7 274.5,163.3 274.1,162.1 273.0,161.5 269.8,155.9 270.4,154.0 269.6,152.5 267.5,150.2 266.4,149.7 263.6,151.0 261.7,149.6 260.0,148.9 256.9,149.2 254.4,148.9 251.1,149.6 251.6,150.3 251.6,151.4 252.2,152.0 251.6,152.3 250.6,151.9 249.6,152.5 247.6,152.4 245.5,150.9 243.1,151.2 241.0,150.6 237.0,151.4 234.4,153.5 231.7,154.7 230.2,156.0 229.5,157.3 229.5,159.2 230.2,161.5 229.1,161.6 224.9,160.1 223.6,156.8 221.9,155.2 219.6,151.7 217.6,150.6 215.3,150.7 213.6,152.9 211.3,152.0 209.8,151.2 208.2,148.2 204.1,145.1 199.3,145.1 199.3,146.3 191.6,146.3 181.1,143.0 181.3,142.4 174.6,143.0 174.2,141.5 172.4,139.9 171.1,139.6 170.8,138.8 169.2,138.7 168.2,137.9 165.6,137.6 164.9,137.2 164.6,135.7 161.9,132.9 159.6,129.0 159.7,128.4 156.3,125.1 155.9,122.9 154.4,121.4 155.1,119.0 155.0,116.7 154.1,114.5 155.2,111.9 155.8,106.9 155.3,103.2 153.6,99.5 154.0,98.9 158.0,99.9 159.5,102.5 160.2,101.8ZM68.3,177.6 70.0,179.1 67.5,180.8 66.8,180.4 66.5,178.6 67.1,177.8 67.1,177.0ZM66.7,175.7 65.5,176.2 64.7,175.2 65.0,175.0ZM61.0,173.0 61.9,174.3 60.8,174.1 60.3,173.4ZM37.6,65.6 39.8,65.9 40.1,66.9 38.4,67.3 34.8,66.1ZM74.4,72.3 76.2,72.5 77.4,73.4 72.2,75.7 70.8,75.0 70.4,73.7ZM108.4,39.7 108.3,65.8 111.1,65.9 113.8,66.7 118.2,69.7 120.9,68.2 123.7,67.3 125.2,68.7 129.6,71.1 134.1,76.2 138.9,78.0 138.9,79.8 137.4,81.1 133.4,79.2 132.6,76.8 129.1,74.5 127.6,71.9 120.5,71.6 117.2,70.8 111.5,68.0 104.0,66.4 100.1,66.7 91.3,64.2 88.3,64.8 88.8,66.7 84.1,67.5 78.6,69.0 78.2,67.4 79.4,64.7 82.4,63.8 81.6,63.1 78.1,64.6 76.2,66.5 72.2,68.5 74.2,69.8 71.6,71.8 65.8,73.8 65.1,75.1 60.8,76.5 59.9,77.8 56.7,79.0 54.8,78.8 47.0,81.4 42.3,82.2 41.8,81.7 50.5,78.1 54.0,77.8 55.4,76.6 59.2,75.0 61.9,73.4 62.4,71.3 63.8,69.7 60.6,70.5 59.7,70.0 58.2,71.0 56.4,69.6 55.6,70.6 54.6,69.2 51.8,70.4 50.1,70.4 49.8,68.7 50.3,67.7 48.6,66.7 44.9,67.2 40.7,65.3 40.7,63.7 38.6,62.5 39.6,60.9 41.9,59.4 42.9,57.9 45.1,57.7 47.0,58.2 49.3,56.8 51.3,57.1 53.4,56.2 52.9,54.9 51.3,54.4 53.4,53.4 48.7,54.0 47.9,54.6 45.7,54.0 41.8,54.3 37.7,53.6 36.5,52.5 33.0,50.9 43.1,48.4 45.4,48.4 45.0,49.8 50.9,49.7 48.6,48.0 45.2,46.9 40.6,44.3 36.8,43.4 38.3,42.0 43.2,41.9 46.8,40.6 47.4,39.3 50.3,38.0 58.2,36.4 60.8,36.6 65.1,35.1 69.3,35.7 71.3,37.0 72.5,36.4 77.2,36.6 77.0,37.2 81.3,37.7 84.1,37.4 97.4,38.9 101.1,38.5ZM23.0,56.2 24.7,56.7 26.4,56.4 31.4,57.5 29.1,58.4 25.9,57.3 23.5,57.5 22.8,57.2ZM742.7,96.6 740.6,98.5 738.2,98.7 738.1,101.5 736.6,102.8 731.1,101.9 729.1,106.8 722.1,108.6 724.6,113.4 722.7,114.1 722.9,115.7 721.2,115.3 719.8,114.3 711.1,113.9 710.1,114.2 706.1,113.1 704.6,113.6 704.1,115.3 699.6,114.3 697.7,114.7 697.1,115.9 691.9,118.4 690.6,120.4 689.6,120.4 688.8,119.1 685.3,119.0 684.8,116.7 683.4,116.7 683.6,113.9 680.3,111.9 672.3,112.5 669.6,110.0 662.5,106.7 655.4,108.3 655.5,118.6 654.0,118.7 652.1,116.5 650.2,115.8 647.1,116.3 645.8,117.3 645.7,116.6 646.4,115.4 645.8,114.5 642.6,113.5 641.4,111.0 639.8,110.3 639.7,109.4 642.4,109.7 642.5,107.7 644.9,107.2 647.3,107.6 647.8,104.9 647.3,103.2 644.6,103.3 642.2,102.6 636.4,104.4 635.0,104.0 635.3,102.6 633.5,100.7 631.4,100.8 629.1,98.9 630.7,96.8 629.9,96.2 632.1,93.2 634.9,94.8 635.3,92.8 641.0,89.7 645.4,89.7 654.8,92.7 657.7,91.5 662.1,91.5 665.7,92.9 666.5,92.1 670.4,92.2 671.1,90.9 666.6,89.0 669.2,87.6 668.7,86.9 671.4,86.2 669.4,84.3 670.7,83.3 681.1,82.3 682.4,81.7 689.4,80.6 691.9,79.5 696.8,80.1 697.7,83.0 700.6,82.3 704.2,83.2 704.0,84.8 706.6,84.6 713.6,82.0 712.6,82.8 716.1,85.0 722.3,92.0 723.8,90.6 727.6,92.2 731.6,91.5 733.2,92.0 734.5,93.6 736.4,94.1 737.6,95.3 741.2,94.9ZM655.5,118.6 655.4,108.3 662.5,106.7 669.6,110.0 672.3,112.5 680.3,111.9 683.6,113.9 683.4,116.7 684.8,116.7 685.3,119.0 688.8,119.1 689.6,120.4 690.6,120.4 691.9,118.4 697.1,115.9 697.9,116.2 695.6,118.0 697.7,119.0 699.6,118.4 702.9,119.8 699.4,121.8 696.1,121.6 695.7,120.8 696.3,119.6 692.6,120.2 690.4,123.5 688.1,123.4 687.3,124.6 689.4,125.3 690.0,127.3 688.4,130.2 684.8,129.5 684.9,127.8 678.3,125.3 673.3,122.1 671.9,119.2 671.0,118.7 668.0,118.8 666.9,118.3 666.6,116.0 662.9,114.6 660.5,116.2 658.1,117.1 658.6,118.5ZM891.7,240.6 901.6,244.1 905.1,246.9 905.5,248.5 910.1,250.2 910.8,251.7 908.3,252.0 908.9,253.9 911.3,255.7 913.2,258.6 914.7,258.5 914.6,259.8 916.8,260.2 915.9,260.8 918.9,261.9 918.6,262.7 916.7,262.9 916.1,262.2 910.9,261.5 907.1,258.2 905.7,255.7 902.1,254.5 898.0,256.2 898.4,258.3 896.2,259.2 891.8,258.7ZM924.0,243.5 925.1,244.4 925.4,245.8 924.5,246.6 923.4,243.9 920.5,241.8 918.5,240.9 919.3,240.3 922.9,242.3ZM920.3,249.6 917.3,250.9 915.9,250.9 912.0,249.3 912.2,248.4 914.7,248.8 916.2,248.6 916.7,247.3 917.1,247.2 917.3,248.7 918.9,248.5 921.2,246.5 920.9,244.9 922.6,244.9 923.2,245.3 923.1,246.9 922.2,248.6 920.7,248.8ZM929.9,248.2 933.4,251.5 933.0,252.3 932.2,252.6 931.0,251.5 929.8,249.7 929.2,247.6 929.6,247.3ZM891.7,240.6 891.8,258.7 889.3,256.4 886.5,255.8 885.8,256.6 882.3,256.7 883.4,254.4 885.2,253.7 884.5,250.6 883.1,248.3 877.7,246.0 875.5,245.7 871.3,243.2 870.5,244.5 869.4,244.8 868.8,243.7 868.8,242.5 866.6,241.2 869.6,240.2 871.6,240.2 871.4,239.5 867.3,239.5 866.2,237.8 863.7,237.3 862.6,235.9 866.3,235.3 867.7,234.4 872.2,235.5 873.4,241.0 876.3,242.7 878.6,239.7 881.8,238.1 884.2,238.1 888.7,240.0ZM847.1,258.0 847.5,259.4 845.7,261.5 843.3,262.1 842.9,261.8 844.4,259.1ZM872.8,252.5 872.5,250.4 873.6,248.5 874.2,249.3 874.2,250.6ZM827.5,221.8 825.9,224.3 827.9,227.0 827.4,228.3 830.5,230.8 827.3,231.2 826.3,233.0 826.4,235.6 823.8,237.5 823.7,240.2 822.6,244.5 822.2,243.5 819.1,244.7 818.0,243.0 816.0,242.9 814.6,242.0 811.3,243.0 810.3,241.7 806.2,241.5 805.8,237.8 804.4,237.0 803.0,234.6 802.6,232.2 803.0,229.6 804.6,227.8 805.1,229.6 807.0,231.2 808.8,230.6 810.5,230.8 812.2,229.4 813.5,229.2 816.1,230.0 818.4,229.4 819.8,225.5 820.9,224.5 821.8,221.4ZM859.4,241.1 862.4,241.9 863.4,244.1 861.1,242.9 855.3,242.8 855.9,241.2ZM852.4,243.9 850.5,243.4 850.0,242.2 852.8,242.0 853.5,242.9ZM855.4,227.3 855.6,228.8 857.2,229.1 857.5,230.2 857.3,232.6 855.9,232.3 855.5,234.0 856.6,235.5 855.8,235.8 854.7,234.1 853.9,230.5 854.4,228.3ZM841.5,230.9 844.7,230.8 847.4,228.8 847.9,229.4 845.7,232.1 843.6,232.7 840.9,232.1 833.8,232.7 833.4,234.8 835.9,237.2 837.4,236.0 842.6,235.0 842.4,236.3 841.2,235.9 840.0,237.5 837.5,238.6 840.2,242.2 839.6,243.1 842.1,246.3 842.1,248.2 840.6,249.0 839.5,248.0 840.9,245.7 838.2,246.8 837.5,246.0 837.8,245.0 835.8,243.3 836.0,240.6 834.2,241.5 834.5,248.7 832.8,249.1 831.6,248.3 832.4,245.7 831.9,243.0 830.8,243.0 829.9,241.1 831.1,239.3 832.8,232.9 833.4,231.8 835.8,229.7 838.0,230.5ZM834.2,261.8 830.5,259.9 833.1,259.3 835.5,261.0 835.3,261.8ZM837.1,257.0 838.9,256.8 841.4,255.8 841.0,257.4 836.8,258.1 833.1,257.8 833.1,256.8 835.3,256.2ZM828.5,256.6 830.2,256.3 830.9,257.5 824.3,258.4 825.2,256.8 826.8,256.8 827.5,255.8ZM801.4,251.2 801.7,252.2 807.1,252.4 807.7,251.3 812.8,252.6 813.8,254.4 818.0,254.9 821.4,256.6 818.2,257.6 815.2,256.5 809.8,256.4 804.0,254.8 801.9,254.6 800.8,254.9 795.7,253.8 795.2,252.6 792.7,252.4 794.6,249.7 798.0,249.9ZM789.9,236.3 790.4,238.3 791.4,239.8 793.4,240.1 794.7,241.8 794.0,245.3 793.9,249.6 790.9,249.6 788.5,247.3 785.0,245.1 781.7,241.1 778.2,235.1 775.7,232.8 773.9,228.3 771.4,226.5 769.9,224.1 764.9,219.5 764.7,218.1 770.8,218.8 779.6,227.5 782.4,227.5 784.7,229.4 786.3,231.8 788.4,233.0 787.3,235.3 788.9,236.3ZM309.3,379.5 311.8,382.9 315.4,384.6 319.3,385.3 318.1,386.7 315.4,386.8 314.0,385.8 309.4,385.7ZM339.9,317.3 338.5,322.3 338.5,325.1 337.9,325.7 337.5,329.0 341.0,331.4 340.7,333.3 342.4,334.5 342.3,335.8 339.6,339.4 335.5,340.9 329.9,341.5 326.8,341.2 327.4,342.8 326.9,344.9 327.4,346.3 325.7,347.3 322.9,347.7 320.2,346.7 319.1,347.4 319.5,350.2 321.4,351.0 322.9,350.1 323.7,351.6 321.2,352.4 318.9,354.2 317.9,358.4 315.3,358.4 313.1,359.9 312.3,361.9 315.0,364.0 317.7,364.5 316.7,367.0 313.4,368.6 311.6,371.9 309.1,373.0 307.9,374.3 308.8,377.1 310.7,378.7 300.2,377.8 299.1,376.2 299.1,374.1 297.3,374.3 296.3,373.3 296.1,370.3 298.2,369.1 299.1,367.3 298.8,365.9 300.2,363.6 301.2,359.9 300.9,358.3 302.2,357.7 301.9,356.7 300.6,356.1 301.5,355.0 300.2,353.9 299.6,350.7 300.7,350.1 300.2,346.8 301.6,341.4 303.3,340.4 302.4,337.7 302.4,335.2 304.5,333.3 304.5,331.0 306.1,328.3 306.1,325.8 305.3,325.3 304.1,320.5 305.8,317.6 305.5,314.9 306.5,312.4 308.3,309.8 310.3,308.1 309.5,307.0 310.0,306.1 310.0,301.4 313.0,300.1 313.9,297.2 313.6,296.5 315.9,294.0 319.5,294.7 321.2,296.7 322.3,294.4 325.4,294.5 331.0,299.7 333.3,300.1 336.6,302.1 339.5,303.2 339.9,304.5 337.2,308.7 343.1,309.9 345.3,309.4 347.8,307.3 348.3,304.8 349.6,304.3 351.0,305.9 351.0,308.1 346.8,310.8ZM309.3,379.5 309.4,385.7 314.0,385.8 313.1,386.9 310.7,387.8 302.8,386.3 296.4,383.2 292.6,380.1 302.5,383.5 303.9,382.3 304.8,380.4 307.4,379.2ZM306.7,282.2 308.1,284.1 308.4,286.1 309.9,287.2 309.0,289.9 310.5,293.0 311.6,296.9 313.6,296.5 313.9,297.2 313.0,300.1 310.0,301.4 310.0,306.1 309.5,307.0 310.3,308.1 308.3,309.8 306.5,312.4 305.5,314.9 305.8,317.6 304.1,320.5 305.3,325.3 306.1,325.8 306.1,328.3 304.5,331.0 304.5,333.3 302.4,335.2 302.4,337.7 303.3,340.4 301.6,341.4 300.2,346.8 300.7,350.1 299.6,350.7 300.2,353.9 301.5,355.0 300.6,356.1 301.9,356.7 302.2,357.7 300.9,358.3 301.2,359.9 300.2,363.6 298.8,365.9 299.1,367.3 298.2,369.1 296.1,370.3 296.3,373.3 297.3,374.3 299.1,374.1 299.1,376.2 300.2,377.8 309.5,378.6 307.1,378.6 303.2,380.3 302.8,382.9 301.6,382.9 298.5,382.0 291.8,378.5 290.9,376.7 291.7,375.1 290.3,373.3 290.0,368.5 291.2,365.9 294.1,363.7 289.9,362.9 292.5,360.5 293.5,355.8 296.6,356.8 298.0,351.1 296.1,350.3 295.3,353.8 293.5,353.4 295.3,344.3 296.6,342.4 295.8,339.7 295.6,336.5 296.8,336.5 300.4,327.5 301.6,323.4 300.9,319.2 301.7,316.9 301.4,313.5 303.0,310.1 305.3,292.8 304.5,284.3 305.9,283.6ZM581.5,245.8 582.0,248.4 581.7,249.8 582.3,251.4 583.9,253.0 585.4,256.5 584.3,256.2 579.8,257.0 579.0,258.8 579.6,260.0 578.8,266.1 581.5,267.7 582.3,267.2 582.5,270.2 580.4,270.1 578.2,267.4 576.1,267.0 575.5,265.6 573.8,266.5 571.5,266.1 570.6,264.8 567.5,264.6 567.4,263.8 565.2,263.5 561.5,264.1 561.7,260.8 560.8,259.8 560.6,258.1 561.0,256.4 560.4,255.3 560.4,253.6 557.0,253.6 557.2,252.6 555.8,252.6 555.7,253.1 553.9,253.2 552.8,255.5 551.3,255.1 548.5,255.7 546.8,253.4 545.4,249.7 537.2,249.6 534.2,250.3 533.8,249.4 534.5,249.1 535.1,247.2 536.1,246.6 536.8,246.9 537.8,245.8 539.3,245.9 539.5,246.6 540.5,247.1 544.5,243.2 544.4,240.9 545.6,238.2 548.7,235.4 549.0,234.5 549.5,232.5 549.7,228.5 551.1,225.3 551.5,221.7 552.6,220.3 554.1,219.4 558.1,221.3 562.2,222.1 563.4,220.2 564.7,220.5 567.8,219.1 568.9,219.7 569.8,219.6 570.2,219.0 571.3,218.7 575.1,219.1 576.0,218.8 577.7,221.1 579.0,221.4 582.5,220.6 583.2,221.7 585.6,223.6 585.5,226.8 586.6,227.2 584.6,228.9 583.0,231.7 582.8,233.9 582.2,235.0 582.2,237.1 581.4,237.8 580.6,241.2 581.3,242.5ZM615.5,238.0 613.9,235.7 613.8,225.6 617.0,221.6 618.8,221.5 621.3,219.6 624.9,219.4 632.7,211.1 635.9,207.1 636.0,201.6 639.6,200.9 640.9,199.9 642.0,199.9 641.8,203.8 640.4,207.8 637.4,214.4 635.0,218.5 629.3,225.4 619.8,232.5 616.8,235.9ZM608.9,246.3 604.9,243.5 604.7,241.9 594.2,236.0 594.1,233.0 597.3,228.0 595.8,223.5 594.5,221.5 598.1,218.0 599.5,218.5 599.5,220.1 600.4,221.0 602.4,221.0 605.9,223.3 609.9,223.8 610.7,222.7 613.2,221.5 614.4,222.4 616.3,222.4 613.8,225.6 613.9,235.7 615.5,238.0 613.6,239.1 612.9,240.3 611.8,240.5 611.4,242.4 610.6,243.6 610.0,245.4ZM568.2,210.5 565.2,208.5 565.4,205.3 563.8,203.6 563.5,201.7 562.5,200.9 562.5,199.3 561.9,198.2 560.9,198.4 561.9,196.2 561.6,195.0 562.5,194.2 562.0,193.5 564.0,189.8 566.4,190.0 566.3,177.8 569.4,177.8 569.4,172.2 602.4,172.2 603.3,174.9 602.7,175.5 603.1,178.3 604.1,181.6 606.7,183.3 605.3,184.9 603.2,185.4 602.4,186.2 600.9,192.2 601.2,193.3 600.8,195.7 599.6,198.4 597.9,199.8 596.5,203.0 595.2,203.8 594.3,206.7 594.4,209.2 594.3,207.0 594.0,207.0 593.7,204.7 592.2,203.6 591.9,201.6 592.2,199.5 591.0,199.3 590.8,199.9 589.1,200.1 589.8,200.9 590.0,202.6 587.1,206.1 585.7,206.4 583.3,204.7 582.3,205.3 582.0,206.1 580.6,206.7 580.5,207.2 577.7,207.2 577.3,206.7 575.3,206.6 574.3,207.0 573.5,206.8 571.6,204.4 569.6,204.8 568.2,208.6 566.4,209.4ZM566.2,178.9 566.4,190.0 564.0,189.8 562.0,193.5 562.5,194.2 561.6,195.0 561.9,196.2 560.9,198.4 561.9,198.2 562.5,199.3 562.5,200.9 563.5,201.7 563.5,202.4 561.8,202.9 560.3,204.0 558.3,207.0 555.7,208.3 552.3,208.4 552.5,209.4 549.9,211.4 546.4,212.5 545.3,211.8 544.7,212.5 542.4,212.7 542.9,212.0 541.6,208.9 540.4,208.4 538.8,206.8 539.4,205.5 543.0,205.6 541.5,203.1 541.4,199.4 540.3,197.6 540.5,196.3 538.8,196.2 538.8,194.5 537.6,193.4 538.8,189.8 542.4,187.1 542.5,183.5 543.6,177.9 544.2,176.7 543.0,175.7 543.0,174.9 541.9,174.1 541.3,169.8 544.1,168.3ZM300.8,178.6 300.8,181.2 300.2,181.6 300.9,182.5 300.8,183.2 299.0,182.7 296.0,182.7 294.7,183.2 293.2,182.4 293.4,181.5 298.1,182.1 299.1,181.5 297.8,180.3 297.8,179.2 296.1,178.8 296.7,178.0ZM300.8,183.2 300.9,182.5 300.2,181.6 300.8,181.2 300.8,178.6 301.1,178.1 303.3,178.1 305.7,178.8 306.2,179.7 307.7,179.7 307.6,180.5 308.9,180.6 310.2,181.6 309.2,182.8 307.9,182.2 305.7,182.1 304.1,182.8 303.7,182.1 302.8,182.5 301.7,184.4 301.0,184.0ZM1000.0,34.7 1000.0,36.6 997.0,36.7 996.5,35.8ZM635.1,106.1 632.4,106.6 629.7,109.4 632.2,112.1 631.9,113.9 635.0,117.2 632.8,119.0 631.6,118.8 629.7,117.1 627.2,116.4 626.3,115.3 623.7,114.7 622.0,115.1 621.5,114.6 617.8,113.3 611.3,112.4 611.0,112.7 607.4,110.3 604.3,109.3 601.9,107.7 603.9,107.2 606.2,104.9 604.6,103.8 608.7,102.7 608.7,102.0 606.2,102.5 606.3,101.3 607.7,100.5 610.4,100.3 610.8,99.4 610.2,97.8 611.3,96.4 611.3,95.6 605.6,94.7 603.9,93.4 601.7,93.8 598.2,92.8 598.3,92.3 597.3,91.1 595.1,91.0 594.8,90.1 595.5,89.5 593.8,88.0 590.0,88.1 589.3,88.7 588.3,88.6 587.0,85.9 589.7,85.7 590.8,85.1 590.0,84.4 588.1,83.9 588.3,83.4 587.2,82.9 585.4,81.1 586.0,80.3 585.8,79.0 583.0,78.4 581.6,78.7 581.2,78.0 578.3,77.3 577.1,74.3 575.8,73.7 577.0,72.8 576.2,70.2 578.1,68.6 577.7,68.1 580.9,66.6 578.0,65.3 586.5,60.1 587.5,58.7 583.4,56.8 584.6,55.0 582.1,52.9 583.9,50.5 580.7,47.4 583.3,45.3 579.0,43.4 579.4,41.5 589.3,39.2 593.8,40.8 601.4,41.5 611.9,44.6 614.1,46.0 614.2,47.8 611.2,49.3 606.6,50.0 594.2,47.9 592.2,48.2 596.7,50.3 597.1,54.4 602.8,56.0 603.2,54.6 601.5,53.4 603.3,52.4 610.0,54.1 612.3,53.4 610.5,51.4 616.9,48.7 619.5,48.8 622.1,49.8 623.7,47.9 621.4,46.2 622.7,44.6 620.7,42.9 628.5,43.8 630.1,45.3 626.5,45.6 626.6,47.2 628.7,48.1 633.0,47.5 633.7,45.8 649.2,42.1 651.3,42.2 648.6,43.9 652.0,44.2 654.0,43.2 659.2,43.1 663.3,42.0 666.5,43.7 669.7,41.8 666.8,40.2 668.2,39.3 676.4,40.1 690.3,44.2 692.2,42.7 689.3,41.3 689.3,40.7 685.9,40.4 686.8,39.1 685.3,36.9 685.3,36.0 690.4,33.5 692.2,31.0 694.3,30.4 701.6,31.2 702.2,32.7 699.6,35.0 701.3,35.9 702.2,37.8 701.6,41.6 704.6,43.3 703.4,45.2 698.0,49.1 701.2,49.5 702.3,48.5 705.3,47.8 706.1,46.4 708.5,45.1 706.9,43.5 708.2,41.7 705.1,41.5 704.4,39.9 706.7,37.1 703.1,34.9 708.0,33.0 707.4,31.0 708.8,31.0 710.2,32.5 709.1,35.2 712.1,35.7 710.8,33.7 715.5,32.6 721.3,32.4 726.4,34.0 723.9,31.7 723.6,28.8 728.5,28.2 741.2,28.0 738.9,26.5 742.1,24.7 745.3,24.6 750.7,23.2 758.1,22.9 759.0,22.1 766.3,21.8 768.6,22.5 774.8,21.0 779.9,21.0 780.7,19.8 783.3,18.6 789.9,17.5 794.6,18.4 790.8,19.1 797.1,19.5 797.9,20.9 800.4,20.2 808.5,20.2 814.8,21.6 817.0,22.6 816.3,24.1 806.0,26.5 803.9,27.3 811.4,28.4 813.9,27.8 815.4,29.6 816.6,28.9 821.0,28.5 829.9,28.9 830.6,30.2 842.2,30.6 842.4,28.5 852.7,29.0 857.2,30.4 858.5,32.2 856.8,33.4 860.3,35.6 864.7,36.7 867.4,33.8 871.8,35.0 876.6,34.3 881.9,35.1 884.0,34.4 888.5,34.8 886.5,32.2 890.2,31.0 915.3,32.8 917.6,34.4 924.9,36.5 936.1,36.0 941.7,36.5 944.0,37.6 943.6,39.7 947.1,40.5 950.8,39.9 955.7,39.8 960.9,40.4 966.2,40.0 971.0,42.5 974.5,41.6 972.2,39.9 973.5,38.6 982.3,39.4 988.1,39.2 996.1,40.6 1000.0,41.8 1000.0,52.8 996.4,54.1 992.8,53.9 995.3,55.3 997.0,57.6 998.3,58.4 998.6,59.5 997.9,60.3 992.7,59.7 982.4,62.1 974.2,65.7 973.1,67.0 969.2,65.1 961.9,67.3 960.7,66.2 958.0,67.4 954.3,67.0 953.4,68.9 950.0,71.5 950.1,72.7 953.3,73.3 952.9,77.3 950.4,77.4 949.2,79.8 950.3,81.0 945.5,82.4 944.5,85.5 940.4,86.2 939.5,89.0 935.5,91.6 934.5,89.7 931.8,79.5 933.1,75.6 935.4,74.0 935.6,72.7 939.9,72.1 949.6,65.7 954.6,63.5 956.9,59.6 953.5,59.8 951.8,62.1 944.8,65.2 942.5,61.7 935.3,62.7 928.4,67.3 930.7,69.0 920.2,70.1 920.4,68.0 916.1,67.6 912.6,69.0 904.1,68.5 895.0,69.3 875.4,81.3 879.7,81.7 881.1,83.4 883.8,84.0 885.6,82.6 888.6,82.8 892.6,85.9 892.7,88.2 890.5,91.0 890.3,94.3 889.1,98.8 884.9,102.8 883.9,104.7 874.6,112.8 870.9,114.4 869.2,114.4 867.4,113.1 863.7,115.1 863.3,116.1 862.9,114.2 864.3,114.1 864.7,110.8 864.0,108.4 866.3,107.4 869.7,107.9 871.6,105.2 872.5,102.2 875.1,98.7 870.5,99.5 868.1,100.6 863.9,100.6 862.7,98.0 859.4,96.0 854.6,95.1 853.6,92.4 849.9,86.7 847.4,85.7 843.3,84.8 836.1,85.4 833.8,86.8 835.3,87.5 835.4,89.0 833.8,89.9 831.3,92.8 831.4,94.0 827.4,95.8 824.1,94.8 820.8,95.0 819.3,94.1 817.7,93.8 813.6,95.7 807.4,96.9 801.3,96.4 799.6,95.0 796.9,93.7 794.1,93.3 788.0,94.2 784.0,93.0 783.5,90.9 777.7,89.9 774.6,88.8 771.7,91.6 772.9,93.3 770.2,95.2 763.4,94.4 761.5,93.1 758.6,93.1 756.2,92.2 752.0,93.5 746.7,95.9 742.7,96.6 741.2,94.9 737.6,95.3 736.4,94.1 734.5,93.6 733.2,92.0 731.6,91.5 727.6,92.2 723.8,90.6 722.3,92.0 716.1,85.0 712.6,82.8 713.6,82.0 706.6,84.6 704.0,84.8 704.2,83.2 700.6,82.3 697.7,83.0 696.8,80.1 691.9,79.5 689.4,80.6 682.4,81.7 681.1,82.3 670.7,83.3 669.4,84.3 671.4,86.2 668.7,86.9 669.2,87.6 666.6,89.0 671.1,90.9 670.4,92.2 666.5,92.1 665.7,92.9 662.1,91.5 657.7,91.5 654.8,92.7 645.4,89.7 641.0,89.7 635.3,92.8 634.9,94.8 632.1,93.2 629.9,96.2 630.7,96.8 629.1,98.9 631.4,100.8 633.5,100.7 635.3,102.6 635.0,104.0 636.4,104.4ZM766.5,7.6 771.9,9.0 778.3,11.7 777.6,14.2 771.5,14.6 763.8,13.8 759.2,12.7 757.1,10.7 753.3,10.2 760.5,8.3ZM792.7,14.7 791.9,15.8 776.2,16.9 781.3,13.2 783.6,12.9ZM893.0,22.0 903.0,23.4 900.8,25.5 890.6,25.4 886.0,26.1 880.5,24.3 882.0,22.4 885.6,21.8ZM918.7,24.8 915.5,25.9 911.0,25.6 905.9,24.5 906.6,23.6ZM891.1,28.4 894.6,28.2 898.6,29.2 898.9,30.0 889.0,29.7 888.5,29.5ZM630.0,9.0 634.2,8.9 634.8,9.7 639.0,8.6 643.1,9.2 632.2,11.1 629.2,10.4 630.8,9.6 624.6,9.5ZM558.0,82.5 554.6,82.1 555.2,80.9 559.1,80.0 563.2,81.0 563.1,82.4ZM655.3,26.0 654.5,24.8 669.9,21.5 679.2,21.0 683.9,20.0 689.3,19.6 691.3,20.7 689.4,21.6 671.1,24.3 662.4,26.9 653.9,32.3 654.5,34.6 659.8,36.9 658.2,37.1 649.1,36.8 648.4,35.5 643.3,34.8 642.9,33.3 645.8,32.7 645.7,31.2 651.2,28.8 648.6,28.5ZM897.9,86.8 897.9,89.6 901.8,97.3 897.7,96.4 896.0,100.4 898.7,103.2 898.6,105.2 896.5,103.5 894.7,105.6 894.2,103.3 894.5,100.6 894.2,97.6 894.8,95.5 894.9,91.8 893.3,89.1 893.6,85.3 896.1,84.0 895.0,82.7 896.3,82.3ZM13.8,48.4 15.7,49.1 15.1,47.0 22.6,47.5 28.1,50.1 25.3,51.3 20.7,51.6 20.7,54.3 19.6,54.9 17.0,54.8 14.9,53.8 11.2,53.0 10.5,51.8 7.7,51.3 4.6,51.7 3.0,50.7 3.6,49.7 0.3,50.3 1.6,51.7 0.0,52.8 0.0,41.8 14.1,46.7ZM0.0,36.6 0.0,34.7 0.4,34.6 2.7,34.6 6.7,35.4 6.5,35.7 3.6,36.4ZM280.6,158.9 283.8,158.8 283.8,159.5 280.8,159.9ZM283.9,158.2 286.1,159.5 285.6,161.4 285.1,161.1 285.2,159.6ZM282.8,163.3 283.6,163.4 284.6,165.7 284.6,167.3 283.9,167.5 283.2,165.9 282.2,165.1ZM330.0,377.4 333.3,375.7 335.7,376.4 337.4,375.3 339.6,376.5 338.8,377.5 335.0,378.3 333.8,377.4 331.4,378.6ZM542.1,12.0 543.1,11.1 547.2,11.0 559.8,14.0 552.9,15.1 551.3,17.1 548.9,17.7 547.6,20.0 544.2,20.1 538.2,18.4 540.7,17.4 536.6,16.6 531.2,14.3 529.0,12.1 536.6,11.1 538.1,12.1ZM586.4,40.1 579.4,41.5 580.6,39.5 577.0,38.4 572.7,39.4 571.4,41.4 568.7,42.6 565.7,42.0 562.1,42.1 559.0,40.6 557.3,41.4 555.6,41.5 555.2,43.3 550.0,42.9 549.2,44.4 546.6,44.4 542.0,49.5 537.7,53.4 538.7,54.3 537.7,55.4 534.9,55.4 533.1,58.0 533.3,61.7 535.1,63.1 534.2,66.3 530.6,69.8 528.8,68.1 523.3,71.4 519.6,72.0 515.7,70.6 514.7,67.6 513.9,61.2 516.4,59.4 523.8,57.1 529.2,54.2 541.0,45.0 553.3,39.4 559.4,38.2 564.0,38.3 568.2,36.0 573.3,36.1 578.2,35.6 586.9,37.6 583.3,38.4ZM576.1,11.0 572.0,12.5 564.0,12.8 555.8,12.3 555.3,11.5 551.3,11.5 548.2,10.2 556.8,9.4 560.9,10.1 563.7,9.3ZM568.7,17.1 562.5,18.2 557.6,17.6 559.5,16.8 557.8,16.0 563.6,15.4 564.7,16.4ZM370.1,3.8 379.4,2.2 389.2,2.3 392.7,1.3 402.5,1.0 424.7,1.3 442.1,3.5 437.0,4.6 411.4,5.0 412.8,5.5 422.6,5.2 431.0,6.1 436.4,5.3 438.7,6.3 435.6,7.9 442.7,6.9 456.2,5.8 464.5,6.3 466.1,7.5 454.8,9.5 453.2,10.1 444.3,10.6 450.7,10.8 445.3,14.6 445.4,17.7 448.7,19.5 444.3,19.6 439.8,20.5 444.9,21.9 445.6,24.3 442.6,24.6 446.2,27.0 440.0,27.2 443.2,28.3 442.3,29.3 434.5,29.7 438.0,31.6 438.1,32.8 432.6,31.7 431.1,32.4 434.9,33.1 438.5,34.8 439.6,37.0 434.6,37.6 429.0,34.9 430.0,36.8 426.8,38.3 437.9,38.5 422.9,43.1 411.7,44.1 408.9,45.2 405.0,48.1 399.0,50.1 389.4,51.5 387.0,53.2 387.0,55.2 385.6,57.0 381.1,59.2 382.2,61.4 379.5,66.4 375.6,66.6 371.5,64.3 365.9,64.3 363.2,62.8 361.4,60.0 356.6,56.6 355.2,54.8 354.8,52.3 350.9,49.7 351.9,47.7 350.1,46.7 352.8,43.5 357.0,42.4 358.1,41.3 358.7,39.1 351.5,40.9 348.1,40.0 347.9,38.1 349.0,36.6 357.2,37.3 350.0,34.6 347.2,35.0 344.9,34.3 348.0,31.7 340.8,25.8 337.2,24.7 337.3,23.6 329.8,21.9 309.7,22.1 301.7,19.4 309.0,18.5 314.5,18.4 302.7,17.7 296.4,16.5 296.8,15.5 317.5,12.8 318.5,11.8 311.0,10.8 313.5,9.7 323.1,7.7 327.1,7.4 326.0,6.2 341.1,5.0 349.6,5.0 352.7,5.9 360.0,4.3 376.3,6.5 369.7,5.0ZM691.5,368.4 693.3,369.3 695.9,369.6 696.0,370.2 695.2,371.4 691.0,371.6 690.9,370.1ZM847.1,258.0 847.5,257.4 849.9,256.8 852.7,256.3 853.7,256.7 847.5,259.4ZM545.4,312.7 546.7,311.3 547.8,312.1 548.3,313.3 551.3,314.0 552.8,313.8 555.3,312.4 555.3,302.1 556.0,302.5 557.7,305.2 557.4,306.9 558.0,307.9 560.0,307.6 562.7,305.5 563.4,304.2 564.8,303.5 567.3,304.6 569.5,304.8 571.3,304.1 572.1,301.9 573.6,301.7 575.3,298.8 577.8,296.7 581.8,294.7 586.6,295.1 588.7,301.0 588.2,304.1 588.4,305.1 587.0,304.6 586.2,304.8 585.2,306.7 585.2,307.6 586.9,309.1 588.5,308.8 589.1,307.6 591.2,307.6 590.2,311.9 589.5,313.2 587.0,315.0 583.5,319.8 578.4,324.4 576.3,325.6 572.0,326.9 571.6,327.6 569.9,327.2 568.5,327.7 565.5,327.2 562.7,327.4 557.5,328.9 555.8,330.0 554.5,330.1 553.3,329.1 552.4,329.0 551.2,327.8 551.0,328.2 550.7,325.8 549.8,323.9 550.7,323.4 550.6,321.3ZM580.5,313.8 579.3,312.9 578.0,313.5 575.0,316.3 577.1,318.5 578.1,318.2 578.6,317.3 580.1,316.9 581.5,314.6ZM580.5,313.8 581.5,314.6 580.1,316.9 578.6,317.3 578.1,318.2 577.1,318.5 575.0,316.3 578.0,313.5 579.3,312.9ZM174.6,143.0 181.3,142.4 181.1,143.0 191.6,146.3 199.3,146.3 199.3,145.1 204.1,145.1 208.2,148.2 209.8,151.2 211.3,152.0 213.6,152.9 215.3,150.7 217.6,150.6 219.6,151.7 221.9,155.2 223.6,156.8 224.9,160.1 229.1,161.6 230.2,161.5 228.6,165.9 228.1,171.0 230.0,176.0 231.9,178.1 233.6,181.0 236.6,181.8 237.7,182.9 246.1,180.9 247.9,179.8 249.2,175.0 254.0,173.6 258.2,173.5 258.9,174.1 258.8,175.4 257.3,177.1 256.6,178.8 257.1,179.2 256.0,182.6 255.3,181.9 254.2,182.0 253.2,183.7 252.7,183.3 252.4,183.9 247.2,183.8 247.2,185.4 246.0,185.4 248.8,187.7 248.7,188.7 245.1,188.7 243.8,191.0 244.2,191.5 243.8,192.9 239.2,189.1 237.0,188.3 231.8,189.9 219.9,185.6 216.9,183.6 212.5,182.5 211.3,181.3 208.4,179.7 207.0,177.9 206.3,176.6 207.2,176.3 206.9,175.5 207.6,174.8 207.6,173.8 205.5,170.1 198.9,163.4 196.5,162.3 196.0,161.6 196.4,159.9 193.4,157.9 192.7,155.9 191.2,155.7 188.3,152.9 188.1,152.0 185.7,147.8 185.7,146.7 183.7,145.6 182.8,145.8 181.2,145.0 180.7,146.1 181.5,149.5 185.4,153.5 185.7,154.4 186.2,154.4 186.8,156.2 190.0,159.3 190.9,161.9 192.5,164.4 192.6,165.8 194.0,165.9 196.1,168.4 194.8,169.9 194.4,169.9 193.6,168.2 188.4,164.6 188.1,161.1 184.8,159.0 184.5,159.3 182.0,157.9 180.4,156.3 181.7,156.3 182.8,155.2 182.9,154.0 180.7,152.0 179.1,151.2ZM339.9,317.3 341.7,317.0 344.5,319.1 345.6,319.0 350.6,322.4 352.2,324.2 351.0,325.6 351.7,327.1 350.5,328.9 347.4,330.4 345.3,329.9 343.8,330.2 341.3,329.0 339.4,329.1 337.7,327.5 337.9,325.7 338.5,325.1 338.5,322.3ZM351.7,327.1 351.0,325.6 352.2,324.2 350.6,322.4 345.6,319.0 344.5,319.1 341.7,317.0 339.9,317.3 346.8,310.8 351.0,308.1 351.0,305.9 349.6,304.3 348.3,304.8 349.2,301.6 349.2,300.1 348.2,299.6 347.1,300.0 346.1,299.9 345.5,296.3 345.0,295.4 343.1,294.7 342.0,295.2 339.1,294.7 339.2,290.9 338.4,289.4 339.3,288.8 339.0,287.2 339.8,286.0 340.3,283.8 339.6,282.1 338.1,281.3 337.8,280.2 338.2,278.6 332.9,278.5 331.8,275.3 332.6,275.2 331.9,271.6 330.3,270.8 328.6,270.8 325.5,269.4 324.5,268.4 321.3,267.9 318.3,265.5 318.5,260.4 314.9,260.9 311.0,263.1 310.4,263.9 306.9,263.8 305.3,264.2 304.0,263.9 304.2,259.7 301.9,261.3 299.5,261.3 298.4,259.8 296.6,259.6 297.2,258.4 295.6,256.7 294.5,254.2 295.2,253.7 295.2,252.6 296.9,251.7 296.6,250.2 297.3,249.3 297.5,248.0 300.7,246.1 303.3,245.1 305.9,245.3 307.2,236.5 306.7,234.9 305.5,233.8 305.5,231.8 307.1,231.4 307.6,231.7 307.7,230.6 306.1,230.3 306.1,228.6 311.5,228.6 312.4,227.7 313.7,230.2 314.2,229.9 315.8,231.3 317.9,231.1 318.5,230.3 321.7,229.2 322.0,228.0 324.0,227.2 323.8,226.6 321.5,226.4 321.2,222.8 320.0,222.1 320.5,221.8 324.7,222.9 325.5,222.2 330.6,220.7 331.7,219.7 331.3,218.9 332.7,218.8 333.4,219.4 333.0,220.6 334.0,221.0 334.6,222.3 333.8,223.3 333.4,225.7 334.3,228.4 336.0,229.7 337.4,229.8 337.7,229.3 339.8,228.7 340.7,227.9 344.5,228.3 344.5,226.4 347.0,226.3 349.8,227.5 350.6,226.7 351.2,226.8 351.6,227.6 352.9,227.4 354.0,226.4 356.5,221.8 357.5,221.7 359.7,228.1 361.2,228.5 361.3,230.4 359.2,232.7 360.0,233.6 364.9,234.0 365.0,236.8 367.2,234.9 375.3,237.6 376.6,239.3 376.2,240.8 379.4,240.0 384.8,241.4 388.9,241.3 393.1,243.6 396.6,246.7 398.7,247.5 401.1,247.6 402.1,248.5 403.5,253.7 402.4,258.3 397.1,264.0 395.3,267.1 393.3,269.6 392.6,269.6 391.8,271.6 392.0,276.9 390.9,283.0 390.0,284.1 389.6,287.8 386.7,291.4 386.3,294.3 384.0,295.5 383.4,297.1 380.3,297.1 376.0,298.2 374.0,299.4 370.9,300.2 367.6,302.5 365.3,305.2 364.9,307.3 365.3,308.8 364.2,313.0 362.3,314.5 359.2,319.4 354.8,322.9 353.6,325.5ZM306.9,263.8 310.4,263.9 311.0,263.1 314.9,260.9 318.5,260.4 318.3,265.5 321.3,267.9 324.5,268.4 325.5,269.4 328.6,270.8 330.3,270.8 331.9,271.6 332.6,275.2 331.8,275.3 332.9,278.5 338.2,278.6 337.8,280.2 338.1,281.3 339.6,282.1 340.3,283.8 339.8,286.0 339.0,287.2 339.3,288.8 338.4,289.4 338.4,288.5 335.8,287.1 333.2,287.1 328.4,287.9 327.0,290.3 327.0,291.8 325.9,295.1 325.4,294.5 322.3,294.4 321.2,296.7 319.5,294.7 315.9,294.0 313.6,296.5 311.6,296.9 310.5,293.0 309.0,289.9 309.9,287.2 308.4,286.1 308.1,284.1 306.7,282.2 308.4,279.2 307.3,276.8 307.9,275.9 307.4,274.9 308.5,273.5 308.7,269.2 309.3,268.2ZM305.9,245.3 303.3,245.1 300.7,246.1 297.5,248.0 297.3,249.3 296.6,250.2 296.9,251.7 295.2,252.6 295.2,253.7 294.5,254.2 295.6,256.7 297.2,258.4 296.6,259.6 298.4,259.8 299.5,261.3 301.9,261.3 304.2,259.7 304.0,263.9 305.3,264.2 306.9,263.8 309.3,268.2 308.7,269.2 308.5,273.5 307.4,274.9 307.9,275.9 307.3,276.8 308.4,279.2 305.9,283.6 304.5,284.3 301.7,282.7 301.5,281.6 296.0,278.8 288.9,274.0 287.7,271.7 288.2,270.9 285.8,267.3 278.4,253.3 274.3,250.4 275.2,249.1 273.9,246.5 274.7,244.5 276.9,242.8 277.3,243.9 276.5,244.6 276.5,245.6 278.8,245.7 280.0,247.1 281.6,246.0 282.1,244.1 283.8,241.7 287.1,240.6 290.2,237.7 291.0,235.9 290.6,233.8 291.4,233.5 295.4,236.8 297.0,239.7 299.1,240.1 300.6,239.4 301.6,239.8 303.3,239.6 305.4,240.9 303.6,243.7 304.5,243.8ZM314.2,229.9 313.7,230.2 312.4,227.7 311.5,228.6 306.1,228.6 306.1,230.3 307.7,230.6 307.6,231.7 307.1,231.4 305.5,231.8 305.5,233.8 306.7,234.9 307.2,236.5 305.9,245.3 304.5,243.8 303.6,243.7 305.4,240.9 303.3,239.6 301.6,239.8 300.6,239.4 299.1,240.1 297.0,239.7 295.4,236.8 291.4,233.5 290.6,233.8 288.1,232.2 287.3,232.6 284.9,232.2 284.3,231.0 281.0,229.5 280.6,228.6 281.6,228.4 281.5,227.0 282.1,226.0 283.5,225.8 285.8,222.6 284.7,222.0 285.3,220.4 284.6,217.8 285.2,217.1 284.8,214.7 283.7,213.3 284.0,211.9 284.9,212.1 285.4,211.3 284.8,209.7 285.1,209.2 286.6,209.3 288.6,207.4 289.8,207.1 290.3,203.8 291.9,202.5 293.7,202.5 293.9,201.9 296.1,202.1 299.3,200.1 300.7,198.8 301.7,199.0 302.4,199.7 301.9,200.6 300.1,201.1 299.4,202.5 297.5,204.3 296.4,207.9 297.8,208.1 298.8,210.0 298.8,212.7 299.4,212.9 300.1,213.9 303.7,213.6 305.3,214.0 307.3,216.4 312.0,215.9 312.9,216.4 311.8,218.8 311.6,220.8 313.0,224.1 311.6,225.5 313.4,227.1ZM285.1,209.2 284.8,209.7 285.4,211.3 284.9,212.1 284.0,211.9 283.7,213.3 282.7,212.5 282.1,211.0 282.8,210.2 280.2,208.3 279.0,208.5 278.4,209.5 276.7,210.3 276.4,210.9 277.8,212.4 276.6,213.1 275.3,213.3 274.8,211.6 274.5,212.1 273.6,211.9 273.0,210.8 269.9,210.3 269.9,210.9 269.5,210.5 269.8,208.9 270.2,208.5 269.6,208.1 269.6,207.0 270.7,206.8 271.7,207.8 271.6,208.3 273.0,208.2 273.8,208.9 278.0,207.5 279.0,206.6 280.5,206.8 280.4,207.1 283.2,207.6ZM270.7,206.8 269.6,207.0 269.6,208.1 270.2,208.5 269.8,208.9 269.5,210.5 268.0,209.9 267.5,209.3 267.7,208.2 264.9,206.6 264.7,205.8 264.0,205.3 264.1,206.1 263.6,206.8 262.1,205.7 261.7,205.2 262.1,203.5 261.3,203.1 262.3,202.2 264.2,202.9 264.8,202.5 265.7,202.8 267.0,203.5 267.6,202.9 268.3,204.5ZM267.6,202.9 267.0,203.5 264.8,202.5 264.2,202.9 262.3,202.2 261.9,202.5 256.5,197.5 256.8,197.0 257.2,197.5 258.3,197.2 259.1,196.5 259.0,195.1 260.2,195.1 260.8,194.3 261.7,194.9 263.4,193.5 264.1,192.2 265.4,192.7 268.1,191.6 269.0,191.7 268.7,192.6 268.9,193.6 268.0,195.6 268.1,198.8 267.7,199.1 267.6,201.0 267.1,201.7ZM269.0,191.7 268.1,191.6 265.4,192.7 264.1,192.2 263.4,193.5 261.7,194.9 260.8,194.3 260.2,195.1 259.0,195.1 259.1,196.5 257.5,197.3 257.0,196.4 256.1,196.2 256.3,195.0 255.9,194.7 254.2,194.9 251.8,193.3 252.4,192.6 252.3,191.5 255.8,189.3 258.6,189.6 261.1,188.9 262.7,189.2 263.9,188.9 265.6,189.3ZM251.8,193.3 254.2,194.9 255.4,194.5 256.3,195.0 255.8,196.8 253.2,196.5 249.7,195.2 251.3,193.8 251.1,193.4ZM243.8,192.9 244.2,191.5 243.8,191.0 245.1,188.7 248.7,188.7 248.8,187.7 246.0,185.4 247.2,185.4 247.2,183.8 252.4,183.9 252.1,189.2 254.9,189.6 252.3,191.5 252.4,192.6 251.8,193.3 251.1,193.4 251.3,193.8 249.7,195.2 246.6,194.6ZM252.4,183.9 252.7,183.3 253.2,183.7 254.2,182.0 255.3,182.4 254.6,187.4 253.0,189.2 252.1,189.2ZM331.3,218.9 331.7,219.7 330.6,220.7 325.5,222.2 324.7,222.9 320.5,221.8 320.0,222.1 321.2,222.8 321.5,226.4 323.8,226.6 324.0,227.2 322.0,228.0 321.7,229.2 318.5,230.3 317.9,231.1 315.8,231.3 314.2,229.9 313.4,227.1 311.6,225.5 313.0,224.1 311.6,220.8 311.8,218.8 312.9,216.4 312.0,215.9 307.3,216.4 305.3,214.0 303.7,213.6 300.1,213.9 299.4,212.9 298.8,212.7 298.8,210.0 297.8,208.1 296.4,207.9 297.5,204.3 299.4,202.5 300.1,201.1 301.9,200.6 301.8,201.3 300.1,201.6 301.1,202.9 301.0,204.3 299.8,205.9 300.8,208.1 302.0,208.0 302.7,205.9 301.8,205.0 301.7,202.9 305.1,201.7 304.7,200.4 305.7,199.5 306.7,201.5 308.7,201.5 310.5,203.1 310.6,204.0 316.0,203.8 317.6,205.0 319.7,205.3 321.3,204.5 321.3,203.8 328.1,203.6 325.7,204.4 326.7,205.7 328.9,205.9 331.0,207.3 331.5,209.5 332.9,209.4 334.0,210.1 331.8,211.7 331.6,212.7 332.5,213.8 330.1,214.7 330.2,216.0 329.4,216.8ZM342.9,228.1 340.7,227.9 339.8,228.7 337.7,229.3 337.4,229.8 336.0,229.7 334.3,228.4 333.4,225.7 333.8,223.3 334.6,222.3 334.0,221.0 333.0,220.6 333.4,219.4 332.7,218.8 331.3,218.9 329.4,216.8 330.2,216.0 330.1,214.7 332.5,213.8 331.6,212.7 331.8,211.7 334.0,210.1 335.8,211.1 337.5,212.9 337.6,214.4 338.7,214.4 341.3,216.7 340.8,219.2 339.1,220.0 338.8,222.1 340.0,224.1 340.9,224.1 341.2,225.6ZM348.5,226.9 347.0,226.3 344.5,226.4 344.5,228.3 342.9,228.1 341.2,225.6 340.9,224.1 340.0,224.1 338.8,222.1 339.1,220.0 340.8,219.2 341.3,216.7 344.6,217.3 344.9,216.8 347.1,216.6 350.1,217.3 348.7,219.7 348.9,221.6 350.0,223.3ZM356.5,221.8 354.0,226.4 352.9,227.4 351.6,227.6 351.2,226.8 350.6,226.7 349.8,227.5 348.5,226.9 350.0,223.3 348.9,221.6 348.7,219.7 350.1,217.3 353.1,218.3 356.0,220.7ZM517.2,95.9 518.5,96.7 522.5,97.2 521.1,99.1 520.7,101.1 520.0,101.5 518.7,101.3 518.8,102.0 516.8,103.5 516.7,104.8 518.1,104.4 519.0,105.6 518.9,106.4 519.7,107.4 518.7,108.3 519.5,110.4 521.0,110.8 520.7,112.0 518.1,113.5 512.7,112.8 508.6,113.7 508.3,115.4 505.1,115.7 501.9,114.5 500.9,115.1 495.8,113.8 494.7,112.7 496.2,111.0 496.7,105.5 493.8,102.6 491.8,101.2 487.5,100.1 487.2,98.1 490.8,97.5 495.5,98.2 494.6,95.1 497.3,96.3 503.7,94.1 504.6,91.8 507.0,91.3 507.4,92.2 508.7,92.3 511.9,94.7 513.3,94.5 516.4,96.0ZM524.3,114.9 526.1,113.9 526.6,116.2 525.6,118.4 524.4,117.8 523.7,116.0ZM290.6,233.8 291.0,235.9 290.2,237.7 287.1,240.6 283.8,241.7 282.1,244.1 281.6,246.0 280.0,247.1 278.8,245.7 276.5,245.6 276.5,244.6 277.3,243.9 276.9,242.8 278.4,240.7 277.8,239.5 276.8,240.8 275.1,239.6 275.7,238.8 275.2,236.3 276.2,235.9 277.7,232.3 277.5,231.2 281.0,229.5 284.3,231.0 284.9,232.2 287.3,232.6 288.1,232.2ZM315.9,181.9 317.3,182.1 317.8,182.7 317.1,183.4 313.4,183.5 313.2,182.3 313.6,181.9ZM284.5,182.0 286.4,182.2 287.9,182.9 288.3,183.6 286.4,183.7 285.5,184.2 284.0,183.7 282.4,182.7 282.7,182.1ZM271.5,168.9 276.1,169.2 278.7,170.1 279.8,171.1 282.4,170.8 287.4,174.4 290.0,175.0 289.8,175.7 291.9,175.9 293.9,177.0 293.6,177.6 291.8,178.0 284.0,178.2 285.9,176.6 284.7,175.9 283.0,175.7 282.0,174.9 281.3,173.3 279.8,173.4 276.3,172.1 272.7,171.7 271.8,171.1 272.8,170.5 270.1,170.3 268.1,171.8 266.9,171.8 266.5,172.5 265.1,172.8 264.0,172.5 267.3,170.0ZM586.6,295.1 581.8,294.7 580.0,293.4 577.8,293.0 577.0,290.3 575.8,290.0 572.7,286.9 570.2,282.6 575.1,283.2 579.1,279.1 580.1,278.9 580.4,277.9 582.0,276.8 584.1,276.4 584.3,277.4 586.6,277.4 591.2,279.8 590.7,289.7 589.6,292.0ZM581.8,294.7 577.8,296.7 575.3,298.8 573.6,301.7 572.1,301.9 571.3,304.1 569.5,304.8 567.3,304.6 564.8,303.5 563.4,304.2 562.7,305.5 560.0,307.6 558.0,307.9 557.4,306.9 557.7,305.2 556.0,302.5 555.3,302.1 555.3,294.0 558.0,293.9 558.1,284.0 564.4,283.0 565.5,284.1 567.3,283.0 570.2,282.6 572.7,286.9 575.8,290.0 577.0,290.3 577.8,293.0 580.0,293.4ZM555.3,302.1 555.3,312.4 552.8,313.8 551.3,314.0 548.3,313.3 547.8,312.1 546.7,311.3 545.4,312.7 543.3,310.6 542.3,308.6 540.0,299.6 539.6,294.8 537.1,291.3 535.0,286.2 532.8,283.5 532.6,281.4 535.6,280.4 537.4,280.5 539.1,281.7 550.7,281.4 552.7,282.7 559.4,283.1 566.8,281.4 568.6,281.5 569.7,282.2 565.5,284.1 564.4,283.0 558.1,284.0 558.0,293.9 555.3,294.0ZM453.6,195.6 452.4,193.4 451.0,192.4 452.3,191.9 455.2,187.6 456.6,187.9 458.0,187.3 459.5,187.2 462.7,188.8 466.2,192.7 466.9,196.0 467.9,196.8 468.0,198.8 465.3,199.1 463.3,198.4 456.8,198.3 453.7,198.9 453.2,196.8 455.7,196.9 457.9,195.8 460.3,196.4 461.5,195.8 461.0,195.0 459.2,195.5 458.1,194.8 457.2,194.8 456.6,195.5ZM468.0,198.8 467.9,196.8 466.9,196.0 466.2,192.7 467.1,192.2 467.6,190.6 470.4,191.3 472.0,190.7 473.1,190.9 473.5,190.3 484.6,190.3 485.2,188.3 484.8,188.0 482.1,164.0 486.3,164.0 505.1,176.1 505.7,177.4 508.7,178.6 508.8,180.4 511.9,180.1 511.9,186.5 510.3,188.4 510.1,190.1 503.8,190.8 502.8,191.8 499.3,191.9 498.6,191.3 497.0,191.7 494.4,192.9 491.4,195.7 490.2,196.3 488.9,195.9 488.1,196.6 487.7,198.5 485.5,200.8 485.6,201.7 484.8,202.9 485.0,204.5 483.2,205.3 482.8,204.1 481.5,204.4 481.0,205.2 477.7,205.0 476.8,204.2 477.0,203.4 476.6,203.0 476.1,203.3 476.7,201.7 474.6,199.1 474.1,199.1 471.8,200.4 469.3,199.4 468.2,199.8ZM452.6,175.0 453.2,174.1 464.1,174.1 463.6,170.1 464.2,168.7 466.8,168.4 466.8,161.3 475.9,161.4 475.9,157.2 486.3,164.0 482.1,164.0 484.8,188.0 485.2,188.3 484.6,190.3 473.5,190.3 473.1,190.9 472.0,190.7 470.4,191.3 467.6,190.6 467.1,192.2 466.2,192.7 462.7,188.8 459.5,187.2 458.0,187.3 456.6,187.9 455.2,187.6 454.3,188.5 454.0,187.0 454.8,185.6 455.1,183.0 454.5,178.9 454.8,177.5 454.1,176.2ZM507.5,215.9 505.2,216.3 504.5,214.4 504.6,208.0 504.1,207.4 504.0,206.0 502.1,204.2 502.5,202.8 503.5,202.5 504.0,201.3 505.4,201.0 506.9,199.4 507.9,199.3 510.0,200.9 509.9,201.9 510.5,203.5 510.0,204.6 510.3,205.4 508.1,208.0 507.6,209.7ZM541.3,169.8 541.9,174.1 543.0,174.9 543.0,175.7 544.2,176.7 543.6,177.9 542.5,183.5 542.4,187.1 538.8,189.8 537.6,193.4 538.8,194.5 538.8,196.2 540.5,196.3 540.3,197.6 539.5,197.8 539.4,198.7 538.9,198.7 537.0,195.7 536.3,195.6 534.2,197.1 530.5,196.1 529.7,196.5 528.1,196.5 526.5,197.6 525.0,197.7 521.7,196.3 520.4,196.9 518.9,196.9 517.9,195.9 515.1,194.8 512.1,195.1 511.4,195.7 511.0,197.3 510.2,198.5 510.0,200.9 507.9,199.3 506.9,199.4 506.0,200.2 506.0,198.3 502.8,197.6 502.8,196.3 501.2,194.5 500.8,193.2 501.0,191.9 502.8,191.8 503.8,190.8 510.1,190.1 510.3,188.4 511.9,186.5 511.9,180.1 515.8,178.9 523.8,173.4 533.3,168.1 537.7,169.3 539.3,170.9ZM507.5,215.9 507.6,209.7 508.1,208.0 510.3,205.4 510.0,204.6 510.5,203.5 509.9,201.9 510.2,198.5 511.0,197.3 511.4,195.7 512.1,195.1 515.1,194.8 517.9,195.9 518.9,196.9 520.4,196.9 521.7,196.3 525.0,197.7 526.5,197.6 528.1,196.5 529.7,196.5 530.5,196.1 534.2,197.1 536.3,195.6 537.0,195.7 538.9,198.7 539.4,198.7 540.5,199.8 540.0,201.2 537.7,203.3 535.4,209.1 533.9,210.3 532.6,213.9 530.7,214.9 529.2,213.7 528.1,213.8 526.5,215.4 525.6,215.4 523.6,220.1 520.7,221.1 519.7,220.9 518.6,221.6 516.4,221.5 514.9,219.8 514.0,217.7 512.0,215.9ZM540.3,197.6 541.4,199.4 541.5,203.1 543.0,205.6 539.4,205.5 538.8,206.8 540.4,208.4 541.6,208.9 542.9,212.0 541.0,215.5 540.4,216.0 540.2,220.2 541.5,221.6 542.8,224.1 544.1,225.0 544.5,227.0 544.3,228.5 539.8,227.1 526.8,227.0 527.2,224.8 526.1,223.0 524.9,222.5 524.3,221.2 523.6,220.8 524.3,218.1 525.6,215.4 526.5,215.4 528.1,213.8 529.2,213.7 530.7,214.9 532.6,213.9 533.9,210.3 535.4,209.1 537.7,203.3 540.0,201.2 540.5,199.8 539.4,198.7 539.5,197.8ZM502.5,202.8 502.1,204.2 504.0,206.0 504.1,207.4 504.6,208.0 504.5,214.4 505.2,216.3 502.9,216.9 501.6,214.1 501.4,212.7 502.0,210.2 501.3,209.2 501.0,205.0 499.9,203.6 500.1,202.7ZM500.1,202.7 499.9,203.6 501.0,205.0 501.3,209.2 502.0,210.2 501.4,212.7 501.6,214.1 502.9,216.9 494.5,220.2 492.1,219.5 492.2,218.4 491.0,216.0 491.7,212.8 492.9,210.5 491.8,202.9ZM477.7,205.0 481.0,205.2 481.5,204.4 482.8,204.1 483.2,205.3 485.0,204.5 488.0,206.6 488.9,205.9 490.2,205.8 492.1,206.5 492.9,210.5 491.7,212.8 491.0,216.0 492.2,218.4 492.1,219.5 487.1,219.0 483.8,219.5 478.6,221.2 479.0,217.5 476.1,215.4 476.7,214.1 476.4,212.8 476.6,212.0 477.0,212.0 476.9,210.2 478.2,209.5 476.9,206.1 477.1,205.2ZM461.9,198.4 465.3,199.1 468.0,198.8 468.2,199.8 469.3,199.4 471.8,200.4 474.1,199.1 474.6,199.1 476.7,201.7 476.1,203.3 476.6,203.0 477.0,203.4 476.8,204.2 477.7,205.0 477.1,205.2 476.9,206.1 478.2,209.5 476.9,210.2 477.0,212.0 475.8,211.9 475.2,213.0 474.4,213.0 473.9,212.4 474.1,211.3 472.9,209.6 470.8,210.1 470.5,207.6 469.1,205.4 466.9,205.4 465.5,206.0 464.7,207.4 463.2,208.6 460.9,205.9 459.5,205.0 458.8,203.1 458.0,202.7 459.2,201.3 460.0,201.4 461.8,200.5 461.6,199.6ZM453.7,198.9 456.8,198.3 461.9,198.4 461.6,199.6 461.8,200.5 460.0,201.4 459.2,201.3 458.0,202.7 456.5,201.5 455.3,201.3ZM476.6,212.0 476.7,214.1 476.1,215.4 479.0,217.5 478.6,221.2 475.0,219.9 468.2,214.5 469.0,212.8 471.6,210.0 472.9,209.6 474.1,211.3 473.9,212.4 474.4,213.0 475.2,213.0 475.8,211.9ZM463.2,208.6 464.7,207.4 465.5,206.0 466.9,205.4 469.1,205.4 470.5,207.6 470.8,210.1 471.6,210.0 469.0,212.8 468.2,214.5 465.5,213.2 464.0,211.7ZM485.0,204.5 484.8,202.9 485.6,201.7 485.5,200.8 487.7,198.5 488.1,196.6 488.9,195.9 490.2,196.3 491.4,195.7 494.4,192.9 497.0,191.7 498.6,191.3 499.3,191.9 501.0,191.9 500.8,193.2 501.2,194.5 502.8,196.3 502.8,197.6 506.0,198.3 506.0,200.2 505.4,201.0 504.0,201.3 503.5,202.5 502.5,202.8 498.8,202.5 497.9,203.0 491.8,202.9 492.1,206.5 490.2,205.8 488.9,205.9 488.0,206.6ZM576.0,218.8 575.1,219.1 571.3,218.7 568.9,219.7 567.8,219.1 564.7,220.5 563.4,220.2 562.2,222.1 558.1,221.3 554.1,219.4 552.6,220.3 551.5,221.7 551.3,223.6 547.6,223.0 545.9,224.4 544.5,227.0 544.1,225.0 542.8,224.1 541.5,221.6 540.2,220.2 540.2,218.2 540.4,216.0 541.0,215.5 542.4,212.7 544.7,212.5 545.3,211.8 546.4,212.5 549.9,211.4 552.5,209.4 552.3,208.4 555.7,208.3 558.3,207.0 560.3,204.0 561.8,202.9 563.5,202.4 563.8,203.6 565.4,205.3 565.2,208.5 569.8,211.6 569.8,212.5 572.8,215.1 573.5,216.8 575.6,217.9ZM551.3,223.6 551.1,225.3 549.7,228.5 549.5,232.5 549.0,234.5 548.7,235.4 545.6,238.2 544.4,240.9 544.5,243.2 540.5,247.1 539.5,246.6 539.3,245.9 537.8,245.8 536.8,246.9 535.1,245.7 533.1,247.3 530.8,244.4 532.9,242.9 531.9,241.0 532.8,240.3 534.7,240.0 534.9,238.7 536.4,240.1 538.9,240.2 539.7,238.9 540.1,237.0 539.8,234.9 538.5,233.2 539.7,230.0 539.0,229.5 536.9,229.7 536.1,228.2 536.3,227.0 539.8,227.1 544.3,228.5 544.5,227.0 545.9,224.4 547.6,223.0ZM531.3,227.1 534.3,227.2 536.0,226.9 536.3,227.0 536.1,228.2 536.9,229.7 539.0,229.5 539.7,230.0 538.5,233.2 539.8,234.9 540.1,237.0 539.7,238.9 538.9,240.2 536.4,240.1 534.9,238.7 534.7,240.0 532.8,240.3 531.9,241.0 532.9,242.9 530.8,244.4 526.1,239.3 524.4,236.4 526.4,230.5 531.3,230.4ZM526.8,227.0 531.3,227.1 531.3,230.4 526.4,230.5 525.8,230.1ZM585.4,256.5 591.0,259.0 592.3,260.2 593.0,262.6 592.0,265.6 592.5,267.9 591.6,268.8 590.8,271.4 592.3,272.1 583.8,274.4 584.1,276.4 582.0,276.8 580.4,277.9 580.1,278.9 579.1,279.1 575.1,283.2 570.2,282.6 568.6,281.5 566.8,281.4 564.5,282.0 560.8,278.0 560.9,269.2 566.7,269.2 566.5,268.2 566.9,267.2 566.4,265.9 566.7,264.5 566.4,263.7 567.4,263.8 567.5,264.6 570.6,264.8 571.5,266.1 573.8,266.5 575.5,265.6 576.1,267.0 578.2,267.4 580.4,270.1 582.5,270.2 582.3,267.2 581.5,267.7 578.8,266.1 579.6,260.0 579.0,258.8 579.8,257.0 580.6,256.7 584.3,256.2ZM591.0,259.0 593.7,259.5 595.2,261.6 596.0,265.3 595.2,267.4 596.0,271.1 597.0,271.0 598.0,271.9 599.1,273.9 599.4,277.5 598.2,278.1 597.3,280.0 595.5,278.3 595.3,276.3 595.9,275.0 595.7,273.9 594.6,273.2 593.9,273.5 590.8,271.4 591.6,268.8 592.5,267.9 592.0,265.6 593.0,262.6 592.3,260.2ZM596.0,265.3 598.1,265.1 601.4,265.9 604.1,265.5 605.1,264.6 606.7,264.7 609.8,263.6 612.0,262.0 612.4,263.2 612.8,272.8 613.3,274.1 611.4,278.1 609.6,279.8 603.9,282.2 596.6,288.3 596.4,290.3 597.7,292.4 598.3,294.8 598.8,294.7 598.3,298.7 598.9,299.2 598.5,300.3 597.3,301.3 591.7,303.8 590.5,304.8 590.7,306.0 591.4,306.2 591.2,307.6 589.1,307.6 588.2,304.1 588.7,301.0 586.6,295.1 589.6,292.0 590.7,289.7 591.2,279.8 586.6,277.4 584.3,277.4 583.8,274.4 592.3,272.1 593.9,273.5 594.6,273.2 595.7,273.9 595.9,275.0 595.3,276.3 595.5,278.3 597.3,280.0 598.2,278.1 599.4,277.5 599.1,273.9 598.0,271.9 597.0,271.0 596.0,271.1 595.2,267.4ZM589.1,307.6 588.5,308.8 586.9,309.1 585.2,307.6 585.2,306.7 586.2,304.8 587.0,304.6 588.4,305.1ZM536.1,246.6 535.1,247.2 534.5,249.1 533.8,249.4 533.1,247.3 535.1,245.7ZM534.2,250.3 537.2,249.6 545.4,249.7 546.8,253.4 548.5,255.7 551.3,255.1 552.8,255.5 553.9,253.2 555.7,253.1 555.8,252.6 557.2,252.6 557.0,253.6 560.4,253.6 560.4,255.3 561.0,256.4 560.6,258.1 560.8,259.8 561.7,260.8 561.5,264.1 565.2,263.5 566.4,263.7 566.7,264.5 566.4,265.9 566.9,267.2 566.5,268.2 566.7,269.2 560.9,269.2 560.8,278.0 564.5,282.0 559.4,283.1 552.7,282.7 550.7,281.4 539.1,281.7 537.4,280.5 535.6,280.4 532.6,281.4 532.3,279.6 533.8,273.5 535.4,269.8 537.9,266.8 538.2,264.7 538.0,263.1 537.2,262.1 535.8,258.8 536.8,257.1 535.4,252.6 534.0,250.8ZM584.6,240.0 585.4,242.7 582.6,245.7 581.5,245.8 581.3,242.5 580.6,241.2 582.3,241.4 583.2,239.9ZM599.2,142.5 598.7,143.4 597.7,143.0 597.2,144.8 597.8,145.1 597.1,145.5 597.0,146.2 598.3,145.9 598.4,146.9 597.0,151.4 595.2,146.6 596.0,145.7 597.5,141.4 599.5,140.9ZM599.5,140.9 597.6,141.4 598.6,139.2 600.0,137.1 601.2,137.2 601.7,138.3 600.2,139.4ZM637.6,268.0 639.0,271.0 639.5,274.3 640.2,275.6 639.9,277.0 639.4,277.8 638.5,276.2 638.0,277.0 638.5,279.0 638.3,280.2 637.5,280.9 637.3,283.2 630.8,302.6 626.1,304.4 622.3,302.7 621.6,301.3 621.4,298.8 620.4,296.6 620.2,294.6 620.6,292.6 621.9,292.1 621.9,291.2 623.3,289.1 623.5,287.3 622.3,284.3 622.1,281.7 623.1,280.1 623.5,278.4 628.6,277.2 632.5,273.9 633.3,272.5 633.0,271.3 634.1,271.6 635.7,269.7 635.7,268.0 636.7,266.8ZM598.3,145.9 597.0,146.2 597.1,145.5 597.8,145.1 597.2,144.8 597.7,143.0 598.7,143.4ZM453.6,195.6 456.6,195.5 457.2,194.8 458.1,194.8 459.2,195.5 461.0,195.0 461.5,195.8 460.3,196.4 457.9,195.8 455.7,196.9 453.2,196.8ZM526.3,149.1 525.2,144.2 521.1,140.7 520.9,138.6 522.6,137.1 523.3,134.8 522.8,132.1 523.4,130.7 526.4,129.6 528.4,129.9 528.3,131.3 530.6,130.3 530.8,130.8 529.4,132.2 529.4,133.5 530.4,134.2 530.0,136.6 528.2,138.0 528.7,139.5 530.2,139.5 530.9,140.9 531.9,141.3 531.8,143.4 527.6,146.2 527.7,148.5ZM475.9,157.2 475.9,153.2 480.4,151.2 485.4,150.0 486.5,148.6 489.7,147.5 489.9,145.5 491.5,145.2 492.7,144.2 496.4,143.7 496.9,142.6 496.1,142.0 495.0,137.4 494.0,135.6 496.6,134.1 499.6,133.6 501.4,132.5 504.1,131.7 513.4,130.9 514.8,131.3 517.4,130.2 520.4,130.2 521.5,130.9 523.4,130.7 522.8,132.1 523.3,134.8 522.6,137.1 520.9,138.6 521.1,140.7 525.2,144.2 527.2,151.6 526.7,157.9 527.0,159.7 525.9,160.8 527.5,162.9 527.6,164.1 528.6,165.6 529.9,165.1 532.1,166.4 533.3,168.1 523.8,173.4 515.8,178.9 511.9,180.1 508.8,180.4 508.7,178.6 505.7,177.4 505.1,176.1ZM598.7,143.4 599.2,142.5 602.3,143.6 607.8,140.6 608.9,144.0 602.8,145.8 605.6,148.6 604.6,149.1 604.2,150.0 602.1,150.4 600.2,152.2 597.1,151.8 597.0,151.4 598.4,146.9ZM643.3,166.0 643.8,165.8 643.9,166.6 646.0,166.2 650.0,166.3 655.8,161.0 656.3,161.9 656.7,164.1 655.2,164.1 655.0,165.9 655.5,166.3 654.2,166.9 654.2,168.0 652.8,170.8 644.4,169.4ZM641.1,164.6 641.0,162.5 641.7,161.1 642.5,160.8 643.3,161.7 643.4,163.3 642.7,164.9 642.0,165.1ZM633.3,150.1 634.5,154.0 632.5,154.1 631.8,152.8 629.4,152.5 631.4,149.8ZM608.9,144.0 607.8,140.6 613.9,137.7 615.0,134.4 614.7,132.3 616.2,131.7 617.6,129.9 618.8,129.5 622.1,129.8 623.0,130.6 624.4,130.1 626.2,133.4 628.0,134.2 628.2,135.9 626.8,136.8 626.2,139.0 628.1,141.6 631.5,143.1 632.9,145.3 632.5,147.3 633.3,147.3 633.4,148.7 634.9,150.2 631.4,149.8 629.4,152.5 624.2,152.3 616.4,146.7 612.2,144.8ZM653.4,170.3 654.2,166.9 655.5,166.3 655.0,165.9 655.2,164.1 656.7,164.1 657.9,166.0 659.5,167.0 663.1,167.9 665.1,170.4 666.1,170.7 666.1,171.4 662.5,176.6 661.2,176.4 660.6,177.1 660.2,178.5 660.3,180.7 659.0,180.7 657.2,181.7 657.0,183.1 656.3,183.7 654.6,183.7 653.5,184.4 653.5,185.5 652.2,186.2 650.7,186.0 647.5,187.1 644.4,180.6 652.8,177.8 654.6,172.2ZM656.3,161.9 655.8,161.0 656.6,160.0 656.9,160.3ZM964.5,277.5 966.2,279.1 965.3,279.4 964.4,278.2ZM963.3,276.9 962.9,274.0 964.2,274.8 964.6,277.1ZM785.0,199.5 784.3,196.1 786.1,193.8 789.7,193.3 792.3,193.7 794.6,194.8 795.8,192.9 798.3,193.9 798.9,195.7 798.6,199.1 793.9,201.2 795.1,202.9 792.2,203.1 789.8,204.2 787.5,203.8ZM792.3,193.7 789.7,193.3 786.1,193.8 784.3,196.1 785.0,199.5 782.5,198.2 780.1,198.3 780.5,196.1 778.0,196.1 777.8,199.1 775.4,205.7 775.6,207.7 777.4,207.8 779.1,212.7 780.6,214.3 782.3,214.6 783.7,216.1 782.8,217.2 781.0,217.5 780.8,216.1 778.5,214.9 778.0,215.4 776.9,214.3 776.4,212.9 773.6,210.0 773.2,211.7 772.6,210.1 773.8,205.7 776.6,200.3 775.5,197.8 775.3,194.9 772.8,191.3 773.7,190.8 774.7,188.4 770.5,182.1 771.7,181.6 772.9,178.6 774.9,178.5 778.1,176.6 779.3,177.5 779.5,179.1 781.3,179.3 780.7,182.2 780.7,184.7 783.6,183.0 784.5,183.5 786.1,183.4 786.7,182.5 788.8,182.7 790.9,184.9 791.1,187.7 793.3,190.1 793.2,192.4ZM798.3,193.9 795.8,192.9 794.6,194.8 792.3,193.7 793.2,192.4 793.3,190.1 791.1,187.7 790.9,184.9 788.8,182.7 786.7,182.5 786.1,183.4 784.5,183.5 783.6,183.0 780.7,184.7 780.7,182.2 781.3,179.3 779.5,179.1 779.3,177.5 778.1,176.6 778.7,175.6 781.1,173.8 781.3,174.4 782.8,174.5 782.4,171.3 783.8,170.9 786.7,175.6 790.1,175.7 791.2,178.1 789.4,178.8 788.6,179.8 791.9,181.5 796.0,187.2 798.1,189.1 798.8,191.1ZM778.1,176.6 774.9,178.5 772.9,178.6 771.7,181.6 770.5,182.1 774.7,188.4 773.7,190.8 772.8,191.3 775.3,194.9 775.5,197.8 776.6,200.3 773.8,205.7 773.5,203.7 774.3,201.6 773.4,199.9 773.6,196.9 772.5,195.4 771.1,188.6 769.9,186.3 764.9,189.7 761.6,188.8 762.6,185.3 762.0,182.7 759.8,179.5 760.2,178.5 758.6,178.2 756.6,175.9 756.4,173.7 757.4,174.1 757.4,172.1 758.8,171.4 758.5,170.3 759.1,169.3 759.2,166.4 761.4,167.1 762.6,164.8 762.8,163.4 764.3,161.1 764.2,159.5 767.8,157.6 769.8,158.1 769.6,156.4 770.6,155.9 770.4,154.8 772.0,154.6 772.9,156.3 774.1,156.9 774.1,161.3 771.5,163.7 771.1,167.0 774.1,166.5 774.7,169.0 776.5,169.6 775.7,171.9 778.9,173.4 781.0,172.6 781.1,173.8 778.7,175.6ZM789.8,204.2 792.2,203.1 795.1,202.9 793.9,201.2 798.6,199.1 798.9,195.7 798.3,193.9 798.8,191.1 798.1,189.1 796.0,187.2 791.9,181.5 788.6,179.8 789.4,178.8 791.2,178.1 790.1,175.7 786.7,175.6 783.8,170.9 785.3,170.3 790.2,169.9 792.6,168.5 793.9,169.5 796.5,170.0 796.0,171.6 797.3,172.7 800.1,173.5 796.4,175.8 794.1,178.5 793.5,180.4 798.2,187.0 800.7,188.7 802.4,190.9 803.7,196.0 803.3,200.9 797.8,204.5 795.6,206.9 792.1,209.4 791.1,207.7 791.9,205.8ZM862.9,115.6 863.3,116.1 862.2,115.9 860.2,117.8 860.3,119.8 857.3,121.7 854.3,122.9 853.8,124.4 856.5,126.1 856.1,126.7 853.0,127.1 851.9,128.3 850.5,128.5 849.1,127.9 848.0,128.7 847.9,128.2 846.4,127.5 847.8,125.9 847.6,125.4 848.3,123.9 848.1,123.5 845.2,122.4 847.4,120.6 850.5,119.1 852.4,117.2 853.7,118.0 856.1,118.1 855.7,116.7 860.0,115.5 861.1,113.9ZM850.5,128.5 851.9,128.3 853.0,127.1 856.1,126.7 856.5,126.1 858.9,129.4 859.6,131.2 859.6,134.4 858.6,135.9 856.1,136.4 853.9,137.6 851.3,137.8 851.0,136.3 851.6,134.2 850.3,131.3 852.4,130.9ZM743.8,96.4 746.7,95.9 752.0,93.5 756.2,92.2 758.6,93.1 761.5,93.1 763.4,94.4 770.2,95.2 772.9,93.3 771.7,91.6 774.6,88.8 777.7,89.9 783.5,90.9 784.0,93.0 788.0,94.2 794.1,93.3 796.9,93.7 799.6,95.0 801.3,96.4 807.4,96.9 813.6,95.7 817.7,93.8 819.3,94.1 820.8,95.0 824.1,94.8 820.8,99.6 821.5,100.8 823.1,100.4 825.8,100.8 828.0,99.8 830.2,100.7 832.7,102.6 832.4,103.6 830.2,103.3 826.2,103.7 824.2,104.5 822.2,106.3 817.9,107.4 815.2,108.9 810.8,108.0 809.3,109.8 810.6,111.8 806.7,114.2 803.5,115.2 799.3,115.3 794.8,116.3 791.6,117.8 790.3,116.9 787.0,116.9 782.9,115.2 780.1,114.8 776.4,115.2 767.6,114.7 766.0,113.0 764.7,110.4 763.0,110.1 759.7,108.4 752.6,107.5 751.6,106.3 752.7,103.1 750.8,100.9 746.8,99.8 744.5,98.3ZM770.4,154.8 770.6,155.9 769.6,156.4 769.8,158.1 767.8,157.6 764.2,159.5 764.3,161.1 762.8,163.4 762.6,164.8 761.4,167.1 759.2,166.4 759.1,169.3 758.5,170.3 758.8,171.4 757.4,172.1 756.0,167.7 755.2,167.7 754.7,169.5 753.2,168.0 754.1,166.5 755.3,166.3 756.6,164.0 755.0,163.5 749.8,163.1 749.5,161.2 748.2,161.1 746.0,159.9 745.0,161.8 747.0,163.2 745.3,164.3 744.7,165.3 746.4,166.0 745.9,167.7 746.9,169.8 747.3,172.1 746.9,173.1 741.6,173.6 741.8,175.7 740.3,177.4 736.3,179.2 733.2,182.5 728.3,186.1 728.3,187.3 724.4,189.0 723.1,189.2 722.3,191.3 723.0,197.2 721.8,199.8 721.8,204.6 720.4,204.7 719.1,206.8 720.0,207.7 717.4,208.5 716.5,210.4 715.4,211.2 712.8,208.6 710.4,201.9 708.0,197.9 706.8,192.7 704.3,188.9 702.3,180.0 702.3,176.6 701.8,174.0 697.7,175.7 695.8,175.3 692.1,172.0 693.5,171.0 692.6,169.9 689.4,167.5 691.2,165.7 697.3,165.7 696.8,163.3 695.2,161.9 694.9,159.7 693.1,158.5 696.2,155.6 699.4,155.8 702.3,152.9 704.0,150.1 706.7,147.3 706.7,145.3 709.1,143.7 706.8,142.3 704.9,138.0 706.2,136.8 710.4,137.5 713.5,137.1 716.2,134.7 719.2,138.0 718.9,140.3 720.0,141.7 719.9,143.1 717.9,142.7 718.7,145.8 725.3,149.5 723.5,150.8 722.5,153.3 731.4,157.3 735.2,157.7 736.8,159.1 742.3,160.0 744.6,160.0 744.8,155.9 746.5,155.3 746.8,158.1 749.3,159.1 751.0,158.7 755.6,158.8 755.8,157.1 754.7,156.2 757.0,155.8 759.5,153.8 762.7,152.0 765.0,152.7 767.0,151.5 768.3,153.2 767.4,154.4ZM757.4,172.1 757.4,174.1 756.4,173.7 756.6,175.9 755.1,171.7 753.9,170.1 751.4,170.0 751.6,171.1 750.8,172.7 749.6,172.1 749.2,172.6 747.3,172.1 746.9,169.8 745.9,167.7 746.4,166.0 744.7,165.3 745.3,164.3 747.0,163.2 745.0,161.8 746.0,159.9 748.2,161.1 749.5,161.2 749.8,163.1 755.0,163.5 756.6,164.0 755.3,166.3 754.1,166.5 753.2,168.0 754.7,169.5 755.2,167.7 756.0,167.7ZM754.7,156.2 755.8,157.1 755.6,158.8 751.0,158.7 749.3,159.1 746.8,158.1 746.7,157.5 748.5,155.4 750.0,154.7 753.5,155.4ZM744.8,155.9 744.6,160.0 742.3,160.0 736.8,159.1 735.2,157.7 731.4,157.3 722.5,153.3 723.5,150.8 726.5,148.8 728.7,149.7 731.5,151.5 733.1,151.9 734.0,153.2 736.1,153.8 738.4,155.0ZM716.2,134.7 713.5,137.1 710.4,137.5 706.2,136.8 704.9,138.0 706.8,142.3 709.1,143.7 706.7,145.3 706.7,147.3 704.0,150.1 702.3,152.9 699.4,155.8 696.2,155.6 693.1,158.5 694.9,159.7 695.2,161.9 696.8,163.3 697.3,165.7 691.2,165.7 689.4,167.5 687.3,166.8 686.5,164.8 684.4,162.7 670.8,163.7 671.9,160.4 675.9,159.0 675.6,157.7 674.3,157.3 674.2,154.8 671.6,153.6 669.1,150.5 673.7,151.9 676.5,151.5 678.2,151.8 678.8,151.2 680.7,151.5 684.3,150.3 684.4,147.9 685.9,146.4 688.0,146.4 688.3,145.6 690.4,145.2 691.5,145.5 692.5,144.7 692.4,143.1 693.6,141.4 695.3,140.7 694.3,138.8 696.9,138.9 697.7,137.9 697.5,136.9 698.9,135.7 698.0,133.1 699.6,131.9 708.8,130.2 710.8,131.5 711.6,133.6ZM684.8,129.5 686.3,129.6 689.3,130.5 691.3,129.6 692.2,130.1 693.1,128.9 694.8,128.9 695.5,127.4 696.7,126.4 698.2,127.1 697.9,127.9 698.7,128.0 698.5,130.4 699.6,131.3 701.8,130.4 703.5,129.2 708.3,129.4 708.8,130.2 699.6,131.9 698.0,133.1 698.9,135.7 697.5,136.9 697.7,137.9 696.9,138.9 694.3,138.8 695.3,140.7 693.6,141.4 692.4,143.1 692.5,144.7 691.5,145.5 690.4,145.2 688.3,145.6 688.0,146.4 685.9,146.4 684.4,147.9 684.3,150.3 680.7,151.5 678.8,151.2 678.2,151.8 676.5,151.5 673.7,151.9 669.1,150.5 671.6,148.0 671.4,146.2 669.3,145.7 668.2,141.7 669.3,140.2 668.1,139.8 670.0,134.3 672.9,135.4 675.0,135.0 675.5,133.7 677.7,133.3 679.3,132.5 679.9,130.2 682.2,129.7 682.6,128.7ZM688.4,130.2 690.0,127.3 689.4,125.3 687.3,124.6 688.1,123.4 690.4,123.5 692.6,120.2 696.3,119.6 695.7,120.8 696.1,121.6 697.3,121.5 696.2,122.4 693.2,121.9 693.0,123.5 696.0,123.3 699.4,124.2 704.7,123.8 705.4,126.4 706.3,126.1 708.0,126.7 708.3,129.4 703.5,129.2 701.8,130.4 699.6,131.3 698.5,130.4 698.7,128.0 697.9,127.9 698.2,127.1 696.7,126.4 695.5,127.4 694.8,128.9 693.1,128.9 692.2,130.1 691.3,129.6 689.3,130.5ZM697.1,115.9 697.7,114.7 699.6,114.3 704.1,115.3 704.6,113.6 706.1,113.1 710.1,114.2 711.1,113.9 719.8,114.3 721.2,115.3 722.9,115.7 722.6,116.3 718.2,117.8 717.2,118.9 713.6,119.3 712.6,121.0 709.6,120.7 705.1,122.5 705.4,123.2 704.7,123.8 699.4,124.2 696.0,123.3 693.0,123.5 693.2,121.9 696.2,122.4 697.3,121.5 699.4,121.8 702.9,119.8 699.6,118.4 697.7,119.0 695.6,118.0 697.9,116.2ZM645.8,117.3 647.1,116.3 650.2,115.8 652.1,116.5 654.0,118.7 658.6,118.5 658.1,117.1 660.5,116.2 662.9,114.6 666.6,116.0 666.9,118.3 668.0,118.8 671.0,118.7 671.9,119.2 673.3,122.1 678.3,125.3 684.9,127.8 684.8,129.5 682.6,128.7 682.2,129.7 679.9,130.2 679.3,132.5 677.7,133.3 675.5,133.7 675.0,135.0 672.9,135.4 670.0,134.3 669.8,132.0 667.7,131.9 664.5,129.4 662.3,129.1 659.3,127.7 657.3,127.4 656.1,128.0 654.2,127.9 652.2,129.5 649.8,130.0 649.3,128.0 649.7,125.1 647.5,124.2 648.2,122.3 646.4,122.1 647.0,119.8 649.6,120.5 652.0,119.6 650.0,117.9 649.2,116.3 647.0,117.0 646.7,119.1ZM634.9,150.2 633.4,148.7 633.3,147.3 632.5,147.3 632.9,145.3 631.5,143.1 628.1,141.6 626.2,139.0 626.8,136.8 628.2,135.9 628.0,134.2 626.2,133.4 622.8,127.9 623.4,127.0 622.5,123.8 624.4,123.0 624.9,124.1 626.3,125.3 628.2,125.7 629.2,125.6 632.5,123.6 633.5,123.4 634.3,124.2 633.4,125.6 635.1,127.0 635.8,126.9 636.7,128.9 639.3,129.5 641.2,130.9 645.2,131.4 649.5,130.7 649.8,130.0 652.2,129.5 654.2,127.9 656.1,128.0 657.3,127.4 659.3,127.7 662.3,129.1 664.5,129.4 667.7,131.9 669.8,132.0 670.0,134.3 668.1,139.8 669.3,140.2 668.2,141.7 669.3,145.7 671.4,146.2 671.6,148.0 669.1,150.5 671.6,153.6 674.2,154.8 674.3,157.3 675.6,157.7 675.9,159.0 671.9,160.4 670.8,163.7 659.4,161.8 658.3,158.4 656.9,157.9 654.8,158.4 652.0,159.8 648.6,158.9 645.8,156.7 643.1,155.9 639.2,149.6 637.7,150.0 635.9,149.1ZM599.2,142.5 600.2,139.4 601.7,138.3 601.2,137.2 600.0,137.1 599.7,135.0 601.9,132.6 602.1,131.1 603.0,131.6 606.0,130.8 607.5,131.4 609.8,131.3 613.0,130.3 617.6,129.9 616.2,131.7 614.7,132.3 615.0,134.4 613.9,137.7 602.3,143.6ZM629.2,125.6 628.2,125.7 627.1,123.7 625.8,123.7 625.0,122.9 621.3,121.5 621.5,120.2 621.1,119.2 624.9,118.8 626.6,120.0 626.0,120.7 627.5,121.6 626.7,122.5 629.1,123.7ZM530.6,69.8 534.2,66.3 535.1,63.1 533.3,61.7 533.1,58.0 534.9,55.4 537.7,55.4 538.7,54.3 537.7,53.4 542.0,49.5 546.6,44.4 549.2,44.4 550.0,42.9 555.2,43.3 555.6,41.5 557.3,41.4 565.4,44.6 565.5,48.9 566.4,50.0 561.6,50.8 558.9,52.7 559.4,54.4 549.6,59.0 547.6,62.9 549.5,64.9 552.2,66.4 549.6,69.6 546.7,70.2 545.7,74.9 544.1,77.5 540.7,77.2 539.2,79.4 536.0,79.6 535.1,76.9 532.7,73.8ZM578.3,77.3 581.2,78.0 581.6,78.7 583.0,78.4 585.8,79.0 586.0,80.3 585.4,81.1 587.2,82.9 588.3,83.4 588.1,83.9 590.0,84.4 590.8,85.1 589.7,85.7 587.0,85.9 588.3,88.6 585.9,88.8 585.1,89.4 584.9,90.8 581.3,90.6 580.5,90.0 579.5,90.5 570.4,89.1 568.2,89.2 566.7,90.0 565.4,90.1 565.3,88.8 564.4,87.5 566.1,87.0 566.1,85.9 565.4,84.8 565.2,83.6 567.9,83.6 570.9,82.5 571.6,81.0 573.9,80.1 573.6,78.8ZM589.3,88.7 590.0,88.1 593.8,88.0 595.5,89.5 594.8,90.1 595.1,91.0 597.3,91.1 598.3,92.3 598.2,92.8 601.7,93.8 603.9,93.4 605.6,94.7 611.3,95.6 611.3,96.4 610.2,97.8 610.8,99.4 610.4,100.3 607.7,100.5 606.3,101.3 606.2,102.5 604.0,102.7 602.1,103.6 599.5,103.8 597.1,104.8 597.3,106.5 598.6,107.2 601.5,107.0 600.9,108.0 597.9,108.5 594.1,110.1 592.6,109.5 593.2,108.2 590.2,107.4 593.3,106.0 592.5,105.3 588.2,104.6 588.0,103.6 585.4,103.9 582.2,107.5 581.0,107.0 579.7,107.5 578.4,107.0 579.1,106.7 580.4,104.8 580.2,104.3 583.4,104.4 582.1,103.0 581.7,101.8 580.7,101.4 580.9,100.4 579.6,99.7 576.5,98.7 572.8,99.4 572.1,100.0 569.1,100.7 567.8,100.1 564.3,99.7 563.1,100.3 562.9,99.6 561.3,98.8 562.7,97.0 563.3,97.1 562.6,95.9 565.1,93.6 566.5,93.3 566.7,92.5 565.4,90.1 566.7,90.0 568.2,89.2 570.4,89.1 579.5,90.5 580.5,90.0 581.3,90.6 584.9,90.8 585.1,89.4 585.9,88.8ZM565.2,83.6 565.4,84.8 566.1,85.9 566.1,87.0 564.4,87.5 566.7,92.5 566.5,93.3 565.1,93.6 562.6,95.9 563.3,97.1 560.0,95.9 558.0,96.3 556.7,96.0 555.1,96.6 553.7,95.6 552.5,96.0 551.1,94.5 549.0,94.3 548.8,93.4 546.9,93.1 546.4,93.8 544.9,93.3 545.1,92.5 543.0,92.3 541.7,91.4 540.6,89.6 540.8,88.6 540.1,87.2 539.1,86.2 539.9,85.4 539.2,84.0 549.0,81.0 551.7,81.4 551.9,82.1 563.1,82.4 564.6,82.7ZM547.2,99.7 547.0,100.8 545.4,100.8 545.9,101.4 544.5,103.7 542.0,103.7 540.6,104.4 534.4,103.4 533.8,102.5 531.0,102.9 530.7,103.5 526.3,102.5 526.7,101.3 527.5,101.2 528.9,101.9 529.3,101.2 531.7,101.3 533.7,100.8 535.1,100.9 535.9,101.5 536.2,101.0 535.8,99.2 536.8,98.8 537.8,97.6 539.8,98.5 542.4,97.1 544.5,98.0 545.8,97.8 547.1,98.3ZM561.3,98.8 562.9,99.6 563.1,100.3 561.4,100.9 558.4,104.7 556.2,105.2 554.4,105.1 551.3,106.2 549.0,105.7 546.0,104.2 545.5,103.2 545.0,103.2 545.9,101.4 545.4,100.8 547.0,100.8 547.2,99.7 549.6,100.7 556.2,99.1 557.8,98.3 560.8,99.1ZM573.9,99.4 576.5,98.7 579.6,99.7 580.9,100.4 580.7,101.4 581.7,101.8 582.1,103.0 583.4,104.4 580.2,104.3 580.4,104.8 579.1,106.7 578.4,107.0 577.9,105.7 578.1,103.3 574.8,99.7ZM578.4,107.0 579.7,107.5 581.0,107.0 582.2,107.5 582.3,108.2 580.9,108.8 580.1,108.6 579.3,111.9 575.7,110.6 572.4,111.3 571.0,112.0 563.7,111.6 562.4,110.0 563.1,109.5 562.4,109.2 561.5,109.8 559.9,109.0 559.7,107.8 558.0,107.2 557.7,106.3 556.2,105.2 558.4,104.7 561.4,100.9 564.3,99.7 567.8,100.1 569.1,100.7 572.1,100.0 572.8,99.4 573.9,99.4 574.8,99.7 578.1,103.3 577.9,105.7ZM573.6,78.8 573.9,80.1 571.6,81.0 570.9,82.5 567.9,83.6 565.2,83.6 564.6,82.7 563.1,82.4 563.2,81.0 559.1,80.0 558.5,77.7 561.7,76.8 569.1,76.7 569.4,77.3 570.9,77.5ZM575.8,73.7 577.1,74.3 578.3,77.3 573.6,78.8 570.9,77.5 569.4,77.3 569.1,76.7 561.7,76.8 558.5,77.7 558.6,75.6 559.9,73.9 562.6,72.9 564.8,75.0 567.0,74.9 567.5,72.8 569.9,72.3 573.5,73.7ZM577.7,68.1 578.1,68.6 576.2,70.2 577.0,72.8 575.8,73.7 573.5,73.7 569.9,72.3 567.5,72.8 567.9,71.2 566.8,71.5 565.1,70.5 564.8,68.9 571.8,67.7ZM539.2,84.0 539.9,85.4 539.1,86.2 540.1,87.2 540.8,88.6 540.6,89.6 541.7,91.4 540.5,91.7 539.7,91.3 534.0,93.7 534.8,95.7 537.8,97.6 536.8,98.8 535.8,99.2 536.2,101.0 535.9,101.5 535.1,100.9 533.7,100.8 531.7,101.3 529.3,101.2 528.9,101.9 527.5,101.2 526.7,101.3 523.7,100.5 523.1,101.1 520.7,101.1 521.1,99.1 522.5,97.2 518.5,96.7 517.2,95.9 517.3,94.7 516.8,94.1 517.1,92.2 516.6,89.3 518.3,89.3 519.0,88.3 519.7,85.7 519.2,84.8 519.7,84.2 522.0,84.0 522.6,84.6 524.4,83.3 523.8,82.2 523.7,80.7 525.8,81.0 527.6,80.6 527.6,81.7 530.4,82.3 530.4,83.3 533.2,82.8 534.8,82.0ZM562.9,110.5 563.7,111.6 571.0,112.0 572.4,111.3 575.7,110.6 579.3,111.9 577.9,113.1 576.9,115.1 577.8,116.6 575.4,116.3 572.5,117.1 572.5,118.5 570.0,118.8 568.0,117.8 565.8,118.6 563.8,118.5 563.6,116.7 562.2,115.8 562.6,115.4 562.3,115.1 562.8,114.2 563.9,113.3 562.5,112.1 562.3,111.1ZM573.0,135.3 572.7,136.1 568.7,136.3 568.7,135.9 565.3,135.3 565.8,134.2 567.4,135.1 571.6,135.1 571.5,135.6ZM563.8,118.5 565.8,118.6 568.0,117.8 570.0,118.8 572.5,118.5 572.5,117.1 573.9,117.9 573.0,119.6 572.4,119.9 569.2,119.6 565.9,120.3 567.8,121.9 564.8,122.3 563.4,120.9 562.9,121.5 563.5,123.2 564.9,124.5 563.8,125.1 566.7,127.2 566.8,128.7 564.2,128.0 565.0,129.4 563.3,129.7 564.3,132.2 562.5,132.2 560.2,131.0 558.7,126.9 556.2,124.1 556.0,123.3 557.3,121.9 557.4,121.0 558.3,120.6 558.4,119.9 560.2,119.6 561.3,119.0 562.8,119.1ZM624.4,130.1 623.0,130.6 622.1,129.8 618.8,129.5 613.0,130.3 609.8,131.3 607.5,131.4 606.0,130.8 603.0,131.6 602.1,131.1 601.9,132.6 600.4,133.8 599.4,132.6 600.4,131.5 598.8,131.8 596.4,131.1 594.5,132.7 590.3,133.0 588.1,131.5 585.1,131.5 584.4,132.6 582.5,132.9 579.8,131.5 576.8,131.5 575.1,128.7 573.1,127.2 574.5,125.0 572.7,123.7 575.8,121.1 580.1,120.9 581.2,118.8 586.5,119.2 589.9,117.4 593.1,116.6 597.7,116.6 606.5,119.6 609.8,119.2 612.1,119.4 615.4,118.0 618.4,117.8 621.1,119.2 621.5,120.2 621.3,121.5 624.4,123.0 622.5,123.8 623.4,127.0 622.8,127.9ZM572.5,117.1 575.4,116.3 577.8,116.6 578.1,117.7 580.5,118.6 580.0,119.3 576.7,119.4 573.2,121.8 572.4,119.9 573.0,119.6 573.9,117.9ZM558.4,119.9 558.3,120.6 557.4,121.0 557.3,121.9 556.0,123.3 553.9,121.5 553.7,120.2 554.3,117.4 553.6,116.1 554.8,114.8 555.0,115.3 555.8,115.0 557.0,116.1 556.8,118.0 557.2,119.2ZM546.0,104.2 549.0,105.7 551.3,106.2 552.3,105.8 553.9,107.7 552.8,108.7 551.5,108.1 547.2,107.7 545.9,107.7 545.3,108.3 544.3,107.7 543.8,108.8 549.1,113.8 551.6,114.9 551.3,115.3 544.5,112.5 542.2,110.4 542.7,110.2 541.4,109.1 541.4,108.1 539.6,107.7 538.8,108.9 537.9,108.0 538.1,106.9 540.0,107.0 540.5,106.6 542.6,107.1 542.6,106.3 543.5,106.0 543.8,104.9ZM526.7,101.3 526.3,102.5 529.0,103.1 528.8,104.2 527.6,104.7 525.5,104.3 524.9,105.5 523.6,105.5 523.1,105.1 521.5,106.0 520.2,106.2 519.0,105.6 518.1,104.4 516.7,104.8 516.8,103.5 518.8,102.0 518.7,101.3 520.0,101.5 520.7,101.1 523.1,101.1 523.7,100.5ZM516.8,94.1 517.3,94.7 517.2,95.9 515.8,95.8 516.1,94.2ZM517.1,92.2 516.8,94.1 516.1,94.2 515.8,95.8 513.3,94.5 511.9,94.7 508.7,92.3 507.4,92.2 507.0,91.3 513.8,90.3ZM519.2,84.8 519.7,85.7 519.0,88.3 518.3,89.3 516.6,89.3 517.1,92.2 513.8,90.3 511.2,90.9 509.2,90.7 510.6,89.9 513.1,85.9 516.9,84.7ZM474.9,117.0 477.0,115.9 477.7,117.2 481.5,117.0 482.3,118.4 481.0,119.1 480.9,121.3 480.5,121.7 480.4,123.0 479.2,123.3 480.3,124.9 479.5,126.7 480.5,127.6 479.1,129.4 479.3,130.3 478.2,131.0 476.7,130.6 475.3,130.9 475.7,128.7 475.4,127.0 474.2,126.8 473.5,125.7 473.8,123.9 474.9,122.9 475.6,120.1ZM479.3,130.3 479.1,129.4 480.5,127.6 479.5,126.7 480.3,124.9 479.2,123.3 480.4,123.0 480.5,121.7 480.9,121.3 481.0,119.1 482.3,118.4 481.5,117.0 477.7,117.2 477.0,115.9 474.9,117.0 475.0,115.0 473.9,113.8 477.8,111.8 487.9,112.8 494.7,112.7 495.8,113.8 500.9,115.1 501.9,114.5 505.1,115.7 508.3,115.4 508.4,117.0 505.8,118.8 502.3,119.4 502.0,120.3 500.3,121.9 499.2,124.1 500.3,125.7 498.7,127.0 498.1,128.8 496.0,129.3 494.0,131.5 487.9,131.5 485.1,133.5 483.7,133.3 482.7,132.3 481.9,130.7ZM482.8,83.7 483.2,85.7 481.1,88.2 476.2,89.8 472.3,89.4 474.5,86.5 473.1,83.7 479.0,80.2 479.5,81.7 479.0,83.2ZM960.5,291.9 964.2,294.9 963.2,295.6 961.6,294.8 957.9,292.1 955.6,289.2 956.8,289.2ZM950.3,262.5 951.1,263.4 949.2,263.4 948.1,261.7ZM949.1,260.0 948.7,260.5 946.6,258.1 946.1,256.4 947.0,256.4ZM946.8,260.8 944.0,260.5 943.4,260.1 943.6,259.0 945.5,259.4ZM943.4,255.6 944.2,257.1 939.5,253.9 939.9,253.7ZM936.5,252.8 937.6,253.7 937.1,253.9 935.8,253.3 934.7,252.1 934.8,251.7ZM991.3,344.6 988.9,348.0 986.8,349.1 986.3,348.4 985.1,348.0 986.7,345.7 985.8,344.2 982.8,343.1 982.9,342.1 984.9,341.1 985.4,339.0 985.3,337.2 984.2,334.8 980.7,331.2 979.5,329.2 980.6,329.0 982.1,330.6 984.2,331.3 985.0,333.8 987.0,336.7 987.1,334.8 988.4,335.6 988.8,337.7 991.0,338.6 992.9,338.8 994.5,337.7 995.9,338.0 994.4,342.1 992.2,342.1 991.5,342.9 991.8,344.1ZM971.3,354.3 975.3,351.4 976.6,349.4 977.6,348.7 978.0,347.1 980.0,345.8 981.2,348.1 983.2,347.0 984.0,348.2 984.0,349.4 979.8,353.8 980.8,355.1 978.6,355.2 976.3,356.2 973.9,360.9 970.4,362.9 967.8,362.8 966.0,361.9 963.0,361.7 962.5,360.7 964.0,358.6 967.5,355.9ZM910.2,346.7 911.9,346.9 912.1,350.2 911.2,351.1 910.9,353.4 909.9,352.6 908.0,354.5 905.7,354.3 904.0,351.9 903.6,350.1 902.0,347.7 902.1,346.4 906.6,347.6ZM850.4,322.8 845.1,324.9 844.5,326.3 843.5,327.5 839.4,327.8 836.9,327.3 833.0,327.7 831.4,329.2 830.6,329.1 827.8,330.7 824.0,330.6 819.5,328.3 819.6,326.7 821.0,326.4 821.4,325.7 821.7,322.8 819.4,316.8 819.6,315.2 818.4,312.5 817.1,311.4 816.8,309.3 814.8,305.9 816.1,307.1 815.1,304.5 816.5,305.3 817.3,306.4 817.3,305.0 815.0,301.1 816.2,297.4 815.9,295.8 817.1,293.8 817.3,295.9 818.5,294.0 824.2,290.8 825.5,290.6 826.2,291.0 830.1,289.6 831.3,288.8 832.8,288.8 835.7,288.0 839.6,283.9 839.8,281.3 841.7,278.9 842.9,281.3 844.1,280.7 843.1,279.4 843.9,278.1 845.2,278.7 845.5,276.6 847.7,274.1 849.1,273.6 849.1,272.9 850.3,273.2 850.4,272.5 853.0,271.7 855.0,273.0 856.6,274.6 860.1,274.9 859.5,273.4 860.8,271.2 862.1,270.4 861.6,269.7 862.8,268.2 864.5,267.2 865.9,267.5 868.3,267.0 868.2,265.6 866.2,264.6 867.7,264.2 869.5,264.9 871.0,266.1 873.3,266.8 874.1,266.5 875.8,267.4 877.5,266.6 878.5,266.8 879.1,266.3 880.4,267.6 878.6,270.3 877.7,270.3 878.0,271.5 876.2,274.2 876.4,275.0 880.7,277.4 884.2,280.0 886.4,280.7 886.8,281.6 889.5,282.5 891.3,281.6 892.4,278.9 893.6,275.1 893.1,271.4 893.5,269.3 894.0,268.7 893.6,267.8 894.8,264.0 895.9,263.0 896.7,264.3 896.9,266.1 897.5,266.4 897.7,267.6 898.7,269.0 898.8,271.6 899.8,273.7 901.6,272.7 903.8,275.0 903.5,276.2 904.1,278.6 904.5,280.0 905.2,280.3 906.0,282.7 905.7,284.1 906.6,286.0 913.5,290.0 913.1,290.6 914.7,292.4 915.8,295.4 916.9,294.8 918.0,296.0 918.7,295.6 919.2,298.5 924.6,303.5 925.4,305.8 925.3,309.1 926.6,311.4 926.4,313.9 925.2,317.6 924.7,321.2 923.5,323.8 921.4,325.1 918.7,331.0 917.6,332.4 916.9,334.5 916.7,337.3 915.1,338.3 912.0,338.4 909.4,339.5 906.4,341.8 902.4,340.0 902.9,338.6 901.3,339.1 898.9,341.1 890.7,338.9 888.9,337.2 887.7,333.7 886.3,332.6 883.7,332.3 884.6,330.9 883.9,328.8 882.6,330.8 880.1,331.3 881.5,329.7 882.0,328.1 883.0,326.8 882.8,324.7 880.5,327.1 878.8,328.0 877.7,330.3 875.6,329.1 875.7,327.6 872.5,324.6 873.0,323.9 869.4,322.3 867.5,322.2 864.8,320.8 859.8,321.1 853.1,323.0ZM727.2,212.4 726.8,215.3 725.6,216.1 723.2,216.8 721.9,214.5 721.4,210.6 722.6,206.0 724.6,207.6ZM804.1,182.8 801.8,181.9 801.7,179.5 803.1,178.3 806.1,177.5 807.7,177.6 808.4,178.6 807.1,179.8 806.5,181.4ZM722.9,115.7 722.7,114.1 724.6,113.4 722.1,108.6 729.1,106.8 731.1,101.9 736.6,102.8 738.1,101.5 738.2,98.7 740.6,98.5 742.7,96.6 743.8,96.4 744.5,98.3 746.8,99.8 750.8,100.9 752.7,103.1 751.6,106.3 752.6,107.5 759.7,108.4 763.0,110.1 764.7,110.4 766.0,113.0 767.6,114.7 776.4,115.2 780.1,114.8 782.9,115.2 787.0,116.9 790.3,116.9 791.6,117.8 794.8,116.3 799.3,115.3 803.5,115.2 806.7,114.2 810.6,111.8 809.3,109.8 810.8,108.0 815.2,108.9 817.9,107.4 822.2,106.3 824.2,104.5 826.2,103.7 830.2,103.3 832.4,103.6 832.7,102.6 830.2,100.7 828.0,99.8 825.8,100.8 823.1,100.4 821.5,100.8 820.8,99.6 824.1,94.8 827.4,95.8 831.4,94.0 831.3,92.8 833.8,89.9 835.4,89.0 835.3,87.5 833.8,86.8 836.1,85.4 839.6,84.9 843.3,84.8 847.4,85.7 849.9,86.7 853.6,92.4 854.6,95.1 859.4,96.0 862.7,98.0 863.9,100.6 868.1,100.6 870.5,99.5 875.1,98.7 872.5,102.2 871.6,105.2 869.7,107.9 866.3,107.4 864.0,108.4 864.7,110.8 864.3,114.1 862.9,114.2 862.9,115.6 861.1,113.9 860.0,115.5 855.7,116.7 856.1,118.1 853.7,118.0 852.4,117.2 850.5,119.1 847.4,120.6 845.2,122.4 841.3,123.2 839.3,124.5 836.3,125.3 837.7,124.0 837.2,122.9 839.4,121.0 837.9,119.6 832.3,122.5 830.6,124.3 827.9,124.4 826.5,125.7 827.9,127.6 830.2,128.1 830.3,129.3 832.5,130.1 835.6,128.1 838.1,129.2 839.9,129.3 840.3,130.7 836.4,131.5 835.1,133.0 832.4,134.4 831.0,136.4 834.0,137.9 835.1,140.6 838.6,145.3 838.6,147.4 836.8,148.1 837.5,149.6 839.1,150.5 838.0,154.9 836.5,155.2 829.6,165.1 821.9,170.0 818.8,170.4 817.1,171.6 816.1,170.7 814.6,172.1 810.7,173.5 807.7,173.9 806.8,176.8 805.2,177.0 804.5,175.0 805.2,173.9 801.5,173.0 800.1,173.5 797.3,172.7 796.0,171.6 796.5,170.0 793.9,169.5 792.6,168.5 790.2,169.9 785.3,170.3 782.4,171.3 782.8,174.5 781.3,174.4 781.0,172.6 778.9,173.4 775.7,171.9 776.5,169.6 774.7,169.0 774.1,166.5 771.1,167.0 771.5,163.7 774.1,161.3 774.1,156.9 772.9,156.3 772.0,154.6 767.4,154.4 768.3,153.2 767.0,151.5 765.0,152.7 762.7,152.0 759.5,153.8 757.0,155.8 754.7,156.2 753.5,155.4 750.0,154.7 748.5,155.4 746.7,157.5 746.5,155.3 744.8,155.9 738.4,155.0 736.1,153.8 734.0,153.2 733.1,151.9 731.5,151.5 728.7,149.7 726.5,148.8 725.3,149.5 718.7,145.8 717.9,142.7 719.9,143.1 720.0,141.7 718.9,140.3 719.2,138.0 716.2,134.7 711.6,133.6 710.8,131.5 708.8,130.2 708.3,129.4 708.0,126.7 706.3,126.1 705.4,126.4 704.7,123.8 705.4,123.2 705.1,122.5 707.7,121.2 709.6,120.7 712.6,121.0 713.6,119.3 717.2,118.9 718.2,117.8 722.6,116.3ZM838.3,165.6 835.4,172.3 833.9,170.0 833.6,167.9 835.3,165.2 837.5,163.1 838.8,163.9ZM529.0,103.1 530.7,103.5 531.0,102.9 533.8,102.5 534.4,103.4 538.4,104.1 538.1,105.5 538.7,106.7 536.5,106.3 534.2,107.3 534.1,109.4 535.0,110.9 537.6,112.3 539.0,114.6 542.1,116.8 544.2,116.8 544.9,117.4 544.1,117.9 548.7,119.8 551.0,121.2 551.3,121.8 550.8,122.7 549.3,121.5 546.9,121.0 545.7,122.8 547.7,123.8 547.4,125.3 546.2,125.4 544.7,127.8 543.6,128.0 544.1,125.7 544.7,125.1 542.8,122.1 541.7,121.7 540.8,120.5 539.1,120.0 537.9,118.9 535.8,118.7 531.1,115.7 529.2,114.1 528.3,111.3 524.7,110.1 523.4,110.5 521.8,111.8 520.7,112.0 521.0,110.8 519.5,110.4 518.7,108.3 519.7,107.4 518.9,106.4 519.0,105.6 520.2,106.2 521.5,106.0 523.1,105.1 523.6,105.5 524.9,105.5 525.5,104.3 527.6,104.7 528.8,104.2ZM541.0,127.4 543.1,127.1 542.1,129.3 542.5,130.2 541.9,131.6 534.5,128.9 534.9,127.4ZM524.2,119.7 525.6,118.9 527.2,120.8 526.9,124.5 525.6,124.3 524.5,125.3 523.4,124.5 523.3,121.2 522.7,119.6ZM527.6,80.6 525.8,81.0 523.7,80.7 522.6,79.1 522.5,76.3 523.7,74.7 526.2,74.5 529.4,73.0 529.3,74.4 528.5,75.3 528.8,76.1 530.3,76.5 529.6,77.6 528.8,77.2 526.8,79.3ZM534.4,77.5 535.3,78.9 533.6,81.1 530.7,79.5 530.3,78.4ZM482.8,83.7 479.0,83.2 479.5,81.7 479.0,80.2 481.3,80.1 484.3,81.8ZM491.4,85.0 491.8,83.4 489.9,81.6 486.5,81.1 485.9,80.4 486.9,79.1 486.0,78.4 484.5,79.7 484.3,77.0 482.9,75.6 483.9,72.7 486.1,70.5 491.7,70.5 488.7,73.5 494.6,73.1 493.8,75.4 491.3,77.9 494.2,78.0 496.9,81.6 498.8,82.0 501.3,86.3 504.7,86.8 504.3,88.6 502.9,89.4 504.0,90.9 501.5,92.3 497.8,92.3 493.1,93.1 491.8,92.5 490.0,93.8 487.4,93.5 485.4,94.6 484.0,94.0 488.0,91.1 490.5,90.5 486.2,90.0 485.4,88.9 488.3,88.1 486.7,86.6 487.3,84.7ZM459.7,48.7 459.1,50.5 462.2,52.4 458.6,54.5 448.2,57.0 436.8,55.7 439.5,54.4 433.5,53.1 438.4,52.5 438.3,51.7 432.4,51.1 434.3,49.3 438.5,48.9 442.8,50.7 447.1,49.2 450.6,50.0 455.1,48.5ZM628.9,117.1 629.7,117.1 631.6,118.8 632.8,119.0 635.0,117.2 637.8,120.6 639.1,120.8 640.0,121.5 637.7,121.7 636.7,124.9 635.7,125.5 635.8,126.9 635.1,127.0 633.4,125.6 634.3,124.2 633.5,123.4 632.5,123.6 629.2,125.6 629.1,123.7 626.7,122.5 627.5,121.6 626.0,120.7 626.6,120.0 624.9,118.8 625.6,118.3 629.2,119.3 629.5,118.9 628.2,117.4ZM628.2,125.7 626.3,125.3 624.9,124.1 624.4,123.0 625.0,122.9 625.8,123.7 627.1,123.7ZM611.0,112.7 611.3,112.4 617.8,113.3 621.5,114.6 622.0,115.1 623.7,114.7 626.3,115.3 627.2,116.4 628.9,117.1 628.2,117.4 629.5,118.9 629.2,119.3 627.7,119.1 625.6,118.3 624.9,118.8 621.1,119.2 618.4,117.8 615.4,118.0 615.8,116.8 615.1,114.9ZM835.6,198.0 834.2,195.9 836.6,196.0 837.6,197.0 836.8,199.4ZM840.5,205.6 841.2,204.8 841.5,203.1 843.1,202.9 842.6,204.8 844.7,202.1 844.4,204.8 841.7,208.3 839.9,206.4ZM851.0,210.0 851.5,213.4 850.5,215.9 849.5,213.1 848.2,214.5 849.1,216.5 848.3,217.8 845.1,216.2 844.3,214.2 845.1,212.9 843.4,211.6 842.5,212.7 841.2,212.6 839.1,214.2 838.7,213.4 839.8,211.0 843.0,209.2 844.0,210.4 846.1,209.7 846.6,208.4 848.5,208.4 848.4,206.2 850.6,207.5ZM829.2,207.5 825.5,210.1 826.8,208.1 830.5,204.5 832.0,201.8 832.5,204.0ZM839.8,182.7 839.4,183.9 840.3,185.9 839.6,188.2 838.0,189.1 837.5,191.3 838.1,193.5 839.6,193.8 840.8,193.5 844.3,195.0 844.0,196.6 844.9,197.2 844.7,198.5 842.5,197.1 841.5,195.7 840.8,196.7 839.0,195.0 836.5,195.5 835.1,194.8 835.2,193.7 836.1,193.0 835.3,192.3 834.9,193.3 833.5,191.7 833.1,190.5 833.0,187.9 834.1,188.8 834.4,184.4 835.3,181.9 837.0,181.9 838.7,182.7 839.6,182.0ZM839.0,201.6 838.6,200.3 840.2,201.2 842.0,201.2 841.9,202.3 838.9,204.3ZM848.6,199.5 849.4,202.6 847.3,201.9 848.0,204.6 846.7,205.2 846.6,203.2 845.7,203.1 845.3,201.4 846.9,201.6 846.9,200.6 845.2,198.5 847.9,198.5ZM778.0,215.4 778.5,214.9 780.8,216.1 781.0,217.5 782.8,217.2 783.7,216.1 786.0,218.0 787.2,219.8 787.0,223.0 787.5,225.6 788.5,226.3 789.6,228.8 789.5,229.7 787.6,229.9 781.6,225.7 781.3,224.2 779.7,222.4 779.3,220.1 778.3,218.6 778.6,216.6ZM827.5,221.8 821.8,221.4 820.9,224.5 819.8,225.5 818.4,229.4 816.1,230.0 813.5,229.2 812.2,229.4 810.5,230.8 808.8,230.6 807.0,231.2 805.1,229.6 804.6,227.8 806.7,228.7 808.8,228.2 809.4,225.8 813.9,224.7 817.2,220.8 818.5,222.2 819.1,221.3 820.4,221.3 820.7,218.2 822.8,216.3 824.2,214.1 825.4,214.1 826.8,215.5 826.9,216.7 831.1,218.3 830.9,219.4 829.0,219.5 829.5,220.9ZM820.7,218.2 820.4,221.3 819.1,221.3 818.5,222.2 817.2,220.8ZM538.4,104.1 540.6,104.4 542.0,103.7 544.5,103.7 545.0,103.2 545.5,103.2 546.0,104.2 543.8,104.9 543.5,106.0 542.6,106.3 542.6,107.1 540.5,106.6 540.0,107.0 538.1,106.9 538.7,106.7 538.1,105.5ZM579.4,41.5 579.0,43.4 583.3,45.3 580.7,47.4 583.9,50.5 582.1,52.9 584.6,55.0 583.4,56.8 587.5,58.7 586.5,60.1 578.0,65.3 572.9,65.5 563.5,67.1 561.9,65.6 559.2,64.7 559.8,61.9 558.5,59.4 559.8,57.8 562.3,56.1 570.6,52.5 570.3,51.3 566.4,50.0 565.5,48.9 565.4,44.6 557.3,41.4 559.0,40.6 562.1,42.1 565.7,42.0 568.7,42.6 571.4,41.4 572.7,39.4 577.0,38.4 580.6,39.5ZM562.7,97.0 560.8,99.1 557.8,98.3 556.2,99.1 549.6,100.7 547.2,99.7 546.9,98.7 547.5,97.7 549.7,97.5 551.5,95.8 553.7,95.6 555.1,96.6 556.7,96.0 558.0,96.3 560.0,95.9ZM541.7,91.4 543.0,92.3 545.1,92.5 544.9,93.3 546.4,93.8 546.9,93.1 548.8,93.4 549.0,94.3 551.1,94.5 552.4,95.8 550.5,96.5 549.7,97.5 547.5,97.7 547.1,98.3 542.4,97.1 539.8,98.5 534.8,95.7 534.0,93.7 539.7,91.3 540.5,91.7ZM601.2,193.3 600.9,192.2 602.4,186.2 603.2,185.4 605.3,184.9 606.7,183.3 609.1,189.1 614.4,193.1 618.3,197.2 619.7,198.1 618.8,198.7 617.6,198.5 613.6,194.1 611.2,193.0 609.3,193.0 608.6,192.4 607.0,193.0 605.3,191.8 604.4,193.9ZM894.1,124.5 891.6,127.3 891.6,130.2 890.6,132.4 891.0,133.8 889.6,135.7 886.0,137.0 881.2,137.2 877.2,140.4 875.3,139.3 875.2,137.2 870.4,137.8 867.1,139.2 863.9,139.2 866.7,141.3 864.8,146.0 863.0,147.1 861.7,146.1 862.4,143.6 860.6,142.7 859.5,140.8 862.1,140.0 863.6,138.2 866.3,136.8 868.4,134.9 873.9,134.1 876.9,134.6 879.8,129.7 881.6,131.0 887.3,127.2 889.0,123.8 888.6,120.7 889.7,118.9 892.7,118.4 894.2,122.2ZM901.7,111.2 903.7,110.0 904.3,113.2 900.2,113.9 897.7,116.7 893.4,114.8 891.9,117.8 888.8,117.9 888.4,115.1 889.8,113.0 892.7,112.8 894.4,106.8 897.6,109.7ZM867.7,140.4 869.2,138.7 870.8,139.0 872.0,137.9 874.0,138.5 874.4,139.4 872.8,141.1 871.6,140.2 870.2,140.9 869.5,142.5 867.7,141.7ZM338.4,289.4 339.2,290.9 339.1,294.7 342.0,295.2 343.1,294.7 345.0,295.4 345.5,296.3 346.1,299.9 347.1,300.0 348.2,299.6 349.2,300.1 349.2,301.6 347.8,307.3 345.3,309.4 343.1,309.9 337.2,308.7 339.9,304.5 339.5,303.2 336.6,302.1 333.3,300.1 331.0,299.7 325.9,295.1 327.0,291.8 327.0,290.3 328.4,287.9 333.2,287.1 335.8,287.1 338.4,288.5ZM644.4,180.6 647.5,187.1 645.5,187.8 644.9,190.0 637.7,192.5 635.2,194.4 633.2,194.4 631.5,195.6 626.7,196.4 625.0,198.1 620.8,198.2 620.1,196.6 620.1,195.1 618.3,191.1 618.9,190.9 618.8,187.9 620.1,187.0 619.8,185.9 620.5,184.5 621.6,185.2 625.6,184.9 629.9,185.3 630.6,186.3 631.9,185.8 633.8,182.9 636.4,181.6ZM597.1,151.8 600.2,152.2 602.1,150.4 604.2,150.0 604.6,149.1 605.6,148.6 602.8,145.8 608.9,144.0 612.2,144.8 616.4,146.7 624.2,152.3 631.8,152.8 632.5,154.1 634.5,154.0 635.6,156.4 636.9,157.1 637.4,158.0 639.3,159.2 639.6,162.2 641.1,164.6 642.0,165.1 642.7,164.9 644.4,169.4 652.8,170.8 653.4,170.3 654.6,172.2 652.8,177.8 644.4,180.6 636.4,181.6 633.8,182.9 631.9,185.8 630.6,186.3 629.9,185.3 625.6,184.9 621.6,185.2 620.5,184.5 619.8,185.9 620.1,187.0 618.8,187.9 617.4,184.8 616.0,183.8 614.5,181.5 613.7,179.2 611.8,177.3 610.6,176.8 608.7,174.2 608.5,170.6 606.9,167.5 604.1,165.9 602.6,162.2 601.8,161.6 597.6,155.4 596.2,155.4ZM590.9,135.7 591.5,135.0 593.5,135.1 596.0,134.2 594.2,135.4 594.4,135.9ZM590.9,135.7 592.7,135.7 593.0,136.1 594.1,135.9 594.5,136.2 591.6,137.3 590.3,136.9 589.6,135.8ZM494.0,135.6 495.0,137.4 496.1,142.0 496.9,142.6 496.4,143.7 492.7,144.2 491.5,145.2 489.9,145.5 489.7,147.5 486.5,148.6 485.4,150.0 480.4,151.2 475.9,153.2 475.6,158.0 473.9,158.1 473.0,158.7 470.7,158.4 468.4,158.7 467.4,160.8 466.6,161.0 465.3,164.5 461.4,167.5 460.5,171.4 459.0,173.6 452.7,173.8 452.9,172.5 453.9,171.8 454.8,170.3 454.6,169.4 455.6,167.4 457.1,165.7 458.1,165.2 458.8,163.6 458.9,162.1 459.9,160.4 461.7,159.4 463.5,156.6 464.9,155.4 467.5,155.1 471.1,152.5 473.4,150.2 472.7,146.7 474.2,142.9 476.0,141.0 480.8,138.6 483.5,134.0 485.6,134.0 487.2,135.2 489.9,135.0ZM602.4,172.2 569.4,172.2 569.4,152.1 568.6,149.9 569.3,148.2 568.9,147.0 569.9,145.6 573.6,145.6 580.3,147.6 583.6,145.9 586.0,145.7 588.0,146.0 588.8,147.4 589.4,146.5 593.8,147.3 595.2,146.6 597.0,151.4 594.9,156.0 594.2,156.5 592.0,154.4 590.1,150.4 589.8,150.7 594.7,160.7 599.1,166.9 598.6,167.4 598.7,169.2ZM569.4,172.2 569.4,177.8 566.3,177.8 566.2,178.9 544.1,168.3 539.3,170.9 537.7,169.3 533.3,168.1 532.1,166.4 529.9,165.1 528.6,165.6 527.6,164.1 527.5,162.9 525.9,160.8 527.0,159.7 526.9,155.2 527.4,152.9 526.3,149.1 527.7,148.5 527.6,146.2 531.8,143.4 531.9,141.3 535.2,142.2 536.3,142.0 538.7,142.5 542.3,143.7 543.6,146.2 550.1,147.9 553.0,149.3 555.7,147.3 555.1,145.1 555.9,143.8 557.9,142.5 559.8,142.1 563.6,142.7 564.5,143.9 569.2,144.7 569.9,145.6 568.9,147.0 569.3,148.2 568.6,149.9 569.4,152.1ZM632.7,211.1 624.9,219.4 621.3,219.6 618.8,221.5 617.0,221.6 616.3,222.4 614.4,222.4 613.2,221.5 610.7,222.7 609.9,223.8 605.9,223.3 602.4,221.0 600.4,221.0 599.5,220.1 599.5,218.5 598.1,218.0 596.4,215.0 595.1,214.4 594.7,213.3 593.2,211.9 591.5,211.7 592.5,210.1 594.0,210.1 595.2,203.8 596.5,203.0 597.9,199.8 599.6,198.4 601.2,193.3 604.4,193.9 605.3,191.8 607.0,193.0 608.6,192.4 609.3,193.0 611.2,193.0 613.6,194.1 615.6,196.0 617.6,198.5 615.7,201.0 616.0,202.6 618.2,202.5 618.8,203.0 618.2,204.0 621.3,207.8 630.4,211.1ZM617.6,198.5 618.8,198.7 619.7,198.1 620.3,198.9 620.2,200.1 618.7,200.7 619.8,201.5 618.8,203.0 618.2,202.5 616.0,202.6 615.7,201.0ZM636.0,201.6 635.9,207.1 632.7,211.1 630.4,211.1 621.3,207.8 618.2,204.0 619.8,201.5 620.8,202.0 622.5,204.3 629.6,203.3 634.4,201.7ZM594.2,236.0 585.5,236.2 582.8,237.3 582.2,237.1 582.2,235.0 582.8,233.9 583.0,231.7 584.6,228.9 586.6,227.2 585.5,226.8 585.6,223.6 586.8,222.8 588.6,223.4 590.8,222.8 592.8,222.8 594.5,221.5 595.8,223.5 597.3,228.0 594.1,233.0ZM584.5,236.5 585.6,238.1 585.4,239.7 584.6,240.0 583.2,239.9 582.3,241.4 580.6,241.2 581.4,237.8 582.2,237.1 582.8,237.3ZM551.6,114.9 549.1,113.8 545.7,111.0 543.8,108.8 544.3,107.7 545.3,108.3 545.9,107.7 547.2,107.7 553.8,108.7 553.1,109.9 554.4,111.0 554.0,112.3 552.0,113.3ZM562.2,115.8 563.6,116.7 563.8,118.5 562.8,119.1 561.3,119.0 560.2,119.6 558.4,119.9 557.2,119.2 556.8,118.0 557.7,116.5ZM552.3,105.8 554.4,105.1 556.2,105.2 557.7,106.3 558.0,107.2 559.7,107.8 559.9,109.0 561.5,109.8 562.4,109.2 563.1,109.5 562.4,110.0 562.9,110.5 562.3,111.1 562.5,112.1 563.9,113.3 562.8,114.2 562.3,115.1 562.6,115.4 562.2,115.8 559.9,116.0 560.5,114.8 557.8,113.1 556.3,114.4 556.5,114.2 553.4,112.4 554.0,112.3 554.4,111.0 553.1,109.9 553.8,108.7 552.8,108.7 553.9,107.7ZM555.8,115.0 555.0,115.3 554.8,114.8 553.6,116.1 553.8,117.0 551.3,115.3 552.0,113.3 553.4,112.4 556.5,114.2ZM557.2,117.1 557.0,116.1 555.8,115.0 556.9,114.2 557.3,113.3 557.8,113.1 560.5,114.8 559.9,116.0 557.7,116.5 557.5,117.1ZM328.7,203.4 330.8,203.2 330.7,205.2 327.9,205.3 328.7,204.5ZM585.6,223.6 583.2,221.7 582.5,220.6 579.0,221.4 577.7,221.1 575.6,217.9 573.5,216.8 572.8,215.1 569.8,212.5 569.8,211.6 566.4,209.4 568.2,208.6 569.6,204.8 571.6,204.4 573.5,206.8 574.3,207.0 575.3,206.6 577.3,206.7 577.7,207.2 580.5,207.2 580.6,206.7 582.0,206.1 582.3,205.3 583.3,204.7 585.7,206.4 587.1,206.1 590.0,202.6 589.8,200.9 589.1,200.1 590.8,199.9 591.0,199.3 592.2,199.5 591.9,201.6 592.2,203.6 593.7,204.7 594.0,207.0 594.3,207.0 594.4,209.2 594.0,210.1 592.5,210.1 591.5,211.7 593.2,211.9 594.7,213.3 595.1,214.4 596.4,215.0 598.1,218.0 592.8,222.8 590.8,222.8 588.6,223.4 586.8,222.8Z"/>
      <g id="arcs" filter="url(#glow)"></g>
      <g id="dots" filter="url(#glow)"></g>
      <g id="origin" filter="url(#glow)"></g>
    </svg>
    <div id="stats">
      <div class="stat"><b id="s-conn">0</b><span>Connections</span></div>
      <div class="stat"><b id="s-apps">0</b><span>Apps</span></div>
      <div class="stat"><b id="s-cty">0</b><span>Countries</span></div>
      <div class="stat"><b id="s-loc">0</b><span>Local network</span></div>
    </div>
    <div id="note"></div>
  </section>
  <aside id="side"><h2>Apps (click to focus)</h2><ul id="apps"></ul></aside>
  <section id="tablewrap">
    <table><thead><tr><th>App</th><th>Remote</th><th>Host</th><th>Location</th><th>Organization</th></tr></thead><tbody id="rows"></tbody></table>
  </section>
  <footer>
    <span id="foot-geo">Locations come from ip-api.com. Run with --no-geo to turn that off.</span>
    <span><kbd>Space</kbd> pause &nbsp; <kbd>F</kbd> fullscreen &nbsp; <kbd>T</kbd> table &nbsp; <kbd>H</kbd> clean view &nbsp; <kbd>Esc</kbd> focus off</span>
  </footer>
</div>
<div id="tip"></div>
<script nonce="__NONCE__">
(function(){
'use strict';
var NS='http://www.w3.org/2000/svg', W=1000, H=394.4, TOP=84, BOT=-58;
function $(s){return document.querySelector(s);}
function project(lon,lat){return [(lon+180)/360*W,(TOP-lat)/(TOP-BOT)*H];}
function mk(tag,attrs,parent){var e=document.createElementNS(NS,tag);for(var k in attrs)e.setAttribute(k,attrs[k]);if(parent)parent.appendChild(e);return e;}
var arcsG=$('#arcs'),dotsG=$('#dots'),originG=$('#origin'),tip=$('#tip'),statusEl=$('#status');
var colors={}, palette=["#00d4ff","#ff6b6b","#ffd166","#7bd88f","#b388ff","#ff8c42","#4dd0e1","#f06292","#a3e635","#60a5fa","#e879f9","#facc15"];
function colorFor(name){
  if(!colors[name]){var h=0;for(var i=0;i<name.length;i++)h=(h*31+name.charCodeAt(i))>>>0;colors[name]=palette[h%palette.length];}
  return colors[name];
}
// graticule
var g=$('#grat');
for(var lon=-150;lon<=150;lon+=30){var a=project(lon,TOP),b=project(lon,BOT);mk('line',{x1:a[0],y1:a[1],x2:b[0],y2:b[1],'class':'grat'},g);}
for(var lat=-30;lat<=60;lat+=30){var c=project(-180,lat),d=project(180,lat);mk('line',{x1:c[0],y1:c[1],x2:d[0],y2:d[1],'class':'grat'},g);}

var paused=false, stopped=false, filter=null, last=null, arcEls={}, dotEls={};

function arcPath(o,t){
  var mx=(o[0]+t[0])/2, my=(o[1]+t[1])/2, dist=Math.hypot(t[0]-o[0],t[1]-o[1]);
  var cy=Math.min(o[1],t[1])-dist*0.28-4;
  return 'M'+o[0].toFixed(1)+' '+o[1].toFixed(1)+' Q'+mx.toFixed(1)+' '+cy.toFixed(1)+' '+t[0].toFixed(1)+' '+t[1].toFixed(1);
}

function render(data){
  var o=data.origin?project(data.origin.lon,data.origin.lat):project(10,35);
  originG.replaceChildren();
  mk('circle',{cx:o[0],cy:o[1],r:2.6,fill:'#ffffff'},originG);
  mk('circle',{cx:o[0],cy:o[1],r:5,fill:'none',stroke:'#ffffff','stroke-width':.5,'class':'ring'},originG);
  var t=mk('text',{x:o[0]+5,y:o[1]-4,fill:'#ffffff','font-size':6,'font-family':'Consolas,monospace','letter-spacing':1},originG);t.textContent='YOU';

  var apps={}, dests={}, countries={}, nCty=0, nApps=0;
  data.connections.forEach(function(c){
    var a=apps[c.proc]; if(!a){a=apps[c.proc]={name:c.proc,n:0,cc:{}};nApps++;}
    a.n++;
    if(c.geo){
      a.cc[c.geo.cc]=1; if(!countries[c.geo.cc]){countries[c.geo.cc]=1;nCty++;}
      var key=c.geo.lat+','+c.geo.lon, d=dests[key];
      if(!d){d=dests[key]={key:key,geo:c.geo,conns:[],procs:{}};}
      d.conns.push(c); d.procs[c.proc]=(d.procs[c.proc]||0)+1;
    }
  });

  // arcs
  var seenArc={};
  Object.keys(dests).forEach(function(k){
    var d=dests[k], tp=project(d.geo.lon,d.geo.lat);
    Object.keys(d.procs).forEach(function(p){
      var ak=p+'|'+k; seenArc[ak]=1;
      var e=arcEls[ak];
      if(!e){
        var grp=mk('g',{},arcsG), col=colorFor(p), dpath=arcPath(o,tp);
        mk('path',{d:dpath,stroke:col,'class':'base'},grp);
        mk('path',{d:dpath,stroke:col,'class':'arc'},grp);
        e=arcEls[ak]=grp;
      }
      e.setAttribute('class',(filter&&p!==filter)?'dim':'');
      e.firstChild.setAttribute('d',arcPath(o,tp)); e.lastChild.setAttribute('d',arcPath(o,tp));
    });
  });
  Object.keys(arcEls).forEach(function(k){if(!seenArc[k]){arcEls[k].remove();delete arcEls[k];}});

  // dots
  var seenDot={};
  Object.keys(dests).forEach(function(k){
    var d=dests[k], tp=project(d.geo.lon,d.geo.lat); seenDot[k]=1;
    var top=Object.keys(d.procs).sort(function(a,b){return d.procs[b]-d.procs[a];})[0], col=colorFor(top);
    var e=dotEls[k];
    if(!e){
      var grp=mk('g',{'class':'dot'},dotsG);
      mk('circle',{cx:tp[0],cy:tp[1],r:3,'class':'ring',stroke:col},grp);
      mk('circle',{cx:tp[0],cy:tp[1],r:1.7,fill:col},grp);
      mk('circle',{cx:tp[0],cy:tp[1],r:5,fill:'transparent'},grp);
      grp.addEventListener('mousemove',function(ev){showTip(grp.__d,ev);});
      grp.addEventListener('mouseleave',function(){tip.style.display='none';});
      e=dotEls[k]=grp;
    }
    e.__d=d;
    e.children[0].setAttribute('stroke',col); e.children[1].setAttribute('fill',col);
    e.setAttribute('class','dot'+((filter&&!d.procs[filter])?' dim':''));
  });
  Object.keys(dotEls).forEach(function(k){if(!seenDot[k]){dotEls[k].remove();delete dotEls[k];}});

  // stats
  $('#s-conn').textContent=data.connections.length;
  $('#s-apps').textContent=nApps;
  $('#s-cty').textContent=nCty;
  $('#s-loc').textContent=data.local_count;
  var note=$('#note');
  if(data.demo) note.textContent='DEMO DATA - these connections are fake.';
  else if(!data.geo_enabled) note.textContent='Geo lookup is off (--no-geo): map disabled, list only.';
  else if(data.geo_unreachable) note.textContent='Cannot reach ip-api.com (check your internet). Connections are listed but cannot be placed on the map.';
  else if(data.pending>0) note.textContent='Locating '+data.pending+' new address(es)...';
  else if(!data.origin) note.textContent='Your own location is unknown yet, lines start from a default point.';
  else note.textContent='';
  $('#foot-geo').textContent=data.geo_enabled?'Locations come from ip-api.com. Run with --no-geo to turn that off.':'Geo lookup is OFF. No requests are sent to ip-api.com.';

  // apps list
  var ul=$('#apps'); ul.replaceChildren();
  Object.keys(apps).map(function(k){return apps[k];}).sort(function(a,b){return b.n-a.n;}).forEach(function(a){
    var li=document.createElement('li'); li.setAttribute('data-app',a.name); if(filter===a.name)li.className='sel';
    var sw=document.createElement('span'); sw.className='sw'; sw.style.color=colorFor(a.name);
    var nm=document.createElement('span'); nm.className='an'; nm.textContent=a.name;
    var ct=document.createElement('span'); ct.className='cnt'; ct.textContent=a.n;
    var cc=document.createElement('span'); cc.className='cc'; cc.textContent=Object.keys(a.cc).slice(0,10).join(' ');
    li.appendChild(sw); li.appendChild(nm); li.appendChild(ct); li.appendChild(cc); ul.appendChild(li);
  });

  // table
  var tb=$('#rows'); tb.replaceChildren();
  data.connections.filter(function(c){return !filter||c.proc===filter;})
    .sort(function(a,b){return a.proc<b.proc?-1:a.proc>b.proc?1:a.ip<b.ip?-1:1;}).slice(0,300).forEach(function(c){
    var tr=document.createElement('tr'); tr.className='mono';
    var cells=[c.proc,c.ip+':'+c.port+' '+c.proto,c.host||'-',c.geo?((c.geo.city?c.geo.city+', ':'')+c.geo.country):'-',c.geo?c.geo.org:'-'];
    cells.forEach(function(txt,i){var td=document.createElement('td');td.textContent=txt;if(i===0)td.style.color=colorFor(c.proc);tr.appendChild(td);});
    tb.appendChild(tr);
  });
}

function showTip(d,ev){
  tip.replaceChildren();
  var h=document.createElement('h4'); h.textContent=(d.geo.city?d.geo.city+', ':'')+d.geo.country+' ('+d.geo.cc+')'; tip.appendChild(h);
  if(d.geo.org){var o=document.createElement('div');o.className='d';o.textContent=d.geo.org;tip.appendChild(o);}
  Object.keys(d.procs).sort(function(a,b){return d.procs[b]-d.procs[a];}).forEach(function(p){
    var r=document.createElement('div'); r.textContent=p+'  x'+d.procs[p]; r.style.color=colorFor(p); tip.appendChild(r);
  });
  var hosts=d.conns.map(function(c){return c.host;}).filter(Boolean).slice(0,2);
  hosts.forEach(function(x){var r=document.createElement('div');r.className='d';r.textContent=x;tip.appendChild(r);});
  tip.style.display='block';
  var x=ev.clientX+14,y=ev.clientY+14; if(x+360>innerWidth)x=ev.clientX-360; if(y+140>innerHeight)y=ev.clientY-140;
  tip.style.left=x+'px'; tip.style.top=y+'px';
}

function setStatus(t,cls){statusEl.textContent=t;statusEl.className='mono '+(cls||'');}

function tick(){
  if(stopped)return;
  if(!paused){
    fetch('/api/connections',{cache:'no-store'}).then(function(r){if(!r.ok)throw new Error('http');return r.json();})
    .then(function(data){last=data;render(data);setStatus(data.demo?'DEMO':'LIVE',data.demo?'demo':'');})
    .catch(function(){setStatus('OFFLINE','off');});
  }
  setTimeout(tick,2000);
}

$('#apps').addEventListener('click',function(ev){
  var li=ev.target.closest('li'); if(!li)return;
  var name=li.getAttribute('data-app'); filter=(filter===name)?null:name; if(last)render(last);
});
document.addEventListener('keydown',function(ev){
  var k=ev.key.toLowerCase();
  if(k===' '){ev.preventDefault();paused=!paused;setStatus(paused?'PAUSED':(last&&last.demo?'DEMO':'LIVE'),paused?'paused':'');}
  else if(k==='f'){if(document.fullscreenElement)document.exitFullscreen();else document.documentElement.requestFullscreen();}
  else if(k==='t'){document.body.classList.toggle('notable');}
  else if(k==='h'){document.body.classList.toggle('clean');}
  else if(k==='escape'){filter=null;if(last)render(last);}
});
$('#stop').addEventListener('click',function(){if(!confirm('Stop the local dashboard server?'))return;fetch('/shutdown',{method:'POST'}).then(function(r){if(!r.ok)throw new Error('stop failed');stopped=true;setStatus('STOPPED','off');document.title='Dashboard stopped';$('#note').textContent='Dashboard stopped. You can close this browser tab.';window.close();}).catch(function(){setStatus('STOP FAILED','off');});});
tick();
})();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
