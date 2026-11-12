#!/usr/bin/env python
"""VPN 样本分析看板 / 端点探测 / 代理池压测台.

只监听 127.0.0.1，全部使用裸 socket，不读取、不修改系统代理设置。
"""
import json
import os
import socket
import ssl
import struct
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BASE)
DATA = os.path.join(ROOT, "data")
STATIC = os.path.join(BASE, "static")

JOBS = {}
JOBS_LOCK = threading.Lock()


def load(name, default=None):
    p = os.path.join(DATA, name)
    if not os.path.exists(p):
        return default
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def save(name, obj):
    p = os.path.join(DATA, name)
    with open(p + ".tmp", "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(p + ".tmp", p)


def tcp_once(host, port, timeout=5.0):
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        ms = (time.time() - t0) * 1000
        s.close()
        return True, ms, ""
    except Exception as e:
        return False, (time.time() - t0) * 1000, type(e).__name__ + ": " + str(e)[:80]


def tls_peer(host, port, timeout=6.0):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                return {
                    "tls": tls.version(),
                    "cipher": (tls.cipher() or ["?"])[0],
                    "subject": str(cert.get("subject")),
                    "issuer": str(cert.get("issuer")),
                }
    except Exception as e:
        return {"tls": "", "error": type(e).__name__ + ": " + str(e)[:80]}


def probe_endpoint(ep):
    ok, ms, err = tcp_once(ep["host"], ep.get("port", 443))
    out = dict(ep)
    out.update({"tcp": ok, "tcp_ms": round(ms, 1), "tcp_err": err,
                "at": time.strftime("%Y-%m-%d %H:%M:%S")})
    if ok and int(ep.get("port", 443)) in (443, 8443):
        out.update(tls_peer(ep["host"], int(ep.get("port", 443))))
    return out


def run_probe(job_id):
    eps = load("endpoints.json", {"endpoints": []})["endpoints"]
    with ThreadPoolExecutor(max_workers=8) as ex:
        res = list(ex.map(probe_endpoint, eps))
    summary = {
        "at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total": len(res),
        "tcp_ok": sum(1 for r in res if r["tcp"]),
        "tls_ok": sum(1 for r in res if r.get("tls")),
        "results": res,
    }
    save("probes.json", summary)
    with JOBS_LOCK:
        JOBS[job_id] = {"state": "done", "kind": "probe", "result": summary}


def socks5_request(proxy_host, proxy_port, dst_host, dst_port, timeout=8.0):
    """完整 SOCKS5 CONNECT（域名 ATYP=3），返回 (ok, ms, err)。"""
    t0 = time.time()
    s = None
    try:
        s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return False, 0.0, "auth_reject"
        h = dst_host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", dst_port))
        head = s.recv(4)
        if len(head) < 4 or head[1] != 0:
            code = head[1] if len(head) > 1 else 255
            return False, 0.0, "connect_reject_%d" % code
        atyp = head[3]
        if atyp == 1:
            s.recv(4)
        elif atyp == 3:
            n = s.recv(1)[0]
            s.recv(n)
        elif atyp == 4:
            s.recv(16)
        s.recv(2)
        return True, (time.time() - t0) * 1000, ""
    except Exception as e:
        return False, (time.time() - t0) * 1000, type(e).__name__ + ":" + str(e)[:60]
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


def parse_proxies():
    p = os.path.join(DATA, "proxies.txt")
    if not os.path.exists(p):
        return []
    out = []
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            out.append(line)
    return out


def split_proxy(url):
    if "://" not in url:
        return None
    scheme, rest = url.split("://", 1)
    if scheme not in ("socks5", "socks5h"):
        return None
    host, _, port = rest.rpartition(":")
    if not host:
        return None
    try:
        return scheme, host, int(port)
    except ValueError:
        return None


def run_stress(job_id, concurrency, rounds, dst_host, dst_port):
    entries = [x for x in (split_proxy(u) for u in parse_proxies()) if x]
    if not entries:
        with JOBS_LOCK:
            JOBS[job_id] = {"state": "done", "kind": "stress",
                            "result": {"entries": 0, "results": [],
                                       "note": "data/proxies.txt 为空，尚未入池"}}
        return

    with JOBS_LOCK:
        JOBS[job_id] = {"state": "running", "kind": "stress", "total": len(entries), "done": 0}
    results = []

    def one(item):
        scheme, host, port = item
        ok, ms, err = socks5_request(host, port, dst_host, dst_port, timeout=10)
        return {"proxy": "%s://%s:%d" % (scheme, host, port), "ok": ok, "ms": round(ms, 1), "err": err}

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
        for _ in range(max(1, rounds)):
            results.extend(ex.map(one, entries))
            with JOBS_LOCK:
                JOBS[job_id]["done"] = len(results)

    alive = [r for r in results if r["ok"]]
    summary = {
        "at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target": "%s:%d" % (dst_host, dst_port),
        "entries": len(entries),
        "rounds": rounds,
        "attempts": len(results),
        "ok": len(alive),
        "success_rate": round(len(alive) / len(results) * 100, 1) if results else 0.0,
        "avg_ms": round(sum(r["ms"] for r in alive) / len(alive), 1) if alive else None,
        "results": results,
    }
    save("stress.json", summary)
    with JOBS_LOCK:
        JOBS[job_id] = {"state": "done", "kind": "stress", "result": summary}


class Handler(BaseHTTPRequestHandler):
    server_version = "vpnbatch/1.0"

    def log_message(self, fmt, *args):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path, ctype):
        try:
            with open(path, "rb") as f:
                body = f.read()
        except OSError:
            return self._json({"error": "not found"}, 404)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p in ("/", "/index.html"):
            return self._file(os.path.join(STATIC, "index.html"), "text/html; charset=utf-8")
        if p == "/api/overview":
            return self._json(load("samples.json", {}))
        if p == "/api/endpoints":
            return self._json({
                "endpoints": load("endpoints.json", {"endpoints": []})["endpoints"],
                "probes": load("probes.json", None),
            })
        if p == "/api/pool":
            urls = parse_proxies()
            return self._json({"count": len(urls), "lines": urls[:200],
                               "stress": load("stress.json", None)})
        if p.startswith("/api/jobs/"):
            jid = p.rsplit("/", 1)[-1]
            with JOBS_LOCK:
                job = JOBS.get(jid)
            return self._json(job or {"error": "unknown job"}, 200 if job else 404)
        if p == "/api/health":
            return self._json({"ok": True, "pid": os.getpid()})
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        p = self.path.split("?")[0]
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        jid = uuid.uuid4().hex[:12]
        if p == "/api/probe":
            with JOBS_LOCK:
                JOBS[jid] = {"state": "running", "kind": "probe"}
            threading.Thread(target=run_probe, args=(jid,), daemon=True).start()
            return self._json({"job": jid})
        if p == "/api/stress":
            conc = int(body.get("concurrency", 8))
            rounds = int(body.get("rounds", 1))
            dst = body.get("target", "www.gstatic.com:443")
            host, _, port = dst.rpartition(":")
            with JOBS_LOCK:
                JOBS[jid] = {"state": "running", "kind": "stress"}
            threading.Thread(target=run_stress,
                             args=(jid, conc, rounds, host, int(port or 443)),
                             daemon=True).start()
            return self._json({"job": jid})
        return self._json({"error": "not found"}, 404)


def main():
    host, port = "127.0.0.1", 9099
    srv = ThreadingHTTPServer((host, port), Handler)
    print("demo server on http://%s:%d" % (host, port))
    srv.serve_forever()


if __name__ == "__main__":
    main()