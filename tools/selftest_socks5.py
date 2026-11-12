#!/usr/bin/env python
"""压测台的本地 SOCKS5 夹具：只用于验证 proxies.txt -> SOCKS5 CONNECT 链路本身。

监听 127.0.0.1:<port>，对每个 CONNECT 直接建一条到目标的 TCP，双向搬运。
不实现 UDP ASSOCIATE，不做认证。

    python -I tools/selftest_socks5.py 24099
"""
import socket
import socketserver
import struct
import sys
import threading

UPSTREAM_TIMEOUT = 10


class Handler(socketserver.BaseRequestHandler):
    def _read(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.request.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("eof")
            buf += chunk
        return buf

    def handle(self):
        cli = self.request
        cli.settimeout(UPSTREAM_TIMEOUT)
        try:
            ver, nmethods = self._read(2)
            if ver != 5:
                return
            self._read(nmethods)
            cli.sendall(b"\x05\x00")

            head = self._read(4)
            if head[1] != 1:
                cli.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            atyp = head[3]
            if atyp == 1:
                host = socket.inet_ntoa(self._read(4))
            elif atyp == 3:
                host = self._read(self._read(1)[0]).decode()
            else:
                host = socket.inet_ntop(socket.AF_INET6, self._read(16))
            port = struct.unpack(">H", self._read(2))[0]

            up = socket.create_connection((host, port), timeout=UPSTREAM_TIMEOUT)
            cli.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", 0))

            def pump(src, dst):
                try:
                    while True:
                        data = src.recv(65536)
                        if not data:
                            break
                        dst.sendall(data)
                except OSError:
                    pass
                finally:
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

            threading.Thread(target=pump, args=(cli, up), daemon=True).start()
            pump(up, cli)
            up.close()
        except (ConnectionError, OSError):
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 24099
    print("fixture socks5 on 127.0.0.1:%d" % port)
    Server(("127.0.0.1", port), Handler).serve_forever()