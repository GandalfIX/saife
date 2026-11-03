"""Streaming facade sidecar: the instrument for S0.1.

Answers the health gate on /status, then serves POST /build as a stream: one line
per `interval_ms`, flushed immediately, `lines` in total. Whether those lines reach
the workload *as they are produced* or arrive in one lump at the end is the whole
question - a build log that only appears when the build finishes is useless.
"""

import os
import socket
import sys
import threading
import time

PORT = int(os.environ["SIDECAR_PORT"])
LINES = int(os.environ.get("SIDECAR_CFG_LINES", "20"))
INTERVAL_MS = int(os.environ.get("SIDECAR_CFG_INTERVAL_MS", "1000"))


def handle(conn):
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk
        request_line = data.split(b"\r\n", 1)[0].decode("latin-1")
        method, path, _ = request_line.split(" ", 2)

        if path.startswith("/status"):
            body = b"ok"
            conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n" + body)
            return

        if method in ("GET", "POST") and path.startswith("/build"):
            # Deliberately no Content-Length: the body ends when the socket closes,
            # so every write below is visible to the relay the moment it happens.
            conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n")
            for i in range(LINES):
                line = "line %02d %.3f\n" % (i, time.time())
                conn.sendall(line.encode("ascii"))
                conn.flush() if hasattr(conn, "flush") else None
                time.sleep(INTERVAL_MS / 1000.0)
            conn.sendall(b"done\n")
            return

        conn.sendall(b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n")
    except Exception as e:  # noqa: BLE001 - a sidecar must log, not crash the test
        print("sidecar error:", e, file=sys.stderr, flush=True)
    finally:
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        conn.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(8)
    print("stream sidecar listening on 127.0.0.1:%d" % PORT, flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
