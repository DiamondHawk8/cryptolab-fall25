import os
import socket
import time
import selectors
import psutil
import click
from dotenv import load_dotenv

from cryptolab.logging_utils import ensure_logger, emit_json
from cryptolab.tls_record import TLSInspector, TLS_CONTENT_APP_DATA

BUF_SIZE = 64 * 1024


def _now_ms() -> int:
    return int(time.time() * 1000)


class Pipe:
    """
    One-way pipe and TLS record inspector.
    """

    def __init__(self, src_sock, dst_sock, name: str):
        self.src = src_sock
        self.dst = dst_sock
        self.name = name
        self.bytes = 0  # Total forwarded in this direction (client -> server and server -> client are separate pipes)
        self.inspector = TLSInspector()
        self.closed = False

    def forward_once(self) -> bool:

        if self.closed:
            return False

        try:
            data = self.src.recv(BUF_SIZE)
        except (BlockingIOError, InterruptedError):
            # If nothing to read from src, keep going
            return True

        if not data:
            # Peer sent EOF on this side; fully close the opposite socket so the connection winds down deterministically
            try:
                self.dst.close()
            except OSError:
                pass
            self.closed = True
            return False

        # If data was received, increment the byte counter and attempt to classify TLS records
        self.bytes += len(data)
        self.inspector.feed(data)

        # Forward classified bytes to destination, looping until entire view has been sent
        view = memoryview(data)
        while view:
            try:
                sent = self.dst.send(view)
                view = view[sent:]
            except (BlockingIOError, InterruptedError):
                time.sleep(0.001)

        return True


@click.command()
def main():
    load_dotenv()
    listen_host = os.getenv("LISTEN_HOST", "127.0.0.1")
    listen_port = int(os.getenv("LISTEN_PORT", "8443"))
    target_host = os.getenv("TARGET_HOST", "example.org")
    target_port = int(os.getenv("TARGET_PORT", "443"))
    log_level = os.getenv("LOG_LEVEL", "INFO")
    log_dir = os.getenv("LOG_DIR", "logs")
    log_file = os.getenv("LOG_FILE", "metrics.jsonl")

    logger = ensure_logger(log_dir, log_file, log_level)

    # Create TCP listener
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((listen_host, listen_port))
        listener.listen(128)
        print(f"[proxy] listening on {listen_host}:{listen_port} -> {target_host}:{target_port}")

        while True:
            # Accept client connections
            client, addr = listener.accept()
            client.setblocking(False)
            print(f"[proxy] accepted {addr}")

            # Connect upstream
            upstream = socket.create_connection((target_host, target_port))
            upstream.setblocking(False)

            # Create and register read events for both sockets with tuples to define what direction to forward
            sel = selectors.DefaultSelector()
            sel.register(client, selectors.EVENT_READ, data=("c2s", client, upstream))
            sel.register(upstream, selectors.EVENT_READ, data=("s2c", upstream, client))

            # Construct Pipe instances for both connections
            c2s = Pipe(client, upstream, "c2s")
            s2c = Pipe(upstream, client, "s2c")

            # Initial benchmark
            start_ms = _now_ms()
            start_cpu = psutil.Process().cpu_times()
            handshake_done_ms = None

            try:
                while True:
                    # Wait up to 50 ms per cycle for socket to becom readable
                    events = sel.select(timeout=0.05)

                    # If no readable sockets this cycle
                    if not events:
                        # Check handshake completion (first Application Data seen in both directions)
                        if handshake_done_ms is None and c2s.inspector.app_seen and s2c.inspector.app_seen:
                            handshake_done_ms = _now_ms() - start_ms
                        # Otherwise if closed, both saw EOF and have forwarded
                        if c2s.closed and s2c.closed:
                            break
                        continue

                    # For each readable socket, look at the data tuple to decide which pip to execute
                    for key, _ in events:
                        tag, src, dst = key.data
                        if tag == "c2s":
                            c2s.forward_once()
                        else:
                            s2c.forward_once()
                        if c2s.closed and s2c.closed:
                            break
            finally:
                # Cleanup
                sel.unregister(client)
                sel.unregister(upstream)
                client.close()
                upstream.close()

                # End metrics
                end_ms = _now_ms()
                cpu_end = psutil.Process().cpu_times()
                cpu_user = (cpu_end.user - start_cpu.user)
                cpu_sys = (cpu_end.system - start_cpu.system)

                payload = {
                    "module": "proxy",
                    "mode": "passthrough",
                    "metrics": {
                        "bytes": {
                            "c2s": c2s.bytes,
                            "s2c": s2c.bytes,
                            "total": c2s.bytes + s2c.bytes,
                            "handshake_c2s": c2s.inspector.handshake_bytes,
                            "handshake_s2c": s2c.inspector.handshake_bytes,
                        },
                        "ms": {
                            "handshake": handshake_done_ms if handshake_done_ms is not None else None,
                            "total": end_ms - start_ms,
                        },
                        "cpu": {
                            "user": cpu_user,
                            "system": cpu_sys,
                        },
                        "note": "Handshake bytes are estimated from TLS record headers until first Application Data (type=23) per direction.",
                    },
                }
                print(
                    f"[proxy] bytes c2s={c2s.bytes} s2c={s2c.bytes} "
                    f"hs(c2s)={c2s.inspector.handshake_bytes} hs(s2c)={s2c.inspector.handshake_bytes} "
                    f"t_total_ms={payload['metrics']['ms']['total']} "
                    f"t_hs_ms={payload['metrics']['ms']['handshake']}"
                )
                emit_json(logger, payload)


if __name__ == "__main__":
    main()
