"""Local, two-peer BB84/QOTP teaching interface. Run: python webapp.py."""

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import threading

from src.vernam import _get_backend, generate_otp_key, qotp_decrypt, qotp_encrypt


INDEX = Path(__file__).with_name("web") / "index.html"
MAX_MESSAGE_CHARS = 8
BACKEND_LOOKUP_SECONDS = 20


class DemoHandler(BaseHTTPRequestHandler):
    def send_data(self, status: int, data: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, status: int, data: dict) -> None:
        self.send_data(status, json.dumps(data).encode("utf-8"), "application/json; charset=utf-8")

    def allowed_host(self) -> bool:
        host = self.headers.get("Host")
        port = self.server.server_port
        return host in (f"127.0.0.1:{port}", f"localhost:{port}")

    def selected_backend(self):
        if self.server.backend_error:
            raise RuntimeError(self.server.backend_error)
        if self.server.quantum_backend is None:
            if not os.environ.get("QISKIT_IBM_TOKEN"):
                self.server.quantum_backend = _get_backend(min_num_qubits=8)
            else:
                # Qiskit Runtime's network lookup can stall on invalid
                # credentials. Bound this HTTP request and never retry the
                # failed lookup during this server process.
                done = threading.Event()
                outcome = {}

                def lookup() -> None:
                    try:
                        outcome["backend"] = _get_backend(min_num_qubits=8, require_qpu=True)
                    except Exception as exc:
                        outcome["error"] = type(exc).__name__
                    finally:
                        done.set()

                threading.Thread(target=lookup, daemon=True).start()
                if not done.wait(BACKEND_LOOKUP_SECONDS):
                    self.server.backend_error = "IBM QPU lookup timed out; check token and connectivity"
                elif "error" in outcome:
                    self.server.backend_error = f"IBM QPU lookup failed ({outcome['error']})"
                else:
                    self.server.quantum_backend = outcome["backend"]
                if self.server.backend_error:
                    raise RuntimeError(self.server.backend_error)
        return self.server.quantum_backend

    def do_GET(self) -> None:
        if not self.allowed_host():
            self.send_json(403, {"error": "Use the local server address"})
        elif self.path == "/":
            self.send_data(200, INDEX.read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/api/status":
            try:
                backend = self.selected_backend()
            except RuntimeError as exc:
                self.send_json(503, {"error": str(exc)})
                return
            qpu = bool(os.environ.get("QISKIT_IBM_TOKEN"))
            self.send_json(200, {
                "mode": "IBM QPU" if qpu else "Simulator",
                "backend": str(backend.name) if qpu else "BasicSimulator",
            })
        else:
            self.send_json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        if not self.allowed_host():
            self.send_json(403, {"error": "Use the local server address"})
            return
        if self.path != "/api/send":
            self.send_json(404, {"error": "Not found"})
            return
        origin = self.headers.get("Origin")
        port = self.server.server_port
        if origin and origin not in (f"http://127.0.0.1:{port}", f"http://localhost:{port}"):
            self.send_json(403, {"error": "Cross-origin requests are not allowed"})
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0].lower() != "application/json":
            self.send_json(415, {"error": "Expected JSON"})
            return
        try:
            size = int(self.headers.get("Content-Length", ""))
            if not 0 < size <= 4096:
                raise ValueError("Invalid request size")
            payload = json.loads(self.rfile.read(size))
            sender = payload["sender"]
            message = payload["message"]
            if sender not in ("alice", "bob") or not isinstance(message, str):
                raise ValueError("Invalid sender or message")
            if not 1 <= len(message) <= MAX_MESSAGE_CHARS:
                raise ValueError("Message must have 1 to 8 Unicode code points")
            plaintext = message.encode("utf-8")
        except (ValueError, KeyError, TypeError, UnicodeError, json.JSONDecodeError):
            self.send_json(400, {"error": "Send 1 to 8 Unicode code points from Alice or Bob"})
            return

        try:
            # Both BB84 roles run here. The browser gets the resulting key
            # for both panels; there is no networked quantum channel.
            backend = self.selected_backend()
            if os.environ.get("QISKIT_IBM_TOKEN"):
                print(f"[bb84] Initiating BB84 key exchange on {backend.name}", flush=True)
            key = generate_otp_key(len(plaintext), backend=backend)
            ciphertext = qotp_encrypt(plaintext, key, backend=backend)
            decoded = qotp_decrypt(ciphertext, key, backend=backend).decode("utf-8")
            if decoded != message:
                raise RuntimeError("The decrypted message differs from the original")
        except Exception as exc:
            if self.server.backend_error:
                self.send_json(503, {"error": f"{self.server.backend_error}; message not sent"})
            else:
                mode = "IBM QPU" if os.environ.get("QISKIT_IBM_TOKEN") else "simulator"
                self.send_json(500, {"error": f"{mode} operation failed ({type(exc).__name__}); message not sent"})
            return

        self.send_json(200, {
            "sender": sender,
            "recipient": "bob" if sender == "alice" else "alice",
            "key": key.hex(),
            "ciphertext": ciphertext.hex(),
            "plaintext": decoded,
            "backend": "IBM QPU" if os.environ.get("QISKIT_IBM_TOKEN") else "Simulator",
            "backend_name": str(backend.name) if os.environ.get("QISKIT_IBM_TOKEN") else "BasicSimulator",
        })


def main() -> None:
    parser = argparse.ArgumentParser(description="Local Alice/Bob BB84 + QOTP demo")
    parser.add_argument("--port", type=int, default=8000, help="loopback HTTP port (default: 8000)")
    args = parser.parse_args()
    server = HTTPServer(("127.0.0.1", args.port), DemoHandler)
    server.quantum_backend = None
    server.backend_error = None
    print("IBM QPU" if os.environ.get("QISKIT_IBM_TOKEN") else "SIMULATOR", flush=True)
    print(f"Open http://127.0.0.1:{server.server_port}/ (local demo only)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
