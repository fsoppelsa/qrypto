"""Quantum OTP Chat – classical chat protocol with quantum one-time-pad encryption.

Usage:
    python chatter.py <port> <name>

Example:
    python chatter.py 3333 erwin

The process binds to *port* and presents a prompt-based interface:

    > whoami          # display your identity
    > talk host:port  # connect to a remote peer
    > say 'msg'       # send an encrypted message (max 5 bytes)
    > quit            # exit

Incoming messages are prefixed with ``%``:

    % erwin@192.168.1.1:3333 says <<<Hello>>>

For this educational exercise each message has a fresh key, sent in cleartext
alongside its ciphertext. This is NOT secure key distribution or private chat.
"""

import argparse
import atexit
import os
import readline
import socket
import threading
import time

from vernam import generate_otp_key, qotp_decrypt, qotp_encrypt

# Arrow-key history for the prompt (readline hooks into input() on Unix).
HISTFILE = os.path.expanduser("~/.qipher_history")
try:
    readline.read_history_file(HISTFILE)
except FileNotFoundError:
    pass
readline.set_history_length(100)

def _flush_history() -> None:
    try:
        readline.write_history_file(HISTFILE)
    except OSError:
        pass

atexit.register(_flush_history)

MAX_MSG_BYTES = 5


def recv_exact(sock: socket.socket, length: int) -> bytes | None:
    """Read a complete TCP field, or return None on disconnect."""
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


VERSION = "0.02"


def get_local_ip() -> str:
    """Best-effort local (non-loopback) IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't actually send data
        s.connect(("1.1.1.1", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


class Qipher:
    """Chat peer that listens on a port and can connect to other peers."""

    def __init__(self, name: str, port: int) -> None:
        self.name = name
        self.port = port
        self.ip = get_local_ip()

        # Connection state protected by lock (shared between prompt loop and recv threads).
        self.lock = threading.Lock()
        self.peer_sock: socket.socket | None = None
        self.peer_id: str | None = None  # e.g. "alice@192.168.1.1:3333"

        self.running = True

    @property
    def identity(self) -> str:
        return f"{self.name}@{self.ip}:{self.port}"

    def set_peer(self, sock: socket.socket | None, peer_id: str | None) -> None:
        """Thread-safe setter for the current peer connection, closing the old one."""
        with self.lock:
            old = self.peer_sock
            self.peer_sock = sock
            self.peer_id = peer_id
        if old is not None and old is not sock:
            try:
                old.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            old.close()

    def start_listener(self) -> None:
        """Bind and start the TCP listener in a background thread."""
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("0.0.0.0", self.port))
        self.srv.listen(1)
        self.srv.settimeout(0.5)  # allow checking self.running periodically

        t = threading.Thread(target=self.accept_loop, daemon=True)
        t.start()

    def accept_loop(self) -> None:
        """Accept incoming connections and spawn a handler per connection."""
        while self.running:
            try:
                conn, addr = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            t = threading.Thread(
                target=self.handle_incoming, args=(conn, addr), daemon=True
            )
            t.start()

    def handle_incoming(self, conn: socket.socket, addr: tuple) -> None:
        """Read the IDENT handshake from an accepted connection, then receive messages."""
        try:
            # Read only the handshake; TCP can coalesce it with the first frame.
            line = bytearray()
            while len(line) < 128:
                char = conn.recv(1)
                if not char:
                    conn.close()
                    return
                if char == b"\n":
                    break
                line.extend(char)
            else:
                conn.close()
                return
        except OSError:
            conn.close()
            return

        identity = line.decode(errors="replace")
        if not identity.startswith("IDENT:"):
            conn.close()
            return

        peer_id = identity[6:]
        self.set_peer(conn, peer_id)
        print(f"\n% CONNECTED TO {peer_id}!")

        self.read_loop(conn, peer_id)

    def cmd_talk(self, target: str) -> None:
        """Connect to a remote peer at *target* (host:port)."""
        try:
            host, port_str = target.split(":")
            port = int(port_str)
        except ValueError:
            print("Invalid address format. Use: talk host:port")
            return

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            sock.settimeout(None)
        except OSError as exc:
            print(f"Failed to connect to {target}: {exc}")
            return

        try:
            sock.sendall(f"IDENT:{self.identity}\n".encode())
        except OSError:
            sock.close()
            print(f"Failed to send identity to {target}")
            return

        self.set_peer(sock, target)
        print(f"% CONNECTED TO {target}!")

        t = threading.Thread(target=self.read_loop, args=(sock, target), daemon=True)
        t.start()

    def read_loop(self, sock: socket.socket, peer_id: str) -> None:
        """Receive encrypted messages on *sock* and display them."""
        try:
            while self.running:
                header = recv_exact(sock, 1)
                if header is None:
                    break
                length = header[0]
                if not 1 <= length <= MAX_MSG_BYTES:
                    break
                key = recv_exact(sock, 2 * length)
                if key is None:
                    break
                try:
                    data = recv_exact(sock, length)
                    if data is None:
                        break
                    print("⚛️  decrypting...")
                    start = time.time()
                    plain = qotp_decrypt(data, key)
                    elapsed = time.time() - start
                    print(f"    \033[1m\033[94m[{data.hex()}]\033[0m  ({elapsed:.2f}s)")
                    text = plain.decode(errors="replace")
                    print(f"\n% {peer_id} says \033[1m\033[91m{text}\033[0m")
                finally:
                    del key
                    print("Trashing OTP key... 🗑️ (dropping reference, not secure erasure)")
        except OSError:
            pass
        finally:
            # Only clear if this socket is still the current peer.
            with self.lock:
                if self.peer_sock is sock:
                    self.peer_sock = None
                    self.peer_id = None
            try:
                sock.close()
            except OSError:
                pass

    def cmd_say(self, message: str) -> None:
        """Encrypt and send *message* to the current peer."""
        msg_bytes = message.encode()

        if not msg_bytes:
            print("Message must not be empty.")
            return

        if len(msg_bytes) > MAX_MSG_BYTES:
            print(
                f"Message too long ({len(msg_bytes)} bytes). "
                f"Max is {MAX_MSG_BYTES} bytes."
            )
            return

        with self.lock:
            sock = self.peer_sock
            peer = self.peer_id

        if sock is None:
            print("Not connected. Use 'talk <host>:<port>' first.")
            return

        print("Generating OTP key... 🔑")
        try:
            key = generate_otp_key(len(msg_bytes))
        except Exception as exc:
            print(f"OTP key generation failed: {exc}")
            return
        try:
            print("⚛️  encrypting...")
            start = time.time()
            encrypted = qotp_encrypt(msg_bytes, key)
            elapsed = time.time() - start
            print(f"    \033[1m\033[94m[{encrypted.hex()}]\033[0m  ({elapsed:.2f}s)")
            # Exercise only: sending the raw key defeats secrecy.
            sock.sendall(bytes([len(msg_bytes)]) + key + encrypted)
        except OSError:
            print(f"Failed to send – connection to {peer} lost.")
            with self.lock:
                if self.peer_sock is sock:
                    self.peer_sock = None
                    self.peer_id = None
        finally:
            del key
            print("Trashing OTP key... 🗑️ (dropping reference, not secure erasure)")

    def shutdown(self) -> None:
        """Stop the listener and close the peer connection."""
        self.running = False
        self.set_peer(None, None)
        try:
            self.srv.close()
        except OSError:
            pass

    def run(self) -> None:
        """Main prompt loop."""
        self.start_listener()
        print(f"Qipher v{VERSION} started as {self.identity}")
        if os.environ.get("QISKIT_IBM_TOKEN"):
            print("⚛️  IBM QUANTUM TOKEN CONFIGURED (QPU checked on send)")
        print("Exercise only: OTP keys are sent in cleartext; chat is NOT private.")
        print("Commands: \033[1mwhoami\033[0m | \033[1mtalk\033[0m <host>:<port> | \033[1msay\033[0m '<msg>' | \033[1mquit\033[0m")

        while self.running:
            try:
                line = input("\001\033[1m\002> ")
            except (EOFError, KeyboardInterrupt):
                print()
                _flush_history()
                break

            line = line.strip()
            if not line:
                continue

            if line == "quit":
                _flush_history()
                break
            elif line == "whoami":
                print(self.identity)
            elif line.startswith("talk "):
                target = line[5:].strip()
                if target:
                    self.cmd_talk(target)
                else:
                    print("Usage: \033[1mtalk\033[0m <host>:<port>")
            elif line.startswith("say "):
                rest = line[4:].strip()
                if (rest.startswith("'") and rest.endswith("'")) or (
                    rest.startswith('"') and rest.endswith('"')
                ):
                    message = rest[1:-1]
                    self.cmd_say(message)
                else:
                    print("Usage: say '<message>'")
            else:
                print(f"Unknown command: {line}")

        self.shutdown()
        print("Goodbye!")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Quantum OTP Chat – encrypted peer-to-peer chat"
    )
    parser.add_argument("port", type=int, help="Listening port")
    parser.add_argument("name", type=str, help="Your nickname")
    args = parser.parse_args()

    qipher = Qipher(args.name, args.port)
    qipher.run()


if __name__ == "__main__":
    main()
