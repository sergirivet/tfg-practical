#!/usr/bin/env python3
"""
Live end-to-end demonstration of Protocol 3.4 over localhost.

This script performs a real TCP exchange on 127.0.0.1:8080:
- Server thread listens and accepts a client
- Hybrid handshake runs over raw sockets
- RecordSession is instantiated after Phase 4 on both endpoints
- Client sends encrypted application data over AES-256-GCM
- Server decrypts and prints the plaintext
- Client sends an encrypted close_notify for graceful shutdown

The protocol-specific handshake still happens in the Client/Server classes.
This script focuses on the transport glue needed for a practical demo.
"""

from __future__ import annotations

import socket
import struct
import threading
import queue

from primitives.authentication.hybrid import HybridSignatureEngine
from primitives.kem.hybrid import HybridKEMEngine
from protocol.client import Client
from protocol.server import Server


HOST = "127.0.0.1"
PORT = 8080
SOCKET_TIMEOUT_SECONDS = 5.0


def _send_blob(sock: socket.socket, blob: bytes) -> None:
    """Send one length-prefixed binary blob."""
    sock.sendall(struct.pack("!I", len(blob)) + blob)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    """Receive exactly *size* bytes or raise if the socket closes early."""
    chunks = []
    remaining = size

    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Socket closed before all bytes were received")
        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def _recv_blob(sock: socket.socket) -> bytes:
    """Receive one length-prefixed binary blob."""
    raw_length = _recv_exact(sock, 4)
    (length,) = struct.unpack("!I", raw_length)
    return _recv_exact(sock, length)


def _recv_record_frame(sock: socket.socket) -> bytes:
    """Receive a single record frame by parsing the fixed 5-byte header."""
    header = _recv_exact(sock, 5)
    payload_length = int.from_bytes(header[3:5], "big")
    payload = _recv_exact(sock, payload_length)
    return header + payload


def server_worker(
    ready_event: threading.Event,
    done_event: threading.Event,
    error_queue: "queue.Queue[str]",
    server_signing_private: bytes,
    kem_engine: HybridKEMEngine,
    signature_engine: HybridSignatureEngine,
) -> None:
    """Background server thread: accept, handshake, decrypt, and close cleanly."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(1)
    server_sock.settimeout(SOCKET_TIMEOUT_SECONDS)

    try:
        ready_event.set()
        conn, _ = server_sock.accept()
        conn.settimeout(SOCKET_TIMEOUT_SECONDS)

        with conn:
            server = Server(server_signing_private, kem_engine, signature_engine)

            # Receive Phase 1 client material.
            client_public_key = _recv_blob(conn)

            # Perform Phase 2 on the server side.
            server_ciphertext, signature = server.phase2_generate_ephemeral_and_sign(client_public_key)

            # Send Phase 2 response back to the client.
            _send_blob(conn, server_ciphertext)
            _send_blob(conn, signature)

            # Complete Phase 4 and instantiate the RecordSession.
            server.phase4_derive_session_key(client_public_key)

            # Receive one encrypted application record and decrypt it.
            incoming_frame = _recv_record_frame(conn)
            plaintext = server.receive_application_data(incoming_frame)
            print(f"[server] decrypted application data: {plaintext.decode()}", flush=True)

            # Receive the encrypted close_notify and process graceful shutdown.
            close_frame = _recv_record_frame(conn)
            server.receive_application_data(close_frame)
            print("[server] close_notify received; shutting down cleanly", flush=True)

    except Exception as exc:
        print(f"[server] demo failed: {exc}", flush=True)
        error_queue.put(f"server: {exc}")
    finally:
        try:
            server_sock.close()
        except OSError:
            pass
        done_event.set()


def client_worker(
    ready_event: threading.Event,
    done_event: threading.Event,
    error_queue: "queue.Queue[str]",
    server_signing_public: bytes,
    kem_engine: HybridKEMEngine,
    signature_engine: HybridSignatureEngine,
) -> None:
    """Background client thread: connect, handshake, send data, and close cleanly."""
    if not ready_event.wait(timeout=SOCKET_TIMEOUT_SECONDS):
        raise TimeoutError("Server did not become ready in time")

    client_sock = socket.create_connection((HOST, PORT), timeout=SOCKET_TIMEOUT_SECONDS)
    client_sock.settimeout(SOCKET_TIMEOUT_SECONDS)

    try:
        client = Client(server_signing_public, kem_engine, signature_engine)

        # Phase 1: client generates ephemeral keys and sends them.
        client_public_key = client.phase1_generate_ephemeral_keys()
        _send_blob(client_sock, client_public_key)

        # Phase 2: receive the server response containing keys and dual signatures.
        server_ciphertext = _recv_blob(client_sock)
        signature = _recv_blob(client_sock)

        client.phase3_verify_phase4_derive(server_ciphertext, signature)

        # Send encrypted application data.
        frame = client.send_application_data(b"Post-Quantum Secured Message over AES-GCM")
        client_sock.sendall(frame)

        # Send encrypted close_notify for graceful shutdown.
        close_frame = client.close_session()
        client_sock.sendall(close_frame)

    except Exception as exc:
        print(f"[client] demo failed: {exc}", flush=True)
        error_queue.put(f"client: {exc}")
    finally:
        try:
            client_sock.close()
        except OSError:
            pass
        done_event.set()


def main() -> int:
    kem_engine = HybridKEMEngine()
    signature_engine = HybridSignatureEngine()

    # Trusted long-term signing keys for the server.
    # In a real deployment these would be provisioned via certificates or another PKI channel.
    server_signing_private, server_signing_public = signature_engine.keygen()

    ready_event = threading.Event()
    server_done = threading.Event()
    client_done = threading.Event()
    error_queue: "queue.Queue[str]" = queue.Queue()

    server_thread = threading.Thread(
        target=server_worker,
        args=(
            ready_event,
            server_done,
            error_queue,
            server_signing_private,
            kem_engine,
            signature_engine,
        ),
        daemon=True,
    )
    client_thread = threading.Thread(
        target=client_worker,
        args=(
            ready_event,
            client_done,
            error_queue,
            server_signing_public,
            kem_engine,
            signature_engine,
        ),
        daemon=True,
    )

    print(f"Starting live demo on {HOST}:{PORT}", flush=True)
    server_thread.start()
    client_thread.start()

    client_done.wait(timeout=SOCKET_TIMEOUT_SECONDS * 4)
    server_done.wait(timeout=SOCKET_TIMEOUT_SECONDS * 4)

    server_thread.join(timeout=1.0)
    client_thread.join(timeout=1.0)

    if not error_queue.empty():
        while not error_queue.empty():
            print(f"Live demo error: {error_queue.get_nowait()}", flush=True)
        return 1

    if server_thread.is_alive() or client_thread.is_alive():
        print("Live demo timed out", flush=True)
        return 1

    print("Live demo completed successfully", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())