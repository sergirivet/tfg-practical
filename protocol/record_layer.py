"""
Record Layer for secure post-handshake application data transport.

This module is intentionally separate from the handshake state machine.
It assumes the Phase 4 master secret already exists and turns it into
directional traffic protection keys for a duplex TCP channel.

Design goals:
- Derive independent write/read traffic keys and IVs from the Phase 4 master secret
- Encrypt each record with AES-256-GCM
- Bind the record header and implicit sequence number as AAD
- Detect replay, reordering, truncation, and tampering
- Support encrypted close_notify signaling for clean shutdown
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from primitives.kdf.hkdf import hkdf_expand


class RecordLayerError(Exception):
    """Base error for record-layer failures."""


class RecordAuthenticationError(RecordLayerError):
    """Raised when AEAD authentication or replay validation fails."""


class RecordClosedError(RecordLayerError):
    """Raised when an operation is attempted on a closed or closing session."""


class RecordType(IntEnum):
    HANDSHAKE = 0x16
    APPLICATION_DATA = 0x17
    ALERT = 0x15


class AlertLevel(IntEnum):
    WARNING = 0x01
    FATAL = 0x02


class AlertDescription(IntEnum):
    CLOSE_NOTIFY = 0x00


@dataclass(frozen=True)
class TrafficKeys:
    """Direction-specific traffic protection keys."""

    client_write_key: bytes
    server_write_key: bytes
    client_write_iv: bytes
    server_write_iv: bytes


@dataclass(frozen=True)
class Record:
    """Decrypted record returned by the record layer."""

    content_type: RecordType
    version: bytes
    sequence_number: int
    plaintext: bytes
    alert_level: Optional[AlertLevel] = None
    alert_description: Optional[AlertDescription] = None


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    """Read exactly *length* bytes or raise if the stream ends early."""
    chunks = []
    remaining = length

    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RecordLayerError("Socket closed before the full record was received")
        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def _xor_nonce(base_iv: bytes, sequence_number: int) -> bytes:
    """Derive a per-record nonce by XORing the IV with the sequence number."""
    if len(base_iv) != 12:
        raise ValueError("AES-GCM IVs must be 12 bytes")

    padded_sequence = sequence_number.to_bytes(12, "big")
    return bytes(left ^ right for left, right in zip(base_iv, padded_sequence))


def _close_transport(sock: socket.socket) -> None:
    """Best-effort transport teardown."""
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


class RecordSession:
    """Authenticated AEAD record protection for a client or server endpoint.

    Instantiate this after Phase 4 with the shared master secret.
    The class keeps separate read/write sequence counters and uses
    directional traffic keys to avoid reflection and replay issues in
    a full-duplex TCP stream.
    """

    PROTOCOL_VERSION = b"\x03\x04"
    MAX_FRAGMENT_LENGTH = 0xFFFF
    _KEY_INFO_PREFIX = b"tfg-practical|record-layer|v1|"
    _ALERT_CLOSE_NOTIFY = bytes([AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY])

    def __init__(
        self,
        master_secret: bytes,
        role: Optional[str] = None,
        *,
        is_server: Optional[bool] = None,
        protocol_version: bytes = PROTOCOL_VERSION,
        teardown_callback: Optional[Callable[[], None]] = None,
        # AEAD customization for cryptographic agility
        aead_cls: Callable[[bytes], object] = AESGCM,
        aead_key_len: int = 32,
        aead_iv_len: int = 12,
    ):
        if not master_secret:
            raise ValueError("master_secret cannot be empty")
        if len(protocol_version) != 2:
            raise ValueError("protocol_version must be exactly 2 bytes")

        if role is None and is_server is None:
            raise ValueError("Either role or is_server must be provided")
        if role is not None and is_server is not None:
            expected_role = "server" if is_server else "client"
            if role != expected_role:
                raise ValueError("role and is_server describe conflicting endpoint roles")

        if role is None:
            role = "server" if is_server else "client"
        if role not in {"client", "server"}:
            raise ValueError("role must be 'client' or 'server'")

        self.role = role
        self.protocol_version = protocol_version
        self._teardown_callback = teardown_callback
        self._aead_cls = aead_cls
        self._aead_key_len = aead_key_len
        self._aead_iv_len = aead_iv_len

        # Record-layer state is intentionally separate from the handshake state machine.
        self._closed = False
        self._peer_close_notify_received = False
        self._local_close_notify_sent = False
        self._send_sequence_number = 0
        self._recv_sequence_number = 0

        self._traffic_keys = self._derive_traffic_keys(master_secret)
        self._send_key, self._send_iv, self._recv_key, self._recv_iv = self._select_directional_keys()
        self._send_aead = self._aead_cls(self._send_key)
        self._recv_aead = self._aead_cls(self._recv_key)

    @property
    def send_sequence_number(self) -> int:
        return self._send_sequence_number

    @property
    def recv_sequence_number(self) -> int:
        return self._recv_sequence_number

    @property
    def peer_close_notify_received(self) -> bool:
        return self._peer_close_notify_received

    @property
    def closed(self) -> bool:
        return self._closed

    def _derive_traffic_keys(self, master_secret: bytes) -> TrafficKeys:
        """Expand the Phase 4 secret into four independent traffic secrets.

        Unidirectional keys are architecturally required because a duplex TCP stream
        must never reuse the same AES-GCM key/IV pair for both directions. Separate
        write keys prevent reflection attacks, simplify replay handling, and stop
        an attacker from turning one endpoint into a decryption oracle for its own output.
        """

        client_write_key = hkdf_expand(
            master_secret,
            self._KEY_INFO_PREFIX + self.protocol_version + b"|client write key",
            self._aead_key_len,
        )
        server_write_key = hkdf_expand(
            master_secret,
            self._KEY_INFO_PREFIX + self.protocol_version + b"|server write key",
            self._aead_key_len,
        )
        client_write_iv = hkdf_expand(
            master_secret,
            self._KEY_INFO_PREFIX + self.protocol_version + b"|client write iv",
            self._aead_iv_len,
        )
        server_write_iv = hkdf_expand(
            master_secret,
            self._KEY_INFO_PREFIX + self.protocol_version + b"|server write iv",
            self._aead_iv_len,
        )

        return TrafficKeys(
            client_write_key=client_write_key,
            server_write_key=server_write_key,
            client_write_iv=client_write_iv,
            server_write_iv=server_write_iv,
        )

    def _select_directional_keys(self):
        if self.role == "client":
            return (
                self._traffic_keys.client_write_key,
                self._traffic_keys.client_write_iv,
                self._traffic_keys.server_write_key,
                self._traffic_keys.server_write_iv,
            )

        return (
            self._traffic_keys.server_write_key,
            self._traffic_keys.server_write_iv,
            self._traffic_keys.client_write_key,
            self._traffic_keys.client_write_iv,
        )

    def _build_header(self, content_type: int, payload_length: int) -> bytes:
        if not 0 <= content_type <= 0xFF:
            raise ValueError("content_type must fit in one byte")
        if not 0 <= payload_length <= self.MAX_FRAGMENT_LENGTH:
            raise ValueError("payload_length must fit in two bytes")

        return bytes([content_type]) + self.protocol_version + payload_length.to_bytes(2, "big")

    def _build_aad(self, header: bytes, sequence_number: int) -> bytes:
        return header + sequence_number.to_bytes(8, "big")

    def _seal(self, content_type: int, plaintext: bytes, sequence_number: int) -> bytes:
        content_type_value = int(content_type)
        ciphertext_length = len(plaintext) + 16
        header = self._build_header(content_type_value, ciphertext_length)
        aad = self._build_aad(header, sequence_number)
        ciphertext = self._send_aead.encrypt(_xor_nonce(self._send_iv, sequence_number), plaintext, aad)

        if len(ciphertext) > self.MAX_FRAGMENT_LENGTH:
            raise RecordLayerError("Encrypted record exceeds the protocol length limit")

        return header + ciphertext

    def _open(self, frame: bytes, sequence_number: int) -> Record:
        if len(frame) < 5:
            raise RecordLayerError("Record frame is too short")

        content_type = frame[0]
        version = frame[1:3]
        payload_length = int.from_bytes(frame[3:5], "big")
        ciphertext = frame[5:]

        if version != self.protocol_version:
            raise RecordLayerError("Protocol version mismatch")
        if payload_length != len(ciphertext):
            raise RecordLayerError("Record length does not match the encrypted payload")

        header = frame[:5]
        aad = self._build_aad(header, sequence_number)

        try:
            plaintext = self._recv_aead.decrypt(
                _xor_nonce(self._recv_iv, sequence_number),
                ciphertext,
                aad,
            )
        except Exception as exc:
            raise RecordAuthenticationError("Record authentication failed") from exc

        try:
            record_type = RecordType(content_type)
        except ValueError as exc:
            raise RecordLayerError(f"Unsupported record type: 0x{content_type:02x}") from exc

        if record_type == RecordType.ALERT:
            if len(plaintext) < 2:
                raise RecordLayerError("Alert record is too short")

            alert_level = AlertLevel(plaintext[0]) if plaintext[0] in AlertLevel._value2member_map_ else None
            alert_description = (
                AlertDescription(plaintext[1])
                if plaintext[1] in AlertDescription._value2member_map_
                else None
            )

            if alert_description == AlertDescription.CLOSE_NOTIFY:
                self._peer_close_notify_received = True

            return Record(
                content_type=record_type,
                version=version,
                sequence_number=sequence_number,
                plaintext=plaintext,
                alert_level=alert_level,
                alert_description=alert_description,
            )

        return Record(
            content_type=record_type,
            version=version,
            sequence_number=sequence_number,
            plaintext=plaintext,
        )

    def _ensure_open_state(self) -> None:
        if self._closed:
            raise RecordClosedError("Record session is closed")

    def _seal_and_advance(self, content_type: int, plaintext: bytes) -> bytes:
        self._ensure_open_state()
        if self._peer_close_notify_received and int(content_type) != int(RecordType.ALERT):
            raise RecordClosedError("Peer has already sent close_notify")

        frame = self._seal(content_type, plaintext, self._send_sequence_number)
        self._send_sequence_number += 1

        if int(content_type) == int(RecordType.ALERT) and plaintext == self._ALERT_CLOSE_NOTIFY:
            self._local_close_notify_sent = True

        return frame

    def open_record(self, record_frame: bytes) -> bytes:
        """Decrypt a serialized record frame and return the plaintext bytes.

        The implicit receive sequence number is advanced only after successful
        authentication, which keeps replay detection bound to the current state.
        """
        self._ensure_open_state()
        record = self._open(record_frame, self._recv_sequence_number)
        self._recv_sequence_number += 1
        return record.plaintext

    def _abort_connection(self, sock: socket.socket) -> None:
        self._closed = True

        if self._teardown_callback is not None:
            try:
                self._teardown_callback()
            except Exception:
                pass

        _close_transport(sock)

    def _ensure_can_send(self, content_type: RecordType) -> None:
        if self._closed:
            raise RecordClosedError("Record session is closed")
        if self._peer_close_notify_received and content_type != RecordType.ALERT:
            raise RecordClosedError("Peer has already sent close_notify")

    def seal_record(self, content_type: RecordType, plaintext: bytes) -> bytes:
        """Build an encrypted frame without sending it."""
        return self._seal_and_advance(content_type, plaintext)

    def send_record(self, sock: socket.socket, content_type: RecordType, plaintext: bytes) -> bytes:
        """Encrypt and send a single record over a socket."""
        frame = self._seal_and_advance(content_type, plaintext)
        sock.sendall(frame)

        return frame

    def send_application_data(self, sock: socket.socket, data: bytes) -> bytes:
        return self.send_record(sock, RecordType.APPLICATION_DATA, data)

    def send_handshake_data(self, sock: socket.socket, data: bytes) -> bytes:
        return self.send_record(sock, RecordType.HANDSHAKE, data)

    def send_close_notify(self, sock: socket.socket) -> bytes:
        """Send an encrypted close_notify alert."""
        frame = self.send_record(sock, RecordType.ALERT, self._ALERT_CLOSE_NOTIFY)
        return frame

    def receive_record(self, sock: socket.socket) -> Record:
        """Receive, authenticate, and decrypt one record from a socket."""
        if self._closed:
            raise RecordClosedError("Record session is closed")

        try:
            header = _recv_exact(sock, 5)
            payload_length = int.from_bytes(header[3:5], "big")

            if payload_length > self.MAX_FRAGMENT_LENGTH:
                raise RecordLayerError("Encrypted payload length exceeds protocol limit")

            ciphertext = _recv_exact(sock, payload_length)
            frame = header + ciphertext
            record = self._open(frame, self._recv_sequence_number)
            self._recv_sequence_number += 1
            return record

        except RecordAuthenticationError:
            self._abort_connection(sock)
            raise
        except RecordLayerError:
            self._abort_connection(sock)
            raise

    def close(self, sock: socket.socket, send_close_notify: bool = True) -> None:
        """Terminate the session cleanly.

        If requested and still possible, sends an encrypted close_notify first.
        """
        if self._closed:
            return

        try:
            if send_close_notify and not self._local_close_notify_sent:
                self.send_close_notify(sock)
        finally:
            self._closed = True
            _close_transport(sock)
