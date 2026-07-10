import socket

import pytest

from protocol.record_layer import (
    AlertDescription,
    RecordAuthenticationError,
    RecordClosedError,
    RecordSession,
    RecordType,
)


def _socket_pair():
    left, right = socket.socketpair()
    left.settimeout(1.0)
    right.settimeout(1.0)
    return left, right


def test_record_layer_roundtrip_and_directionality():
    master_secret = b"\x11" * 32
    client = RecordSession(master_secret, role="client")
    server = RecordSession(master_secret, role="server")
    client_sock, server_sock = _socket_pair()

    try:
        client.send_application_data(client_sock, b"hello application layer")
        incoming = server.receive_record(server_sock)

        assert incoming.content_type == RecordType.APPLICATION_DATA
        assert incoming.plaintext == b"hello application layer"
        assert client.send_sequence_number == 1
        assert server.recv_sequence_number == 1

        server.send_application_data(server_sock, b"pong")
        reply = client.receive_record(client_sock)

        assert reply.content_type == RecordType.APPLICATION_DATA
        assert reply.plaintext == b"pong"
        assert server.send_sequence_number == 1
        assert client.recv_sequence_number == 1

    finally:
        client_sock.close()
        server_sock.close()


def test_close_notify_is_encrypted_and_recognized():
    master_secret = b"\x22" * 32
    client = RecordSession(master_secret, role="client")
    server = RecordSession(master_secret, role="server")
    client_sock, server_sock = _socket_pair()

    try:
        client.send_close_notify(client_sock)
        alert = server.receive_record(server_sock)

        assert alert.content_type == RecordType.ALERT
        assert alert.alert_description == AlertDescription.CLOSE_NOTIFY
        assert server.peer_close_notify_received is True

        with pytest.raises(RecordClosedError):
            server.send_application_data(server_sock, b"not allowed after close_notify")

    finally:
        client_sock.close()
        server_sock.close()


def test_replayed_record_triggers_authentication_failure_and_teardown():
    master_secret = b"\x33" * 32
    teardowns = []

    def teardown_callback():
        teardowns.append(True)

    client = RecordSession(master_secret, role="client")
    server = RecordSession(master_secret, role="server", teardown_callback=teardown_callback)
    client_sock, server_sock = _socket_pair()

    try:
        frame = client.seal_record(RecordType.APPLICATION_DATA, b"replay-probe")

        client_sock.sendall(frame)
        first = server.receive_record(server_sock)
        assert first.plaintext == b"replay-probe"

        client_sock.sendall(frame)
        with pytest.raises(RecordAuthenticationError):
            server.receive_record(server_sock)

        assert teardowns == [True]
        assert server.closed is True

    finally:
        client_sock.close()
        server_sock.close()
