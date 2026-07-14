from protocol.client import Client
from protocol.server import Server
from primitives.authentication.hybrid import HybridSignatureEngine
from primitives.kem.hybrid import HybridKEMEngine


def _build_handshake_pair():
    kem_engine = HybridKEMEngine()
    signature_engine = HybridSignatureEngine()
    server_signing_private, server_signing_public = signature_engine.keygen()

    client = Client(server_signing_public, kem_engine, signature_engine)
    server = Server(server_signing_private, kem_engine, signature_engine)

    client_public_key = client.phase1_generate_ephemeral_keys()
    server_ciphertext, signature_blob = server.phase2_generate_ephemeral_and_sign(client_public_key)

    client_session_key = client.phase3_verify_phase4_derive(server_ciphertext, signature_blob)
    server_session_key = server.phase4_derive_session_key(client_public_key)

    assert client_session_key == server_session_key
    assert client.record_session is not None
    assert server.record_session is not None

    return client, server


def test_client_server_record_layer_application_data_roundtrip():
    client, server = _build_handshake_pair()

    client_frame = client.send_application_data(b"application payload from client")
    assert server.receive_application_data(client_frame) == b"application payload from client"

    server_frame = server.send_application_data(b"application payload from server")
    assert client.receive_application_data(server_frame) == b"application payload from server"


def test_client_server_record_layer_close_notify():
    client, server = _build_handshake_pair()

    close_frame = client.close_session()
    assert server.receive_application_data(close_frame) == b"\x01\x00"
    assert server.record_session.peer_close_notify_received is True
