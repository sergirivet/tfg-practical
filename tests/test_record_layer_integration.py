from protocol.client import Client
from protocol.server import Server
from primitives.authentication.quantum import generate_keypair as generate_keypair_dilithium
from primitives.authentication.classical import generate_keypair as generate_keypair_ecdsa


def _build_handshake_pair():
    server_signing_public_dilithium, server_signing_private_dilithium = generate_keypair_dilithium()
    server_signing_public_ecdsa, server_signing_private_ecdsa = generate_keypair_ecdsa()

    client = Client(server_signing_public_dilithium, server_signing_public_ecdsa)
    server = Server(server_signing_private_dilithium, server_signing_private_ecdsa)

    client_pk_dh, client_pk_kyber = client.phase1_generate_ephemeral_keys()
    server_pk_dh, server_kyber_ciphertext, sig_dilithium, sig_ecdsa = server.phase2_generate_ephemeral_and_sign(
        client_pk_dh,
        client_pk_kyber,
    )

    client_session_key = client.phase3_verify_phase4_derive(
        server_pk_dh,
        server_kyber_ciphertext,
        sig_dilithium,
        sig_ecdsa,
    )
    server_session_key = server.phase4_derive_session_key(client_pk_dh)

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
