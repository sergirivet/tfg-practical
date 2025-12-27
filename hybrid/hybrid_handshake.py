from classic.hkdf import hkdf_extract, hkdf_expand

def hybrid_session_key(dh_secret, pq_secret):
    combined = dh_secret + pq_secret
    prk = hkdf_extract(None, combined)
    return hkdf_expand(prk, b"hybrid handshake", 32)
