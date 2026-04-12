# Hybrid Post-Quantum Authenticated Handshake Protocol

Implementación Python de protocolos de handshake criptográficos clásicos, post-cuánticos e híbridos con autenticación DUAL.

## Overview

Este proyecto implementa un protocolo de handshake autenticado que combina:
- **Criptografía clásica**: X25519 (Diffie-Hellman de curvas elípticas) + ECDSA (P-256)
- **Criptografía post-cuántica**: ML-KEM-512 (Kyber) + ML-DSA-44 (Dilithium)
- **Híbrido seguro**: Protocolo 3.4 con DUAL AUTENTICACIÓN (clásica + post-cuántica)

El objetivo es validar un enfoque defensivo en profundidad (defense-in-depth) contra amenazas cuánticas:
- Si una familia de firmas se ve comprometida, la otra sigue proporcionando seguridad
- Ambas firmas deben verificarse exitosamente para una autenticación completa
- Mantiene compatibilidad con algoritmos clásicos probados

## Características

**Implementación completa**:
- Handshake clásico DH (X25519)
- Handshake post-cuántico (Kyber + Dilithium)
- **Handshake híbrido autenticado DUAL-SIGNATURE** (Protocolo 3.4)
  - Firma 1: ECDSA P-256 (autenticación clásica)
  - Firma 2: ML-DSA-44 Dilithium (autenticación post-cuántica)
- Derivación segura de claves (HKDF-SHA256)
- Protección de integridad de mensajes (HMAC-SHA256)

**Criptografía estándar**:
- X25519: RFC 7748 (Montgomery ladder)
- HKDF: RFC 5869 (HMAC-based KDF)
- HMAC-SHA256: RFC 2104
- ECDSA P-256: NIST FIPS 186-4 (Sig.auth. clásica)
- ML-KEM-512 (Kyber): NIST FIPS 203
- ML-DSA-44 (Dilithium): NIST FIPS 204

**Suite de tests exhaustiva**:
- Handshake completo clásico
- Handshake híbrido sin autenticación
- Handshake autenticado DUAL-SIGNATURE (Protocolo 3.4)
- Pruebas de detección de MITM con ambos esquemas
- Validación de firmas individuales y híbridas

## Estructura del Proyecto

```
tfg-practical/
├── classic/                           # Criptografía clásica
│   ├── hmac.py                        # HMAC-SHA256 (RFC 2104)
│   └── hkdf.py                        # HKDF-SHA256 (RFC 5869)
│
├── dh_kem/                            # Key Encapsulation Mechanism clásico
│   └── kem.py                         # X25519 Diffie-Hellman
│
├── pq_kem/                            # Key Encapsulation Mechanism post-cuántico
│   └── kyber_kem.py                   # ML-KEM-512 (Kyber)
│
├── signatures/                        # Esquemas de firma digital HÍBRIDO
│   ├── signatures.py                  # ML-DSA-44 (Dilithium - post-cuántico)
│   └── ecdsa.py                       # ECDSA P-256 (clásico)
│
├── hybrid/                            # Protocolo híbrido DUAL-AUTH
│   ├── hybrid_handshake.py            # Lógica del protocolo (dual signatures)
│   ├── client.py                      # Implementación cliente
│   └── server.py                      # Implementación servidor
│
├── tests/                             # Suite completa de pruebas
│   ├── test_full_handshake.py         # Prueba DH clásico
│   ├── test_hybrid_handshake.py       # Prueba híbrido sin auth
│   ├── test_authenticated_handshake.py # Prueba dual-signature
│   ├── test_protocol_3_4.py           # Protocolo 3.4 (clientes/servidores)
│   └── test_hybrid_signatures.py      # Tests individuales ECDSA + Dilithium
│
└── README.md                          # Este archivo
```

## Autenticación Híbrida (DUAL-SIGNATURE)

El protocolo 3.4 implementa autenticación dual donde el servidor firma el handshake con AMBOS esquemas:

```
PHASE 0: Setup
  Server: genera keypairs DUALES (ECDSA + Dilithium)
  Client: obtiene ambas public keys a través de canal trusted

PHASE 1: Client Init
  Client: genera ephemeral keys y los envía al server

PHASE 2: Server Response & DUAL Signing
  Server: genera ephemeral keys y FIRMA con ambos esquemas
  transcript = concatenate(client_ephemeral_keys || server_ephemeral_keys)
  signature_ecdsa = ECDSA-P256(transcript)
  signature_dilithium = ML-DSA-44(transcript)

PHASE 3: Dual Verification  
  Client: VERIFICA AMBAS firmas
  ✓ Si ambas verifican: handshake autenticado (defense-in-depth)
  ✗ Si alguna falla: handshake ABORTADO (MITM detectado)

PHASE 4: Key Derivation
  Ambas partes: derivan session key (solo después de verificar ambas firmas)
  - DH shared secret: X25519 (efímero)
  - Kyber shared secret: ML-KEM-512 (efímero)  
  - Hybrid session key: HKDF(DH secret || Kyber secret)

POST-HANDSHAKE: Message Protection
  - HMAC-SHA256: integridad de messages (ya no se usan firmas)
```

## Requisitos

- Python 3.8+
- Dependencias criptográficas:
  ```
  cryptography>=41.0.0  # Para X25519 y HKDF
  ml-kem>=0.2.0         # Para ML-KEM-512 (Kyber)
  ml-dsa>=0.2.0         # Para ML-DSA-44 (Dilithium)
  ```

## Instalación

```bash
# Clonar repositorio
git clone <repository-url>
cd tfg-practical

# Crear ambiente virtual (recomendado)
python3 -m venv .venv
source .venv/bin/activate  # En macOS/Linux
# source .venv/Scripts/activate  # En Windows

# Instalar dependencias
pip install -r requirements.txt
```

## Uso

### 1. Handshake Clásico Simple

```python
from dh_kem.kem import dh_keygen, dh_shared_secret
from classic.hkdf import expand_extract

# Generar claves efímeras
sk_a, pk_a = dh_keygen()
sk_b, pk_b = dh_keygen()

# Calcular secreto compartido
ss = dh_shared_secret(sk_a, pk_b)

# Derivar clave de sesión
session_key = expand_extract(ss, b"context")
print(f"Session key: {session_key.hex()}")
```

### 2. Handshake Híbrido con Autenticación (Protocolo 3.4)

```python
from hybrid.client import Client
from hybrid.server import Server
from signatures.signatures import generate_keypair

# PHASE 0: Servidor genera claves de firma a largo plazo
sk_sign, pk_sign = generate_keypair()
server = Server(sk_sign)
client = Client(pk_sign)

# PHASE 1: Cliente genera claves efímeras
client.phase1()

# PHASE 2: Servidor responde y firma el transcript
server_response = server.phase2(client._pk_dh, client._pk_kyber)

# PHASE 3: Cliente verifica la firma
client.phase3(server_response[0], server_response[1], server_response[2])

# PHASE 4: Ambos derivan la clave de sesión híbrida
server.phase4(client._pk_dh, client._pk_kyber, server_response[3])

print(f"Client session key: {client.session_key.hex()}")
print(f"Server session key: {server.session_key.hex()}")
print(f"Keys match: {client.session_key == server.session_key}")
```

### 3. Ejecución de Tests

```bash
# Ejecutar todos los tests
pytest tests/

# Ejecutar un test específico
pytest tests/test_protocol_3_4.py -v

# Ejecutar con cobertura
pytest tests/ --cov=. --cov-report=html
```

## Protocolo 3.4 - Especificación Detallada

### Fase 0: Setup (Server, off-line)
```
sk_sign, pk_sign ← ML-DSA-44.KeyGen()
Server almacena sk_sign (secreto a largo plazo)
```

### Fase 1: Inicialización del Cliente
```
sk_dh, pk_dh ← X25519.KeyGen()
sk_kyber, pk_kyber ← ML-KEM-512.KeyGen()
Cliente → Servidor: pk_dh || pk_kyber
```

### Fase 2: Respuesta del Servidor
```
sk_dh', pk_dh' ← X25519.KeyGen()
sk_kyber', pk_kyber' ← ML-KEM-512.KeyGen()
(ss_kyber, ct_kyber) ← ML-KEM-512.Encaps(pk_kyber)

transcript = pk_dh || pk_kyber || pk_dh' || pk_kyber' || ct_kyber
sig ← ML-DSA-44.Sign(sk_sign, transcript)

Servidor → Cliente: pk_dh' || pk_kyber' || ct_kyber || sig
```

### Fase 3: Verificación del Cliente
```
transcript = pk_dh || pk_kyber || pk_dh' || pk_kyber' || ct_kyber
ML-DSA-44.Verify(pk_sign, transcript, sig)  // Si falla: abort
```

### Fase 4: Derivación de Clave (Cliente y Servidor)
```
ss_dh ← X25519.SharedSecret(sk_dh, pk_dh')
ss_kyber ← ML-KEM-512.Decaps(sk_kyber, ct_kyber)

hybrid_ss = ss_dh || ss_kyber
session_key = HKDF-SHA256.Expand(hybrid_ss, "hybrid-session-key", 32)
```

## Tests Disponibles

| Test | Descripción | Protocolo |
|------|-------------|-----------|
| `test_full_handshake.py` | Handshake clásico básico | DH simple |
| `test_hybrid_handshake.py` | DH + Kyber sin autenticación | Híbrido no autenticado |
| `test_authenticated_handshake.py` | Protocolo completo con firmas | Protocolo 3.4 |
| `test_protocol_3_4.py` | Interfaz Client/Server formal | Protocolo 3.4 (recomendado) |

## Roadmap - Trabajo Pendiente

### 3.5 Benchmarks and Measurements (TODO)

Se implementarán métricas de performance para evaluar:

- **Latencia**: Tiempo de ejecución de cada fase y handshake completo
- **Uso de memoria**: Peak memory durante operaciones criptográficas
- **Tamaño de keys**: Comparativa de bytes transmitidos (pk_dh vs pk_kyber vs certificates)
- **Throughput**: Handshakes/segundo según configuración

**Salida esperada**:
- Tabla CSV con resultados
- Gráficos comparativos (latencia, memoria, tamaño)
- Análisis del overhead de hibridación

**Script propuesto**: `benchmark.py` en raíz del proyecto

### 3.6 Mini Web Server (Opcional) 

Servidor HTTP+UI para demostración interactiva de protocolos.

## Dependencias Internas

```
classic/
  ├── hmac.py: Primitiva para HKDF y MAC
  └── hkdf.py: Derivación de claves

dh_kem/
  └── kem.py: X25519 (requiere cryptography)

pq_kem/
  └── kyber_kem.py: ML-KEM-512 (requiere ml-kem)

signatures/
  └── signatures.py: ML-DSA-44 (requiere ml-dsa)

hybrid/
  ├── hybrid_handshake.py: Lógica del protocolo
  ├── client.py: Requiere dh_kem, pq_kem, signatures, classic
  └── server.py: Requiere dh_kem, pq_kem, signatures, classic
```

## Notas Técnicas

### Seguridad

- **Post-quantum readiness**: Utiliza algoritmos NIST FIPS 203/204
- **Defensa en profundidad**: Combinación de DH + Kyber previene compromisos parciales
- **Autenticación**: Firmas digitales garantizan integridad del transcript
- **Derivación segura**: HKDF-SHA256 con extractores apropiados

### Performance Esperado

(Se agregará con benchmarks en sección 3.5)


## Autor

Sergi 

---

**Última actualización**: 25 Marzo 2026
