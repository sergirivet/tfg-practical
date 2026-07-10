# Hybrid Post-Quantum Authenticated Handshake Protocol

Implementación Python de protocolos de handshake criptográficos clásicos, post-cuánticos e híbridos con autenticación DUAL.

## Overview

Este proyecto implementa un protocolo de handshake autenticado que combina:
- **Criptografía clásica**: X25519 (Diffie-Hellman de curvas elípticas) + ECDSA (P-256)
- **Criptografía post-cuántica**: ML-KEM-512 (Kyber) + ML-DSA-44 (Dilithium)
- **Híbrido seguro**: Protocolo 3.4 con DUAL AUTENTICACIÓN (clásica + post-cuántica)
- **Capa de datos segura**: Record Layer con AES-256-GCM y `RecordSession`

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
- Record Layer autenticada para datos de aplicación con AES-256-GCM
- Demo live sobre sockets reales con `demo_live.py`

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
- Integración de Record Layer y transmisión segura de datos
- Pruebas de detección de MITM con ambos esquemas
- Validación de firmas individuales y híbridas

## Estructura del Proyecto

```
tfg-practical/
├── primitives/                        # Capas de primitivos criptográficos
│   ├── __init__.py
│   ├── kdf/                           # Key Derivation Functions
│   │   ├── __init__.py
│   │   ├── hmac.py                    # HMAC-SHA256 (RFC 2104)
│   │   └── hkdf.py                    # HKDF-SHA256 (RFC 5869)
│   ├── kem/                           # Key Encapsulation Mechanisms
│   │   ├── __init__.py
│   │   ├── classical.py               # X25519 Diffie-Hellman (RFC 7748)
│   │   └── quantum.py                 # ML-KEM-512 (Kyber, NIST FIPS 203)
│   └── authentication/                # Esquemas de firma digital
│       ├── __init__.py
│       ├── classical.py               # ECDSA P-256 (NIST FIPS 186-4)
│       └── quantum.py                 # ML-DSA-44 (Dilithium, NIST FIPS 204)
│
├── protocol/                          # Capa de composición de protocolo
│   ├── __init__.py
│   ├── hybrid_handshake.py            # Lógica del protocolo (dual signatures)
│   ├── client.py                      # Implementación cliente
│   ├── record_layer.py                # Capa de datos segura (AES-256-GCM)
│   └── server.py                      # Implementación servidor
│
├── tests/                             # Suite completa de pruebas
│   ├── __init__.py
│   ├── test_complete_hybrid_authenticated_handshake.py
│   ├── test_hybrid_kem_exchange.py
│   └── test_hybrid_signatures.py
│
├── benchmark_suite.py                 # Suite de benchmarking de rendimiento
├── benchmarks_results.csv             # Resultados de mediciones
├── demo_live.py                       # Demo live sobre socket real (localhost)
├── README.md                          # Este archivo
└── requirements.txt                   # Dependencias del proyecto
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

sk_a, pk_a = dh_keygen()
sk_b, pk_b = dh_keygen()

# Calcular secreto compartido
ss = dh_shared_secret(sk_a, pk_b)

# Derivar clave de sesión
prk = hkdf_extract(b"salt", ss)
session_key = hkdf_expand(prk, b"context", 32)
print(f"Session key: {session_key.hex()}")
```

### 2. Handshake Híbrido con Autenticación Dual (Protocolo 3.4)

```python
from protocol.client import Client
from protocol.server import Server
from primitives.authentication.classical import generate_keypair as generate_ecdsa_keypair
from primitives.authentication.quantum import generate_keypair as generate_dilithium_keypair

# Fase 0: el servidor crea sus claves de firma a largo plazo
server_signing_public_dilithium, server_signing_private_dilithium = generate_dilithium_keypair()
server_signing_public_ecdsa, server_signing_private_ecdsa = generate_ecdsa_keypair()

client = Client(server_signing_public_dilithium, server_signing_public_ecdsa)
server = Server(server_signing_private_dilithium, server_signing_private_ecdsa)

# Fase 1: el cliente genera sus claves efímeras híbridas
client_pk_dh, client_pk_kyber = client.phase1_generate_ephemeral_keys()

# Fase 2: el servidor encapsula hacia la clave pública Kyber del cliente y firma el transcript
server_pk_dh, server_kyber_ciphertext, sig_dilithium, sig_ecdsa = server.phase2_generate_ephemeral_and_sign(
  client_pk_dh,
  client_pk_kyber,
)

# Fase 3: el cliente verifica ambas firmas antes de usar cualquier secreto derivado
client_session_key = client.phase3_verify_phase4_derive(
  server_pk_dh,
  server_kyber_ciphertext,
  sig_dilithium,
  sig_ecdsa,
)

# Fase 4: el servidor completa la misma derivación de sesión
server_session_key = server.phase4_derive_session_key(client_pk_dh)

assert client_session_key == server_session_key
print(f"Master secret established: {client_session_key.hex()}")
```

### 3. Transmisión Segura de Datos (Record Protocol)

```python
import socket

from protocol.client import Client
from protocol.server import Server
from primitives.authentication.classical import generate_keypair as generate_ecdsa_keypair
from primitives.authentication.quantum import generate_keypair as generate_dilithium_keypair

def recv_frame(sock):
  # La cabecera fija del record incluye type, version y length.
  header = sock.recv(5)
  if len(header) != 5:
    raise RuntimeError("Truncated record header")

  payload_length = int.from_bytes(header[3:5], "big")
  payload = b""
  while len(payload) < payload_length:
    chunk = sock.recv(payload_length - len(payload))
    if not chunk:
      raise RuntimeError("Truncated record payload")
    payload += chunk

  return header + payload

# Handshake previo completo
server_signing_public_dilithium, server_signing_private_dilithium = generate_dilithium_keypair()
server_signing_public_ecdsa, server_signing_private_ecdsa = generate_ecdsa_keypair()
client = Client(server_signing_public_dilithium, server_signing_public_ecdsa)
server = Server(server_signing_private_dilithium, server_signing_private_ecdsa)

client_pk_dh, client_pk_kyber = client.phase1_generate_ephemeral_keys()
server_pk_dh, server_kyber_ciphertext, sig_dilithium, sig_ecdsa = server.phase2_generate_ephemeral_and_sign(
  client_pk_dh,
  client_pk_kyber,
)
client_master_secret = client.phase3_verify_phase4_derive(
  server_pk_dh,
  server_kyber_ciphertext,
  sig_dilithium,
  sig_ecdsa,
)
server_master_secret = server.phase4_derive_session_key(client_pk_dh)

assert client_master_secret == server_master_secret

# En la fase de datos ya no participan firmas: AES-256-GCM protege cada record
# y el AAD incluye el header más el sequence_number implícito para bloquear replay.

# Socket simulado para transporte dúplex
client_sock, server_sock = socket.socketpair()

# Cliente -> Servidor
client_frame = client.send_application_data(b"GET /v1/account/balance")
client_sock.sendall(client_frame)
server_incoming = recv_frame(server_sock)
server_plaintext = server.receive_application_data(server_incoming)
print(server_plaintext.decode())

# Servidor -> Cliente
server_frame = server.send_application_data(b"HTTP/1.1 200 OK")
server_sock.sendall(server_frame)
client_incoming = recv_frame(client_sock)
client_plaintext = client.receive_application_data(client_incoming)
print(client_plaintext.decode())

# Cierre limpio autenticado con close_notify
close_frame = client.close_session()
client_sock.sendall(close_frame)
close_record = recv_frame(server_sock)
server.receive_application_data(close_record)
print("close_notify recibido y autenticado")
```

### 4. Demo Live sobre Socket Real

```bash
# Ejecutar la demostración end-to-end sobre 127.0.0.1:8080
python demo_live.py
```

La demo levanta un servidor y un cliente en threads, completa el handshake híbrido, transmite un mensaje de aplicación cifrado con AES-256-GCM y finaliza con `close_notify` autenticado.

### 5. Ejecución de Tests

```bash
# Ejecutar todos los tests
pytest tests/

# Ejecutar un test específico
pytest tests/test_complete_hybrid_authenticated_handshake.py -v

# Ejecutar con cobertura
pytest tests/ --cov=. --cov-report=html
```

### 6. Suite de Benchmarking

Ejecutar análisis de rendimiento y payload de red:

```bash
# Ejecutar benchmarks completos (genera gráficos y CSV)
python benchmark_suite.py

# Salida esperada:
#  - Tabla Markdown con comparativas
#  - benchmarks_results.csv con datos detallados
#  - Gráficos de latencia y payload
#  - Análisis de fragmentación de packets
```
client.phase3(server_response[0], server_response[1], server_response[2])
# Fase 4: el servidor completa la misma derivación de sesión

# PHASE 4: Ambos derivan la clave de sesión híbrida
server.phase4(client._pk_dh)

print(f"Client session key: {client.session_key.hex()}")
print(f"Server session key: {server.session_key.hex()}")
print(f"Keys match: {client.session_key == server.session_key}")
print(f"Defense-in-depth: Both classical and post-quantum signatures verified ✓")
```

### 3. Ejecución de Tests

```bash
# Ejecutar todos los tests
pytest tests/

# Ejecutar un test específico
pytest tests/test_complete_hybrid_authenticated_handshake.py -v

# Ejecutar con cobertura
pytest tests/ --cov=. --cov-report=html
```

### 4. Suite de Benchmarking

Ejecutar análisis de rendimiento y payload de red:

```bash
# Ejecutar benchmarks completos (genera gráficos y CSV)
python benchmark_suite.py

# Salida esperada:
#  - Tabla Markdown con comparativas
#  - benchmarks_results.csv con datos detallados
#  - Gráficos de latencia y payload
#  - Análisis de fragmentación de packets
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
(ss_kyber, ct_kyber) ← ML-KEM-512.Encaps(pk_kyber)

transcript = pk_dh || pk_kyber || pk_dh' || ct_kyber
sig ← ML-DSA-44.Sign(sk_sign, transcript)

Servidor → Cliente: pk_dh' || ct_kyber || sig
```

### Fase 3: Verificación del Cliente
```
transcript = pk_dh || pk_kyber || pk_dh' || ct_kyber
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

| Test | Descripción |
|------|-------------|
| `test_hybrid_signatures.py` | Pruebas individuales de ECDSA P-256 + ML-DSA-44 |
| `test_hybrid_kem_exchange.py` | Intercambio híbrido de claves (X25519 + ML-KEM-512) |
| `test_complete_hybrid_authenticated_handshake.py` | Protocolo 3.4 completo: KEM híbrido + dual signatures |

## Performance Measurements (Benchmarks)

El proyecto incluye una **suite completa de benchmarking** (`benchmark_suite.py`) que mide el rendimiento de los cuatro escenarios criptográficos:

### Métricas Capturadas

#### 1. Latencia
- **Cold Start**: Tiempo de la primera ejecución (warm-up no óptimo)
- **Warm Mean**: Promedio de 99 ejecuciones subsecuentes
- **Standard Deviation**: Variabilidad entre ejecuciones
- **Desglose por componentes**:
  - Key Generation (tiempo para generar claves efímeras)
  - Encapsulation/Signing (tiempo de operaciones criptográficas)
  - Verification/Decapsulation (tiempo de verificación)

#### 2. Tamaño de Payload (Análisis de Red)
- **Total Bytes**: Suma de todos los datos transmitidos en el handshake
- **Fragmentación**: Detección de excedencia del MTU (Ethernet: 1,500 bytes)
- **Número de Packets**: Cantidad de paquetes IP requeridos
- **Desglose por componente**:
  - Public keys (DH, Kyber)
  - Ciphertexts (encapsulación)
  - Signatures (ECDSA, Dilithium)

### Escenarios Benchmarkeados

| Escenario | KEM | Signatures | Use Case |
|-----------|-----|-----------|----------|
| **Classical** | X25519 (DH) | ECDSA P-256 | Baseline (seguridad probada) |
| **Post-Quantum** | ML-KEM-512 (Kyber) | ML-DSA-44 (Dilithium) | Máxima preparación post-cuántica |
| **Hybrid KEM-Only** | X25519 + ML-KEM-512 | ECDSA P-256 | Defensa híbrida sin overhead de firmas PQ |
| **Full Hybrid** | X25519 + ML-KEM-512 | ECDSA P-256 + ML-DSA-44 | Defensa en profundidad total |

### Ejecución y Resultados

```bash
# Ejecutar benchmarks (toma ~5-10 minutos)
python benchmark_suite.py
```

**Archivos generados**:
- `benchmarks_results.csv` - Datos tabulares exportables para análisis
- `benchmark_latency.png` - Gráfico comparativo de latencias
- `benchmark_payload.png` - Gráfico de tamaños de payload con umbral MTU
- `benchmark_component_timings.png` - Desglose de tiempos por componente

### Hallazgos Clave

#### Payload Network (Fragmentación)
- **Classical**: ~200 bytes → **1 packet** (OK)
- **Post-Quantum**: ~2,500 bytes → **2 packets** (Fragmented)
- **Hybrid KEM-Only**: ~2,400 bytes → **2 packets** (Fragmented)
- **Full Hybrid**: ~4,900 bytes → **4 packets** (Heavily Fragmented)

#### Trade-offs Seguridad vs. Eficiencia
- **Hybrid KEM-Only**: 10% overhead vs Classical, máxima compatibilidad red
- **Full Hybrid**: 2400% overhead en payload (Dilithium signature = ~2,420 bytes)
- Pero: Full Hybrid proporciona **defense-in-depth** dual-signature

#### Performance (Ejemplo representativo - varía según máquina)
- Key Generation: Kyber ≈ 5-10x más lento que X25519
- Signing: Dilithium ≈ 100-500x más lento que ECDSA
- Verification: ML-DSA-44 ≈ 50-200x más lento que ECDSA

## Roadmap - Trabajo Pendiente

### 3.6 Mini Web Server (Opcional) 

Servidor HTTP+UI para demostración interactiva de protocolos.

## Dependencias del Proyecto

### Estructura Modular

```
primitives/
  ├── kdf/
  │   ├── hmac.py: Primitiva para HKDF y MAC (RFC 2104)
  │   └── hkdf.py: Derivación de claves (RFC 5869)
  │
  ├── kem/
  │   ├── classical.py: X25519 Diffie-Hellman (RFC 7748)
  │   └── quantum.py: ML-KEM-512 Kyber (NIST FIPS 203)
  │
  └── authentication/
      ├── classical.py: ECDSA P-256 (NIST FIPS 186-4)
      └── quantum.py: ML-DSA-44 Dilithium (NIST FIPS 204)

protocol/
  ├── hybrid_handshake.py: Lógica del protocolo (dual signatures)
  ├── client.py: Requiere primitives/{kdf, kem, authentication}
  └── server.py: Requiere primitives/{kdf, kem, authentication}

tests/
  ├── test_complete_hybrid_authenticated_handshake.py
  ├── test_hybrid_kem_exchange.py
  └── test_hybrid_signatures.py
```

### Dependencias Externas

```
cryptography>=41.0.0    # X25519 (DH), ECDSA P-256, HKDF
ml-kem>=0.2.0          # ML-KEM-512 (Kyber)
ml-dsa>=0.2.0          # ML-DSA-44 (Dilithium)
pytest                 # Testing framework
matplotlib             # Gráficos de benchmarks (opcional)
```

## Notas Técnicas

### Seguridad

- **Post-quantum readiness**: Utiliza algoritmos NIST FIPS 203/204
- **Defensa en profundidad**: Combinación de DH + Kyber previene compromisos parciales
- **Autenticación**: Firmas digitales garantizan integridad del transcript
- **Derivación segura**: HKDF-SHA256 con extractores apropiados

### Performance Esperado

Ver sección **Performance Measurements (Benchmarks)** arriba para métricas detalladas de:
- Latencia por fase y total
- Tamaño de payload y análisis de fragmentación
- Desglose de tiempo por componente criptográfico


## Autor

Sergi 

---

**Última actualización**: 10 Julio 2026
