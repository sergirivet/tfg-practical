# Hybrid Post-Quantum Authenticated Handshake Protocol

Implementación Python de protocolos de handshake criptográficos clásicos, post-cuánticos e híbridos.

## Overview

Este proyecto implementa un protocolo de handshake autenticado que combina:
- **Criptografía clásica**: X25519 (Diffie-Hellman de curvas elípticas)
- **Criptografía post-cuántica**: ML-KEM-512 (Kyber) + ML-DSA-44 (Dilithium)
- **Híbrido seguro**: Protocolo 3.4 que autentica ambas claves efímeras

El objetivo es validar un enfoque defensivo en profundidad contra amenazas cuánticas mientras se mantiene la compatibilidad con algoritmos de confianza probada.

## Características

**Implementación completa**:
- Handshake clásico DH (X25519)
- Handshake post-cuántico (Kyber + Dilithium)
- Handshake híbrido autenticado 4-fase (Protocolo 3.4)
- Derivación segura de claves (HKDF-SHA256)
- Autenticación digital con ML-DSA-44

**Criptografía estándar**:
- X25519: RFC 7748 (Montgomery ladder)
- HKDF: RFC 5869 (HMAC-based KDF)
- HMAC-SHA256: RFC 2104
- ML-KEM-512 (Kyber): NIST FIPS 203
- ML-DSA-44 (Dilithium): NIST FIPS 204

**Suite de tests exhaustiva**:
- Handshake completo clásico
- Handshake híbrido sin autenticación
- Handshake autenticado (Protocolo 3.4)
- Validación de firmas digitales

## Estructura del Proyecto

```
tfg-practical/
├── classic/                    # Criptografía clásica
│   ├── hmac.py                # HMAC-SHA256 (RFC 2104)
│   └── hkdf.py                # HKDF-SHA256 (RFC 5869)
│
├── dh_kem/                     # Key Encapsulation Mechanism clásico
│   └── kem.py                 # X25519 Diffie-Hellman
│
├── pq_kem/                     # Key Encapsulation Mechanism post-cuántico
│   └── kyber_kem.py           # ML-KEM-512 (Kyber)
│
├── signatures/                 # Esquema de firma digital
│   └── signatures.py          # ML-DSA-44 (Dilithium)
│
├── hybrid/                      # Protocolo híbrido
│   ├── hybrid_handshake.py    # Lógica del protocolo
│   ├── client.py              # Implementación cliente
│   └── server.py              # Implementación servidor
│
├── tests/                       # Suite de pruebas
│   ├── test_full_handshake.py
│   ├── test_hybrid_handshake.py
│   ├── test_authenticated_handshake.py
│   └── test_protocol_3_4.py
│
└── README.md                    # Este archivo
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
