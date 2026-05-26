# Online Image Encryption Application (IEA) — Documentation

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Programming Tools](#programming-tools)
4. [Encryption Algorithms](#encryption-algorithms)
5. [Hash Functions](#hash-functions)
6. [Digital Signatures](#digital-signatures)
7. [Distributed System Organization](#distributed-system-organization)
8. [Communication Tools](#communication-tools)
9. [Security Tools](#security-tools)
10. [Synchronization Tools](#synchronization-tools)
11. [Database Management](#database-management)
12. [Web-Server Tools](#web-server-tools)
13. [How to Run](#how-to-run)
14. [File Structure](#file-structure)

---

## Overview

IEA is a client-server application where clients communicate by exchanging **DES-encrypted, digitally signed images** over a network. Session secret keys are exchanged using **RSA encryption**, and RSA keys are **periodically rotated** by the server. A **sysadmin** can monitor the server through a dedicated admin panel.

**Key principle**: All cryptographic primitives (DES, RSA, SHA-256) are implemented **from scratch** — no external crypto libraries are used.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    IEA SERVER (server.py)                 │
│                                                          │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ TCP Socket   │  │ SQLite DB    │  │ Key Rotation   │  │
│  │ Server       │  │ (database.py)│  │ Thread         │  │
│  │ (multi-      │  │              │  │ (background)   │  │
│  │  threaded)   │  │ - users      │  │                │  │
│  │              │  │ - messages   │  │ Regenerates    │  │
│  │ Handles:     │  │ - images     │  │ RSA keys every │  │
│  │ - auth       │  │ - admin_logs │  │ 5 minutes      │  │
│  │ - chat       │  │ - session_   │  │                │  │
│  │ - images     │  │   keys       │  │                │  │
│  │ - key mgmt   │  │              │  │                │  │
│  └─────────────┘  └──────────────┘  └────────────────┘  │
│              │                                           │
│              │  Encrypted images stored in               │
│              │  encrypted_images/ folder                  │
└──────────────┼───────────────────────────────────────────┘
               │
     TCP Sockets (JSON protocol)
               │
    ┌──────────┼──────────┐
    │          │          │
┌───▼───┐ ┌───▼───┐ ┌───▼───┐
│Client │ │Client │ │Admin  │
│  A    │ │  B    │ │Monitor│
│(GUI)  │ │(GUI)  │ │(GUI)  │
└───────┘ └───────┘ └───────┘
```

### Communication Flow (Image Exchange)

```
Client A                          Server                          Client B
   │                                │                                │
   │─── 1. Login ──────────────────►│                                │
   │◄── 2. RSA keys (pub+priv) ────│                                │
   │                                │                                │
   │─── 3. Request B's public key ─►│                                │
   │◄── 4. B's RSA public key ─────│                                │
   │                                │                                │
   │─── 5. Generate DES session key │                                │
   │─── 6. Encrypt DES key with    │                                │
   │       B's RSA public key       │                                │
   │─── 7. Send encrypted key ────►│──── 8. Forward to B ──────────►│
   │                                │                                │
   │─── 9. Encrypt image with DES  │                                │
   │─── 10. Sign encrypted image   │                                │
   │        (SHA-256 + RSA)         │                                │
   │─── 11. Send encrypted+signed ►│──── 12. Store encrypted ──────│
   │                                │──── 13. Forward to B ────────►│
   │                                │                                │
   │                                │         14. Verify signature  │
   │                                │         15. Decrypt DES key   │
   │                                │         16. Decrypt image     │
```

---

## Programming Tools

| Tool | Version | Purpose |
|------|---------|---------|
| **Python** | 3.8+ | Main programming language |
| **Tkinter** | Built-in | GUI framework for client and admin |
| **SQLite3** | Built-in | Database engine |
| **socket** | Built-in | TCP network communication |
| **threading** | Built-in | Multi-threaded server and client |
| **json** | Built-in | Message serialization protocol |
| **base64** | Built-in | Binary data encoding for transmission |
| **struct** | Built-in | Byte packing for SHA-256 |
| **os** | Built-in | File operations and random bytes |

**Note**: No external packages are required. Everything uses Python's standard library.

---

## Encryption Algorithms

### DES (Data Encryption Standard)

**File**: `crypto_utils/des.py`

- **Type**: Symmetric block cipher
- **Block size**: 64 bits (8 bytes)
- **Key size**: 56 bits (64-bit key with 8 parity bits)
- **Mode**: ECB (Electronic Codebook)
- **Padding**: PKCS5

**Implementation details**:
- All standard DES permutation tables (IP, FP, E, P, PC1, PC2)
- 8 S-boxes (S1–S8) for substitution
- 16-round Feistel network
- Key schedule generates 16 round keys from the master key

**How DES is used in IEA**:
1. Images are encrypted with DES before transmission
2. Images are stored DES-encrypted on the server
3. Chat messages are encrypted with DES session keys

**Algorithm steps**:
```
Input: 64-bit plaintext block, 64-bit key

1. Generate 16 round keys via key schedule (PC1, shifts, PC2)
2. Apply Initial Permutation (IP) to plaintext
3. Split into 32-bit halves: L₀, R₀
4. For rounds i = 1 to 16:
   a. Expand R (32→48 bits) via E-table
   b. XOR with round key Kᵢ
   c. Apply 8 S-boxes (48→32 bits)
   d. Apply P permutation
   e. Lᵢ = Rᵢ₋₁, Rᵢ = Lᵢ₋₁ ⊕ f(Rᵢ₋₁, Kᵢ)
5. Combine R₁₆L₁₆ (note swap)
6. Apply Final Permutation (FP)

Output: 64-bit ciphertext block
```

### RSA (Rivest–Shamir–Adleman)

**File**: `crypto_utils/rsa.py`

- **Type**: Asymmetric (public-key) cryptosystem
- **Key size**: 512 bits
- **Public exponent**: e = 65537

**Implementation details**:
- Miller-Rabin primality test (40 rounds) for prime generation
- Extended Euclidean Algorithm for modular inverse
- Python's built-in `pow(base, exp, mod)` for modular exponentiation

**How RSA is used in IEA**:
1. **Key exchange**: DES session keys are encrypted with recipient's RSA public key
2. **Digital signatures**: Image hashes are signed with sender's RSA private key
3. **Key rotation**: Server periodically regenerates RSA keys for all users

**Algorithm steps**:
```
Key Generation:
1. Generate two large primes p, q (each ~256 bits for 512-bit RSA)
2. Compute n = p × q
3. Compute φ(n) = (p-1) × (q-1)
4. Choose e = 65537
5. Compute d = e⁻¹ mod φ(n) (using Extended Euclidean Algorithm)
6. Public key = (e, n), Private key = (d, n)

Encryption:  c = m^e mod n
Decryption:  m = c^d mod n
```

---

## Hash Functions

### SHA-256 (Secure Hash Algorithm 256-bit)

**File**: `crypto_utils/sha256.py`

- **Type**: Cryptographic hash function
- **Output**: 256 bits (32 bytes, 64 hex characters)
- **Standard**: FIPS 180-4

**Implementation details**:
- 8 initial hash values (H0–H7)
- 64 round constants (K)
- 6 logical functions: Ch, Maj, Σ₀, Σ₁, σ₀, σ₁
- Message preprocessing with padding and length encoding

**How SHA-256 is used in IEA**:
- Hashing image data before signing with RSA (digital signature)
- SHA-256 reduces arbitrary-length data to a fixed 256-bit hash that can be signed with RSA

**Algorithm steps**:
```
1. Pad message:
   - Append bit '1'
   - Append zeros until length ≡ 448 mod 512
   - Append original message length as 64-bit big-endian

2. Process each 512-bit block:
   a. Prepare message schedule W[0..63]
   b. Initialize working variables a..h from current hash
   c. 64 rounds of compression:
      T1 = h + Σ₁(e) + Ch(e,f,g) + K[i] + W[i]
      T2 = Σ₀(a) + Maj(a,b,c)
      Shift variables, add T1 and T2
   d. Add compressed values to hash

3. Output: concatenation of final H0..H7 (256 bits)
```

---

## Digital Signatures

**File**: `crypto_utils/signature.py`

**How it works**:
1. **Signing**: Hash the data with SHA-256, then "encrypt" the hash with the sender's RSA **private** key
2. **Verification**: "Decrypt" the signature with the sender's RSA **public** key, hash the data with SHA-256, compare the two values

```
Signing:   signature = hash(data)^d mod n    (using private key d)
Verifying: recovered  = signature^e mod n    (using public key e)
           valid = (recovered == hash(data))
```

**Purpose**: Ensures the image was sent by the claimed sender (authenticity) and wasn't tampered with (integrity).

---

## Distributed System Organization

### Client-Server Model

- **Server** (`server.py`): Central node that all clients connect to
- **Clients** (`client.py`): Connect to the server via TCP sockets
- **Admin** (`admin.py`): Special client for sysadmin monitoring

### Message Routing
- All messages pass through the server
- Server routes messages to the correct recipient based on username
- If recipient is offline, messages are stored in the database

### Key Management
- RSA keys are generated on the server and distributed to clients
- A background thread rotates all RSA keys every 5 minutes (configurable)
- When keys rotate, online clients receive their new keys immediately
- DES session keys are generated by clients and exchanged via RSA encryption

---

## Communication Tools

### TCP Sockets (Python `socket` module)

- **Protocol**: TCP (reliable, ordered delivery)
- **Message format**: 4-byte big-endian length prefix + JSON payload
- **Binary data**: Base64-encoded within JSON messages

```
┌──────────┬────────────────────────┐
│ 4 bytes  │    N bytes             │
│ (length) │    (JSON payload)      │
└──────────┴────────────────────────┘
```

### Message Types

| Type | Direction | Description |
|------|-----------|-------------|
| `REGISTER` | Client → Server | Register new user |
| `LOGIN` | Client → Server | Authenticate user |
| `LOGIN_RESPONSE` | Server → Client | Auth result + RSA keys |
| `GET_USERS` | Client → Server | Request online user list |
| `USER_LIST` | Server → Client | Online user list (broadcast) |
| `GET_PUBLIC_KEY` | Client → Server | Request a user's RSA public key |
| `PUBLIC_KEY_RESPONSE` | Server → Client | User's RSA public key |
| `CHAT` | Bidirectional | DES-encrypted chat message |
| `SEND_IMAGE` | Client → Server | Encrypted + signed image |
| `IMAGE` | Server → Client | Forward encrypted image to recipient |
| `SEND_SESSION_KEY` | Client → Server | RSA-encrypted DES session key |
| `SESSION_KEY_UPDATE` | Server → Client | Forward session key to recipient |
| `KEY_ROTATION` | Server → Client | New RSA keys (periodic) |
| `ADMIN_LOGIN` | Admin → Server | Admin authentication |
| `ADMIN_STATS` | Admin → Server | Request server statistics |
| `ADMIN_LOGS` | Admin → Server | Request admin log entries |

---

## Security Tools

### Implemented from Scratch (No Libraries)

| Tool | Purpose | File |
|------|---------|------|
| DES | Symmetric encryption of images and messages | `crypto_utils/des.py` |
| RSA | Asymmetric encryption for key exchange and signatures | `crypto_utils/rsa.py` |
| SHA-256 | Cryptographic hashing for digital signatures | `crypto_utils/sha256.py` |
| Digital Signatures | Authenticity and integrity verification | `crypto_utils/signature.py` |

### Security Features

1. **Confidentiality**: Images and messages encrypted with DES
2. **Key Exchange**: DES session keys encrypted with RSA public keys
3. **Authentication**: Login with username/password
4. **Integrity**: SHA-256 hash ensures data hasn't been modified
5. **Non-repudiation**: Digital signatures prove the sender's identity
6. **Key Rotation**: RSA keys are periodically regenerated (default: every 5 minutes)
7. **Encrypted Storage**: Images stored DES-encrypted on the server

---

## Synchronization Tools

### Threading (`threading` module)

- **Server**: Each client connection runs in its own thread
- **Client**: Background receive thread for incoming messages
- **Key Rotation**: Dedicated daemon thread on the server
- **Image Encryption**: Background threads for CPU-intensive crypto operations

### Thread Safety

- `threading.Lock` (`clients_lock`) protects the shared `connected_clients` dictionary
- SQLite uses WAL (Write-Ahead Logging) mode for concurrent access
- Tkinter GUI updates are scheduled via `root.after()` to run on the main thread

---

## Database Management System Tools

### SQLite3 (Built-in Python)

**File**: `database.py`

**Tables**:

| Table | Purpose |
|-------|---------|
| `users` | User accounts, RSA keys, online status |
| `messages` | Chat message history |
| `images` | Encrypted image metadata |
| `admin_logs` | Server event logs for admin monitoring |
| `session_keys` | Encrypted DES session keys between user pairs |

**Schema**:
```sql
users:        id, username, password, public_key_e, public_key_n,
              private_key_d, private_key_n, is_online, created_at

messages:     id, sender, receiver, content, is_image, timestamp

images:       id, sender, receiver, filename, encrypted_key, signature, timestamp

admin_logs:   id, event, details, timestamp

session_keys: id, user1, user2, encrypted_key_for_user2, timestamp
```

---

## Web-Server Tools

This application does **not** use a web server (no Flask, no HTTP). Instead, it uses:

- **Raw TCP sockets** (`socket` module) for network communication
- **Custom JSON protocol** with length-prefixed framing
- **Tkinter** for the graphical user interface

This design choice was made to minimize external dependencies and keep the codebase simple. The entire application runs on Python's standard library — **zero pip installs required**.

---

## How to Run

### Prerequisites
- Python 3.8 or newer
- No external packages needed (everything is built-in)

### 1. Start the Server

On the server machine (or any machine on the network):

```bash
cd Online-Image-Encryption-Application
python3 server.py
```

The server will display its IP address and port. Note this for the clients.

### 2. Start Clients (on separate computers)

On each client computer, copy the project folder and run:

```bash
cd Online-Image-Encryption-Application
python3 client.py
```

1. Enter the server's IP address and port
2. Register a new account (first time) or Login
3. Select a user from the online list to start chatting
4. Use "Send" for text messages, "Send Image" for encrypted images

### 3. Start Admin Monitor (optional)

```bash
cd Online-Image-Encryption-Application
python3 admin.py
```

Enter the server's IP and port to connect. Admin credentials are in `config.py`.

### Configuration

Edit `config.py` to change:
- `SERVER_PORT` — default: 9999
- `RSA_KEY_BITS` — default: 512
- `KEY_ROTATION_INTERVAL` — default: 300 seconds (5 minutes)
- `ADMIN_USERNAME` / `ADMIN_PASSWORD` — default: admin/admin123

---

## File Structure

```
Online-Image-Encryption-Application/
├── server.py              # TCP socket server (main entry point)
├── client.py              # Tkinter GUI client
├── admin.py               # Sysadmin monitoring client
├── config.py              # Configuration constants
├── database.py            # SQLite database module
├── crypto_utils/          # Custom cryptographic implementations
│   ├── __init__.py        # Package init
│   ├── des.py             # DES encryption (from scratch)
│   ├── rsa.py             # RSA encryption (from scratch)
│   ├── sha256.py          # SHA-256 hash (from scratch)
│   └── signature.py       # Digital signatures (SHA-256 + RSA)
├── encrypted_images/      # DES-encrypted image storage (server)
├── received_images/       # Decrypted images (client, created at runtime)
├── DOCUMENTATION.md       # This file
└── iea_database.db        # SQLite database (created at runtime)
```
