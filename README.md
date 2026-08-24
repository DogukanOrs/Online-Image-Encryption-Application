# Online Image Encryption Application (IEA)

A client-server application where users can send each other images and chat messages over a network, with everything encrypted end to end. The interesting part is that none of the cryptography comes from a library — DES, RSA and SHA-256 are all implemented from scratch in plain Python.

Built as a network security course project.

**This is educational code.** It uses DES and 512-bit RSA, both of which are far too weak for anything real. Details are in the [Security notes](#security-notes) at the bottom.

## What it does

- Users register and log in through a Tkinter desktop client
- Any user can send a chat message or an image to any other online user
- Images are encrypted before they leave the sender's machine and are only decrypted on the recipient's machine
- Every image is digitally signed, so the recipient can verify who actually sent it
- The server stores images in encrypted form and never sees the plaintext
- An admin panel lets a sysadmin see stats, logs and message metadata

## How the encryption works

The system uses hybrid encryption, which is how TLS and PGP handle the same problem.

RSA is good at solving key distribution but it is slow and can only encrypt data smaller than its modulus — you cannot push a 2 MB photo through it. DES is fast enough for bulk data but both sides need the same key beforehand, which is exactly the problem you were trying to solve.

So the two are combined. When Alice sends Bob an image:

1. Alice generates a random DES session key for this transfer
2. She encrypts the image with DES using that key
3. She encrypts the session key itself with Bob's RSA public key — it is only 8 bytes, so RSA handles it easily
4. She hashes the image with SHA-256 and signs the hash with her own RSA private key
5. All of it goes to the server, which routes it to Bob without being able to read anything

On the other end Bob decrypts the session key with his RSA private key, uses it to decrypt the image, and checks the signature against Alice's public key to confirm the image really came from her and was not modified in transit.

The server also rotates RSA key pairs every five minutes in a background thread, so a compromised key has a limited useful lifetime.

### The three primitives

**DES** — 64-bit blocks, 56-bit effective key, 16-round Feistel network with the standard permutation tables and S-boxes. ECB mode with PKCS#5 padding.

**RSA** — 512-bit keys with e = 65537. Key generation uses Miller-Rabin for primality testing and the Extended Euclidean Algorithm to compute the private exponent.

**SHA-256** — produces the 256-bit digest that gets signed. Signing the hash rather than the whole message is what makes signatures practical for large files.

## Project structure

| File / folder | What it is |
|---|---|
| `server.py` | Multi-threaded TCP server. Handles auth, routing, key distribution, key rotation. |
| `client.py` | Tkinter GUI client. |
| `admin.py` | Admin panel — stats, logs, message metadata. |
| `crypto_utils/` | DES, RSA, SHA-256 and digital signature implementations. |
| `database.py` | SQLite schema and queries. |
| `config.py` | Host, port, key sizes, rotation interval, paths. |
| `encrypted_images/` | Where the server keeps images, still encrypted. |

## The protocol

Messages go over plain TCP sockets. Each one is a 4-byte big-endian length prefix followed by a JSON payload, so the receiver always knows how many bytes to read before parsing. Binary data such as image bytes and ciphertext is base64-encoded to survive the JSON encoding.

There are fourteen message types covering registration, login, listing users, fetching public keys, chat, image transfer, session key exchange and the admin functions.

## Running it

Python 3 is all you need. There are no dependencies to install — everything is standard library, including the Tkinter GUI.

Start the server first:

```bash
python server.py
```

It listens on port 9999 by default and creates the SQLite database and the image directory on first run.

Then open a client in another terminal:

```bash
python client.py
```

Register a user, then do the same in a third terminal for a second user. Once both are logged in you can send messages and images between them.

For the admin panel:

```bash
python admin.py
```

Default credentials are set in `config.py`. Change them before running this anywhere other than your own machine.

To run clients on different machines, point them at the server's IP address and make sure port 9999 is open.

## Security notes

Writing the primitives yourself is a good way to understand them and a bad way to secure anything. The known problems, roughly in order of severity:

**512-bit RSA is breakable.** It was factored publicly in 1999 and can be broken on ordinary hardware today. Real deployments use 2048 bits minimum, or elliptic curve keys.

**DES is obsolete.** The 56-bit key space fell to dedicated hardware in 1998. NIST withdrew the standard in 2005.

**ECB mode leaks structure.** Each block is encrypted independently with no IV or chaining, so identical plaintext blocks produce identical ciphertext. On images this is especially bad — large flat regions of the same colour stay visible in the ciphertext as a recognisable pattern. This is the well-known "ECB penguin" problem. CBC or CTR mode would fix it.

**Hand-rolled crypto has side channels.** Even if the algorithms are mathematically correct, a from-scratch implementation is unlikely to be constant-time, which opens the door to timing attacks. This is the main reason production systems use audited libraries.

**Default admin credentials are hardcoded** in `config.py`.

**No transport security.** The socket carries JSON in the clear. The message payloads are encrypted, but metadata — who is talking to whom, how often, message sizes — is fully visible to anyone on the network. TLS underneath would cover that.

A production version of this would use AES-256-GCM instead of DES, RSA-2048 or X25519 for key exchange, and TLS for the transport, all from a maintained library such as `cryptography`.



Doğukan Bilal Örs — [github.com/DogukanOrs](https://github.com/DogukanOrs)
