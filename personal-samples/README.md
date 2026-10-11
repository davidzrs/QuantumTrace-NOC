# Personal samples

Our own inputs for the file types QuantumTrace reads beyond the organisers' `samples/`:
dependency manifests, certificates and keys, server configurations and compiled binaries. They
cover the brief's "configuration files, or binary artifacts" and the CBOM's "cryptographic
libraries". `samples/` stays as the organisers shipped it; this folder is ours.

| Folder | Files | What the report shows |
| --- | --- | --- |
| `dependency-manifests/` | `requirements.txt`, `pyproject.toml`, `go.mod`, `pom.xml`, `package.json` | Cryptographic libraries with version and purl, e.g. PyCrypto 2.6.1 (unmaintained), BouncyCastle 1.78.1, `@noble/post-quantum`. Non-crypto packages are left out. In the CBOM each is a `library` component. |
| `certificates/` | expired RSA-1024 certificate, P-256 leaf and its P-384 CA, the leaf as DER, a CSR, an RSA-3072 public key, OpenSSH public keys | Key, signature and digest of each certificate; the expired one flagged; the CA told apart from the leaf. |
| `server-configs/` | `ssh-legacy`, `ssh-post-quantum`, `ssh-defaults` (`sshd_config`); `nginx/legacy.conf`, `nginx/nginx.conf`; `apache/ssl.conf` | DH group 1, SHA-1, CBC and 3DES allowed by the legacy server; ML-KEM key exchange on the post-quantum one; TLS 1.0 and static RSA in the legacy nginx; hybrid `X25519MLKEM768` in the modern one. Each finding points at the config line. |
| `binaries/` | `LegacyVault.class`, `legacy-vault.jar`, `legacy-agent` (stripped Linux Go executable) | RSA-1024, 3DES-ECB, MD5, ML-DSA and ML-KEM read from Java bytecode at their source lines; the Go version, `golang.org/x/crypto` and the crypto linked into the Go binary. |

## Scan them

```sh
cd backend && uv run quantumtrace scan ../personal-samples
uv run quantumtrace scan ../personal-samples -f cbom -o personal.cdx.json   # CBOM with libraries
```

In the web app, upload the folder. The browser recognises every sample here except `legacy-agent`,
which has no extension: zip `binaries/` (or the whole folder) to include it.

No private key is kept here. The tests create them in a temporary folder, since a committed key
would be flagged by secret scanners. To show "private key in file" live, generate one in a
scratch folder (`ssh-keygen -t ed25519 -f id_ed25519 -N ""`; key files are recognised by name or
by `.key`/`.pem`) and scan it.

## Where they come from

The certificates are made by `backend/tests/sample_sources/regenerate_certs.py`; the binaries are
compiled from the Java and Go sources in the same folder (see its README to rebuild). The golden
tests in `backend/tests/test_*_scanner.py` assert on every file here, so a change to one shows up
as a test diff.
