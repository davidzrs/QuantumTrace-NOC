---
name: add-scanner
description: Implement or extend a QuantumTrace ingestion scanner (source code, pcap/TLS/SSH, cloud config, live TLS probe, binaries). Use when adding detection for a new input type, language, protocol or API pattern.
---

# Add or implement a scanner

Scanners turn raw inputs into `CryptoAsset`s. They **never** decide risk; the classifier does that.

## 1. Write the golden test first
- Pick real files from `samples/` and write the assertions in `backend/tests/test_<vector>_scanner.py`.
  Assert on `(tier, classification.name, asset.usage)` with `tests.conftest.summarise()`, and on
  evidence (file, line or flow).
- Existing suites to copy from: `test_cloud_scanner.py`, `test_code_scanner.py`,
  `test_pcap_scanner.py`. Mark a new case `xfail(strict=True)` only while it's in progress.

## 2. Implement the Scanner protocol (`scanners/base.py`)
```python
class MyScanner:
    name = "my-vector"            # stable id, shows in ScanResult.scanners
    source_type = SourceType.CODE # cloud | code | network
    def accepts(self, path: Path) -> bool: ...          # cheap: extension / magic bytes
    def scan(self, paths: Sequence[Path]) -> Iterable[CryptoAsset]: ...
```
- `scan` receives **all** accepted files together, so cross-file correlation is possible (see
  how `cloud/aws.py` gives ACM certs the exposure of their ELB listeners).
- Register it in `scanners/__init__.py`.

## 3. Emit good assets
- `algorithm`: an alias that `rules/algorithms.yaml` resolves (check with
  `default_classifier().lookup(alias, key_size)`). If none exists, add a rule using the
  `crypto-classification` skill, not a special case in the scanner.
- `key_size`: when known. It selects rules such as `RSA-1024` or `AES-128` vs `AES-256`.
- `usage`: what the primitive does there (`SIGN_VERIFY`, `tls-key-exchange`, `hash`, ...).
  Add a human label for any new usage in `frontend/apps/web/src/lib/format.ts`.
- `exposure`: `internet` only when you know it is reachable from outside.
- `observation`: how the input proves it (`negotiated`, `configured`, `in-code`, `permitted`,
  `offered`). `variant`: the precise form (AES-128-GCM, x25519, RSA-2048).
- Yield `ScanNote(scanner=..., message=...)` for anything you can't see. Reviewers reward a
  scanner that states its blind spots.
- `flags`: misuse that is independent of quantum risk, e.g. `ecb-mode`, `no-forward-secrecy`,
  `weak-rng`, `hardcoded-key`, `rotation-disabled`.
- `evidence`: `location` is the file, ARN or flow, plus `line`, `snippet`, and `context` for
  anything the UI should show. Keep paths as given; the API relativises them.
- Dedupe within a logical unit (one listener, one function). Don't dedupe across units: each
  occurrence matters for the CBOM.

## Vector notes
- **Code** (`scanners/code/`): add a language by writing `<lang>_lang.scan(src: SourceFile)` and
  registering its extension in `source.LANGUAGES`. Use `src.emit(pos, observed, alias, usage, ...)`,
  which handles line numbers and per-file dedupe. Use `src.constant()` / `src.int_value()` /
  `src.symmetric_key_hint()` to resolve sizes. Java `Signature.getInstance("SHA1withRSA")` yields
  RSA **and** SHA-1. Hand-rolled crypto needs structural heuristics; see `go_lang._hand_rolled_kdf`.
- **PCAP** (`scanners/network/`): `flows.read_flows` reassembles TCP (the SYN decides the
  server). `tls.py` parses hellos and ServerKeyExchange from the stream and skips any cleartext
  preamble (STARTTLS, SSLRequest). `ssh.py` parses KEXINIT and negotiates per RFC 4253. Map new
  IANA ids in `rules/tls.py` (`CIPHER_SUITES`, `NAMED_GROUPS`). Evidence context carries
  `server`, `server_port`, `service` and `sni`.
- **Live TLS probe** (`scanners/network/probe.py`): hand-built ClientHellos (one offering
  X25519MLKEM768, one TLS 1.2-only) fed through the pcap `tls_assets`, plus an `ssl` handshake
  for the leaf certificate. `resolve_public` is the SSRF guard; tests use local `ssl` servers.

## 4. Verify
```sh
cd backend && uv run pytest tests/test_<vector>_scanner.py -q
uv run quantumtrace scan ../samples/<dir>          # eyeball the table
make lint
```
Check that `score.counts.unknown` stays at 0 on the samples. Every unknown is an unclassified
primitive, which costs accuracy points.
