# Sample sources

What builds the files in `personal-samples/` (repository root). Kept here, not there, so a scan
of `personal-samples/` only sees the file types it demonstrates.

Certificates and public keys (`personal-samples/certificates`):

```sh
cd backend && uv run python tests/sample_sources/regenerate_certs.py
```

Java bytecode (JDK 21 or later), from `backend/tests/sample_sources`:

```sh
javac --release 21 -d build java/com/acme/vault/LegacyVault.java
cp build/com/acme/vault/LegacyVault.class ../../../personal-samples/binaries/
# The jar also carries META-INF/maven/<group>/<artifact>/pom.properties for com.acme:legacy-vault
# 2.3.0 and, as a shaded fat jar would, org.bouncycastle:bcprov-jdk18on 1.78.1 (properties only,
# no BouncyCastle classes inside).
jar --create --file ../../../personal-samples/binaries/legacy-vault.jar -C build com -C build META-INF
```

Go executable, built in a container so no local Go toolchain is needed (`x/crypto` v0.36.0 is
the last release that builds with Go 1.24):

```sh
docker run --rm -v "$PWD/go:/src" -w /src golang:1.24-alpine \
  sh -c "CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o legacy-agent ."
mv go/legacy-agent ../../../personal-samples/binaries/
```
