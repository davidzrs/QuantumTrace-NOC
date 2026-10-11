package com.acme.vault;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;

/**
 * Source of personal-samples/binaries/LegacyVault.class and legacy-vault.jar: classical and
 * post-quantum JCA calls for the bytecode scanner (tests/test_binary_scanner.py). See
 * ../../../../README.md to rebuild. Never run, only compiled.
 */
public class LegacyVault {

    public Cipher legacyCipher() throws Exception {
        return Cipher.getInstance("DESede/ECB/PKCS5Padding");
    }

    public KeyPairGenerator signingKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        return kpg;
    }

    public Signature receiptSigner() throws Exception {
        return Signature.getInstance("SHA1withRSA");
    }

    public byte[] fingerprint(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data);
    }

    public Mac webhookMac() throws Exception {
        return Mac.getInstance("HmacSHA256");
    }

    public SecretKeyFactory passwordKdf() throws Exception {
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    }

    public Cipher bouncyGcm() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding", "BC");
    }

    public KeyPairGenerator quantumSafeKeys() throws Exception {
        return KeyPairGenerator.getInstance("ML-DSA");
    }

    public KEM quantumSafeKem() throws Exception {
        return KEM.getInstance("ML-KEM");
    }

    public int sessionToken() {
        return new Random().nextInt();
    }
}
