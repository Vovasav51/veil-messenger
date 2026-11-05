package io.veil.messenger.core;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * AES-256-GCM vault cipher backed by a non-exportable Android Keystore key.
 *
 * <p>The key is generated on first launch with {@code RandomizedEncryptionRequired}
 * (the system supplies a fresh IV per operation) and can never be read out of
 * the keystore, so a copied vault file is useless without this device.
 */
public final class AndroidKeystoreCipher implements Vault.VaultCipher {

    private static final String KEY_ALIAS = "io.veil.messenger.vault.aes.v1";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_BYTES = 12;
    private static final byte[] AAD =
            "io.veil.messenger/vault/v1".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    private final SecretKey key;

    public AndroidKeystoreCipher() throws GeneralSecurityException, java.io.IOException {
        this.key = getOrCreateKey();
    }

    private static SecretKey getOrCreateKey() throws GeneralSecurityException, java.io.IOException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (keyStore.containsAlias(KEY_ALIAS)) {
            java.security.Key existing = keyStore.getKey(KEY_ALIAS, null);
            if (existing instanceof SecretKey) {
                return (SecretKey) existing;
            }
            throw new GeneralSecurityException("vault key has an unexpected type");
        }
        KeyGenerator generator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build());
        return generator.generateKey();
    }

    @Override
    public byte[] seal(byte[] plaintext) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipher.updateAAD(AAD);
        byte[] ciphertext = cipher.doFinal(plaintext);
        byte[] iv = cipher.getIV();
        if (iv == null || iv.length != IV_BYTES) {
            throw new GeneralSecurityException("unexpected GCM IV length");
        }
        byte[] output = new byte[IV_BYTES + ciphertext.length];
        System.arraycopy(iv, 0, output, 0, IV_BYTES);
        System.arraycopy(ciphertext, 0, output, IV_BYTES, ciphertext.length);
        return output;
    }

    @Override
    public byte[] open(byte[] sealed) throws GeneralSecurityException {
        if (sealed.length < IV_BYTES + GCM_TAG_BITS / 8) {
            throw new GeneralSecurityException("sealed vault is truncated");
        }
        byte[] iv = Arrays.copyOfRange(sealed, 0, IV_BYTES);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        cipher.updateAAD(AAD);
        return cipher.doFinal(sealed, IV_BYTES, sealed.length - IV_BYTES);
    }

    /** Only used to make the random-IV requirement explicit to readers/tests. */
    static byte[] randomIv() {
        byte[] iv = new byte[IV_BYTES];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
