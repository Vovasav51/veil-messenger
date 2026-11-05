package io.veil.messenger.core;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/**
 * Single AES-GCM encrypted vault file with transactional mutation.
 *
 * <p>Every mutation happens on a deep copy of the state. The copy is serialized,
 * encrypted and durably replaced on disk; only then does it become the new
 * in-memory state. Any exception (mutation or save) discards the copy, so the
 * caller's ratchet, outbox, chat rows and dedup ids all roll back together.
 *
 * <p>A corrupt or unreachable vault is never silently reset: the app shows a
 * failure screen instead of losing the identity.
 */
public final class Vault {

    /** Encryption backend, so unit tests can run without Android Keystore. */
    public interface VaultCipher {
        /** Returns IV || ciphertext. */
        byte[] seal(byte[] plaintext) throws Exception;

        byte[] open(byte[] sealed) throws Exception;
    }

    public interface Tx<T> {
        T run(VaultState state) throws Exception;
    }

    private static final byte[] MAGIC = {'V', 'E', 'I', 'L', 'V', 'L', 'T', '1'};
    private static final int MAX_PLAINTEXT_BYTES = 8 * 1024 * 1024;
    private static final int MAX_FILE_BYTES = MAX_PLAINTEXT_BYTES + 64 * 1024;

    private final File directory;
    private final File file;
    private final File tempFile;
    private final VaultCipher cipher;

    private VaultState state = VaultState.empty();
    private boolean loaded;

    public Vault(File directory, VaultCipher cipher) {
        this.directory = directory;
        this.file = new File(directory, "state.veil");
        this.tempFile = new File(directory, "state.veil.tmp");
        this.cipher = cipher;
    }

    public synchronized boolean isLoaded() {
        return loaded;
    }

    /** Read-only view for the UI. Callers must not mutate it. */
    public synchronized VaultState snapshot() {
        return state;
    }

    public synchronized void load() throws VaultException {
        if (loaded) {
            return;
        }
        if (!file.exists()) {
            state = VaultState.empty();
            loaded = true;
            return;
        }
        final byte[] raw;
        try {
            raw = readBounded(file);
        } catch (IOException e) {
            throw new VaultException(VaultException.Kind.IO, "cannot read vault", e);
        }
        if (raw.length < MAGIC.length + 12 + 16) {
            throw new VaultException(VaultException.Kind.CORRUPT, "vault file is truncated");
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (raw[i] != MAGIC[i]) {
                throw new VaultException(VaultException.Kind.CORRUPT, "vault file has bad header");
            }
        }
        byte[] sealed = new byte[raw.length - MAGIC.length];
        System.arraycopy(raw, MAGIC.length, sealed, 0, sealed.length);

        final byte[] plaintext;
        try {
            plaintext = cipher.open(sealed);
        } catch (Exception e) {
            // Never treat a decryption failure as "empty state": that would
            // destroy the only copy of the identity.
            throw new VaultException(VaultException.Kind.CORRUPT,
                    "cannot decrypt vault", e);
        }
        if (plaintext.length > MAX_PLAINTEXT_BYTES) {
            throw new VaultException(VaultException.Kind.CORRUPT, "vault is too large");
        }
        try {
            JSONObject json = new JSONObject(Codec.fromUtf8(plaintext));
            state = VaultState.fromJson(json);
        } catch (JSONException e) {
            throw new VaultException(VaultException.Kind.CORRUPT, "vault JSON is invalid", e);
        }
        loaded = true;
    }

    /**
     * Runs {@code body} against a deep copy and commits atomically.
     *
     * @throws VaultException with kind MUTATION when the body threw (cause is the
     *                        original exception, e.g. CryptoException), or IO /
     *                        TOO_LARGE when the write failed. In both cases the
     *                        previous state remains fully intact.
     */
    public synchronized <T> T transaction(Tx<T> body) throws VaultException {
        if (!loaded) {
            throw new VaultException(VaultException.Kind.IO, "vault is not loaded");
        }
        VaultState candidate = state.copy();
        final T result;
        try {
            result = body.run(candidate);
        } catch (VaultException e) {
            throw e;
        } catch (Exception e) {
            throw new VaultException(VaultException.Kind.MUTATION, "mutation failed", e);
        }
        persist(candidate);
        state = candidate;
        return result;
    }

    private void persist(VaultState candidate) throws VaultException {
        final byte[] plaintext;
        try {
            plaintext = Codec.utf8(candidate.toJson().toString());
        } catch (JSONException e) {
            throw new VaultException(VaultException.Kind.MUTATION, "state is not serializable", e);
        }
        if (plaintext.length > MAX_PLAINTEXT_BYTES) {
            throw new VaultException(VaultException.Kind.TOO_LARGE, "state is too large");
        }
        final byte[] sealed;
        try {
            sealed = cipher.seal(plaintext);
        } catch (Exception e) {
            throw new VaultException(VaultException.Kind.IO, "cannot encrypt vault", e);
        }
        if (!directory.exists() && !directory.mkdirs() && !directory.exists()) {
            throw new VaultException(VaultException.Kind.IO, "cannot create vault directory");
        }
        try (FileOutputStream out = new FileOutputStream(tempFile)) {
            out.write(MAGIC);
            out.write(sealed);
            out.flush();
            out.getFD().sync();
        } catch (IOException e) {
            tempFile.delete();
            throw new VaultException(VaultException.Kind.IO, "cannot write vault", e);
        }
        try {
            Files.move(tempFile.toPath(), file.toPath(),
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception atomicFailure) {
            if (!tempFile.renameTo(file)) {
                tempFile.delete();
                throw new VaultException(VaultException.Kind.IO,
                        "cannot replace vault file", atomicFailure);
            }
        }
    }

    private static byte[] readBounded(File source) throws IOException {
        long length = source.length();
        if (length > MAX_FILE_BYTES) {
            throw new IOException("vault file is too large");
        }
        try (InputStream in = new FileInputStream(source)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream((int) Math.max(64, length));
            byte[] buffer = new byte[8192];
            int total = 0;
            int read;
            while ((read = in.read(buffer)) != -1) {
                total += read;
                if (total > MAX_FILE_BYTES) {
                    throw new IOException("vault file is too large");
                }
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        }
    }
}
