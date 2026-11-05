package io.veil.messenger.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import io.veil.messenger.core.model.Account;
import io.veil.messenger.core.model.ChatMessage;
import io.veil.messenger.core.model.Contact;
import io.veil.messenger.core.model.OutgoingEnvelope;
import io.veil.messenger.crypto.CryptoState;
import io.veil.messenger.crypto.SignalEngine;

/**
 * Vault transaction and serialization tests. The cipher is a test-only AES-GCM
 * implementation with an in-memory key: Android Keystore is unavailable on the
 * JVM, but the storage contract (all-or-nothing commit, no wipe on corruption)
 * is the same.
 */
public class VaultTest {

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    private static final class TestCipher implements Vault.VaultCipher {
        private final SecretKey key;
        private int seals;
        private int failAfter = Integer.MAX_VALUE;

        TestCipher() throws Exception {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(256);
            key = generator.generateKey();
        }

        @Override
        public byte[] seal(byte[] plaintext) throws Exception {
            if (seals++ >= failAfter) {
                throw new java.io.IOException("simulated write failure");
            }
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipher.updateAAD("test".getBytes("UTF-8"));
            byte[] ct = cipher.doFinal(plaintext);
            byte[] iv = cipher.getIV();
            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            return out;
        }

        @Override
        public byte[] open(byte[] sealed) throws Exception {
            byte[] iv = Arrays.copyOfRange(sealed, 0, 12);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            cipher.updateAAD("test".getBytes("UTF-8"));
            return cipher.doFinal(sealed, 12, sealed.length - 12);
        }
    }

    @Test
    public void emptyVaultStartsEmptyAndPersistsAccounts() throws Exception {
        File dir = folder.newFolder("vault");
        TestCipher cipher = new TestCipher();
        Vault vault = new Vault(dir, cipher);
        vault.load();
        org.junit.Assert.assertNull(vault.snapshot().account);

        vault.transaction(state -> {
            state.account = new Account("0192f4b3-1c2d-7a10-9d21-0f6c3b1e4a01",
                    "alice", "token", "https://relay.test/");
            state.messages.add(new ChatMessage("m1", "peer", "hi", true,
                    1700000000000L, ChatMessage.STATUS_QUEUED));
            return null;
        });

        Vault reloaded = new Vault(dir, cipher);
        reloaded.load();
        assertNotNull(reloaded.snapshot().account);
        assertEquals("alice", reloaded.snapshot().account.handle);
        assertEquals(1, reloaded.snapshot().messages.size());
        assertTrue(new File(dir, "state.veil").exists());
    }

    @Test
    public void failedMutationRollsBackEverything() throws Exception {
        File dir = folder.newFolder("rollback");
        TestCipher cipher = new TestCipher();
        Vault vault = new Vault(dir, cipher);
        vault.load();

        final CryptoState crypto = new CryptoState();
        SignalEngine.ensureIdentity(crypto, 5);
        final String originalIdentity = crypto.identityKeyPair;
        final String originalOutboxId = "0192f4b3-1c2d-7a10-9d21-0f6c3b1e4a99";

        vault.transaction(state -> {
            state.account = new Account("0192f4b3-1c2d-7a10-9d21-0f6c3b1e4a01",
                    "alice", "token", "https://relay.test/");
            state.crypto = crypto;
            state.outbox.add(new OutgoingEnvelope(originalOutboxId, "peer", 1, 3, "AAAA"));
            state.messages.add(new ChatMessage(originalOutboxId, "peer", "queued", true,
                    1700000000000L, ChatMessage.STATUS_QUEUED));
            return null;
        });

        try {
            vault.transaction(state -> {
                state.account = null;
                state.crypto.identityKeyPair = null;
                state.outbox.clear();
                state.messages.clear();
                throw new IllegalStateException("mutation failed after partial changes");
            });
            fail("transaction must propagate the failure");
        } catch (VaultException expected) {
            assertEquals(VaultException.Kind.MUTATION, expected.kind);
        }

        VaultState after = vault.snapshot();
        assertNotNull("account must survive a rolled back mutation", after.account);
        assertEquals("alice", after.account.handle);
        assertEquals(originalIdentity, after.crypto.identityKeyPair);
        assertEquals(1, after.outbox.size());
        assertEquals(originalOutboxId, after.outbox.get(0).id);
        assertEquals(1, after.messages.size());

        // The disk copy is unchanged too.
        Vault reloaded = new Vault(dir, cipher);
        reloaded.load();
        assertEquals("alice", reloaded.snapshot().account.handle);
        assertEquals(originalIdentity, reloaded.snapshot().crypto.identityKeyPair);
    }

    @Test
    public void saveFailureRollsBackAndKeepsDiskState() throws Exception {
        File dir = folder.newFolder("savefail");
        TestCipher cipher = new TestCipher();
        Vault vault = new Vault(dir, cipher);
        vault.load();
        vault.transaction(state -> {
            state.account = new Account("0192f4b3-1c2d-7a10-9d21-0f6c3b1e4a01",
                    "alice", "token", "https://relay.test/");
            return null;
        });

        cipher.failAfter = cipher.seals; // every following seal fails
        try {
            vault.transaction(state -> {
                state.account = new Account("0192f4b3-1c2d-7a10-9d21-0f6c3b1e4a02",
                        "mallory", "token", "https://relay.test/");
                return null;
            });
            fail("save failure must surface");
        } catch (VaultException expected) {
            assertEquals(VaultException.Kind.IO, expected.kind);
        }
        assertEquals("alice", vault.snapshot().account.handle);

        Vault reloaded = new Vault(dir, cipher);
        reloaded.load();
        assertEquals("alice", reloaded.snapshot().account.handle);
    }

    @Test
    public void corruptVaultThrowsInsteadOfWiping() throws Exception {
        File dir = folder.newFolder("corrupt");
        TestCipher cipher = new TestCipher();
        Vault vault = new Vault(dir, cipher);
        vault.load();
        vault.transaction(state -> {
            state.account = new Account("0192f4b3-1c2d-7a10-9d21-0f6c3b1e4a01",
                    "alice", "token", "https://relay.test/");
            return null;
        });

        File file = new File(dir, "state.veil");
        byte[] raw = java.nio.file.Files.readAllBytes(file.toPath());
        raw[raw.length - 5] ^= 0x7F;
        java.nio.file.Files.write(file.toPath(), raw);

        Vault broken = new Vault(dir, cipher);
        try {
            broken.load();
            fail("corrupt vault must not load as empty state");
        } catch (VaultException expected) {
            assertEquals(VaultException.Kind.CORRUPT, expected.kind);
        }
        assertTrue("the file must not be deleted", file.exists());
    }

    @Test
    public void stateRoundTripKeepsCryptoAndOrder() throws Exception {
        VaultState state = new VaultState();
        state.account = new Account("0192f4b3-1c2d-7a10-9d21-0f6c3b1e4a01",
                "alice", "token", "https://relay.test/");
        state.crypto = new CryptoState();
        SignalEngine.ensureIdentity(state.crypto, 3);
        state.contacts.add(new Contact("0192f4b3-1c2d-7a10-9d21-0f6c3b1e4a02",
                "bob", "AAAA", true));
        state.messages.add(new ChatMessage("m1", "peer", "перше", true, 1L, "sent"));
        state.messages.add(new ChatMessage("m2", "peer", "друге", false, 2L, "received"));
        state.markProcessed("env1");

        VaultState copy = state.copy();
        assertEquals(2, copy.messages.size());
        assertEquals("перше", copy.messages.get(0).text);
        assertEquals("друге", copy.messages.get(1).text);
        assertEquals(state.crypto.identityKeyPair, copy.crypto.identityKeyPair);
        assertTrue(copy.isProcessed("env1"));
        assertTrue(copy.contacts.get(0).verified);

        // Mutating the copy must not touch the original.
        copy.messages.clear();
        assertEquals(2, state.messages.size());
    }

    @Test
    public void dedupRingIsBounded() throws Exception {
        VaultState state = new VaultState();
        for (int i = 0; i < VaultState.MAX_PROCESSED_IDS + 25; i++) {
            state.markProcessed(String.format(java.util.Locale.ROOT,
                    "0192f4b3-1c2d-7a10-9d21-%012d", i));
        }
        assertEquals(VaultState.MAX_PROCESSED_IDS, state.processedEnvelopeIds.size());
        assertTrue(state.isProcessed(String.format(java.util.Locale.ROOT,
                "0192f4b3-1c2d-7a10-9d21-%012d", VaultState.MAX_PROCESSED_IDS + 24)));
    }
}
