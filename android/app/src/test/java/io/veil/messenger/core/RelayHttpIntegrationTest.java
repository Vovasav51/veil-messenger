package io.veil.messenger.core;

import static org.junit.Assert.*;

import io.veil.messenger.core.model.Account;
import io.veil.messenger.core.model.Contact;
import io.veil.messenger.core.model.Envelope;
import io.veil.messenger.core.model.OutgoingEnvelope;
import io.veil.messenger.crypto.SignalEngine;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Real Android Java transport + real Signal JNI + actual Python HTTP/SQLite.
 * Runs on Linux JVM, not on an Android device; Android Keystore/UI are not tested.
 */
public class RelayHttpIntegrationTest {
    @Rule public TemporaryFolder folder = new TemporaryFolder();

    @Test public void encryptedOfflineDeliveryReplyAndRetryThroughRealRelay() throws Exception {
        File root = new File(System.getProperty("user.dir")).getCanonicalFile();
        while (root != null && !new File(root, "server/veil_relay").isDirectory()) {
            root = root.getParentFile();
        }
        assertNotNull("Run from the complete Veil repository (server source required)", root);
        int port;
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            port = socket.getLocalPort();
        }
        File database = new File(folder.newFolder("relay"), "relay.sqlite3");
        ProcessBuilder builder = new ProcessBuilder("python3", "-m", "veil_relay",
                "--host", "127.0.0.1", "--port", Integer.toString(port),
                "--db", database.getAbsolutePath());
        builder.directory(new File(root, "server"));
        builder.environment().remove("VEIL_INVITE_CODE");
        builder.redirectErrorStream(true);
        builder.redirectOutput(folder.newFile("relay-process.log"));
        Process process = builder.start();
        try {
            URL url = new URL("http://127.0.0.1:" + port + "/");
            RelayClient registration = new RelayClient(url, null);
            Exception lastFailure = null;
            boolean ready = false;
            for (int i = 0; i < 80 && process.isAlive(); i++) {
                try {
                    ready = "ok".equals(registration.health().status);
                    if (ready) break;
                } catch (RelayException e) { lastFailure = e; }
                Thread.sleep(25);
            }
            if (!ready) throw new AssertionError("Local relay did not become ready", lastFailure);

            VaultState alice = VaultState.empty();
            VaultState bob = VaultState.empty();
            SignalEngine.ensureIdentity(alice.crypto, 100);
            SignalEngine.ensureIdentity(bob.crypto, 100);
            String aliceUid = Uuid7.create();
            String bobUid = Uuid7.create();
            RelayClient.RegisterResponse a = registration.register(aliceUid, "alice_http",
                    SignalEngine.buildBundle(alice.crypto, false));
            RelayClient.RegisterResponse b = registration.register(bobUid, "bob_http",
                    SignalEngine.buildBundle(bob.crypto, false));
            alice.account = new Account(a.uid, a.handle, a.token, url.toString());
            bob.account = new Account(b.uid, b.handle, b.token, url.toString());
            RelayClient aliceClient = new RelayClient(url, a.token);
            RelayClient bobClient = new RelayClient(url, b.token);
            RelayClient.DirectoryEntry bobEntry = aliceClient.directory("bob_http");
            RelayClient.DirectoryEntry aliceEntry = bobClient.directory("alice_http");
            alice.upsertContact(new Contact(b.uid, b.handle, bobEntry.identityKey, false));
            bob.upsertContact(new Contact(a.uid, a.handle, aliceEntry.identityKey, false));
            SignalEngine.pinIdentity(alice.crypto, b.uid, bobEntry.identityKey);
            SignalEngine.pinIdentity(bob.crypto, a.uid, aliceEntry.identityKey);
            assertEquals(SignalEngine.fingerprint(alice.crypto, a.uid, b.uid, bobEntry.identityKey),
                    SignalEngine.fingerprint(bob.crypto, b.uid, a.uid, aliceEntry.identityKey));

            String secret = "Veil_тест_наскрізного_шифрування_41A9";
            OutgoingEnvelope outgoing = SendQueue.enqueue(alice, b.uid, secret,
                    aliceClient.prekeys(b.uid));
            aliceClient.send(outgoing);
            aliceClient.send(outgoing); // lost HTTP response: exact ciphertext/id retry
            SendQueue.markSent(alice, outgoing.id);
            for (File file : database.getParentFile().listFiles()) {
                String raw = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
                assertFalse("Plaintext must not be in SQLite or WAL", raw.contains(secret));
            }

            List<Envelope> inbox = bobClient.fetchMessages();
            assertEquals(1, inbox.size());
            assertEquals(a.uid, inbox.get(0).senderUid);
            InboxProcessor.Result received = InboxProcessor.process(bob, inbox.get(0), b.uid);
            assertTrue(received.acknowledge);
            assertEquals(secret, received.message.text);
            assertTrue(InboxProcessor.process(bob, inbox.get(0), b.uid).duplicate);
            bobClient.acknowledge(Collections.singletonList(outgoing.id));
            assertTrue(bobClient.fetchMessages().isEmpty());
            aliceClient.send(outgoing); // tombstone retry after ACK must not redeliver
            assertTrue(bobClient.fetchMessages().isEmpty());

            OutgoingEnvelope reply = SendQueue.enqueue(bob, a.uid, "Відповідь через Signal", null);
            assertEquals(2, reply.messageType);
            bobClient.send(reply);
            List<Envelope> replyInbox = aliceClient.fetchMessages();
            assertEquals(1, replyInbox.size());
            assertEquals("Відповідь через Signal",
                    InboxProcessor.process(alice, replyInbox.get(0), a.uid).message.text);
            aliceClient.acknowledge(Collections.singletonList(reply.id));
            assertTrue(aliceClient.fetchMessages().isEmpty());
        } finally {
            process.destroy();
            if (!process.waitFor(3, TimeUnit.SECONDS)) process.destroyForcibly();
        }
    }
}
