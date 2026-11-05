package io.veil.messenger.core;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

import io.veil.messenger.BuildConfig;
import io.veil.messenger.R;
import io.veil.messenger.core.model.Account;
import io.veil.messenger.core.model.Contact;
import io.veil.messenger.core.model.Envelope;
import io.veil.messenger.core.model.OutgoingEnvelope;
import io.veil.messenger.core.model.PendingRegistration;
import io.veil.messenger.core.model.PublicBundle;
import io.veil.messenger.crypto.CryptoException;
import io.veil.messenger.crypto.SignalEngine;

/**
 * Application core: one worker thread owns the vault, the relay client and all
 * crypto state. UI code only reads immutable snapshots and posts operations;
 * every callback is delivered on the main thread.
 *
 * <p>No networking and no libsignal call ever happens on the main thread.
 */
public final class AppCore {

    public interface Listener {
        void onReady();

        void onStateChanged();

        void onFatal(String message);

        void onNotice(String message);
    }

    public interface Op {
        void onSuccess();

        void onFailure(String message);
    }

    public interface OpT<T> {
        void onSuccess(T value);

        void onFailure(String message);
    }

    private interface Task {
        void run() throws Exception;
    }

    private static final long POLL_INTERVAL_MS = 3_000L;
    private static final long POLL_MAX_BACKOFF_MS = 60_000L;

    private final Context appContext;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final ExecutorService worker = Executors.newSingleThreadExecutor(
            new ThreadFactory() {
                @Override
                public Thread newThread(Runnable runnable) {
                    Thread thread = new Thread(runnable, "veil-core");
                    thread.setDaemon(true);
                    return thread;
                }
            });
    private final AtomicBoolean syncInFlight = new AtomicBoolean(false);
    private final Runnable pollRunnable = new Runnable() {
        @Override
        public void run() {
            requestSync();
        }
    };

    private Vault vault;
    private RelayClient client;
    private volatile VaultState published = VaultState.empty();
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();
    private final AtomicBoolean started = new AtomicBoolean(false);
    private volatile boolean fatal;
    private volatile String fatalMessage = "";
    private volatile boolean foreground;
    private int foregroundActivities;
    private volatile boolean syncHalted;
    private long nextPollDelayMs = POLL_INTERVAL_MS;

    public AppCore(Context context) {
        this.appContext = context.getApplicationContext();
    }

    // --- lifecycle -----------------------------------------------------------

    /** Registers a UI listener and loads the vault exactly once. */
    public void start(Listener newListener) {
        if (newListener != null) {
            addListener(newListener);
        }
        if (!started.compareAndSet(false, true)) {
            if (newListener != null && vault != null) {
                newListener.onReady();
            }
            return;
        }
        worker.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    Vault created = new Vault(
                            new File(appContext.getFilesDir(), "vault"),
                            new AndroidKeystoreCipher());
                    created.load();
                    vault = created;
                    published = created.snapshot();
                    if (published.account != null) {
                        if (!published.crypto.hasIdentity()) {
                            throw new IllegalStateException("account protocol keys are missing");
                        }
                        client = new RelayClient(
                                UrlPolicy.parse(published.account.serverUrl, BuildConfig.DEBUG),
                                published.account.token);
                    }
                    mainHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            for (Listener current : listeners) {
                                current.onReady();
                                current.onStateChanged();
                            }
                            scheduleNext(0);
                        }
                    });
                } catch (Exception e) {
                    fatal = true;
                    fatalMessage = appContext.getString(R.string.fatal_body);
                    mainHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            for (Listener current : listeners) {
                                current.onFatal(fatalMessage);
                            }
                        }
                    });
                }
            }
        });
    }

    /** Called by every activity so a process restart never leaves the core idle. */
    public void ensureStarted() {
        start(null);
    }

    public void addListener(Listener newListener) {
        if (newListener != null && !listeners.contains(newListener)) {
            listeners.add(newListener);
        }
    }

    public void removeListener(Listener oldListener) {
        if (oldListener != null) {
            listeners.remove(oldListener);
        }
    }

    public boolean isReady() {
        return vault != null && !fatal;
    }

    public boolean isFatal() {
        return fatal;
    }

    public String fatalMessage() {
        return fatalMessage;
    }

    public VaultState state() {
        return published;
    }

    public boolean hasAccount() {
        return published.account != null;
    }

    /**
     * Foreground-only polling, reference-counted across activities so that
     * Main -> Chat navigation (start before stop) never disables the loop.
     */
    public void setForeground(final boolean value) {
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                if (value) {
                    foregroundActivities++;
                } else if (foregroundActivities > 0) {
                    foregroundActivities--;
                }
                foreground = foregroundActivities > 0;
                if (foreground) {
                    scheduleNext(0);
                } else {
                    mainHandler.removeCallbacks(pollRunnable);
                }
            }
        });
    }

    public void refreshNow() {
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                if (!foreground) {
                    return;
                }
                mainHandler.removeCallbacks(pollRunnable);
                requestSync();
            }
        });
    }

    private void requestSync() {
        if (fatal || syncHalted || vault == null || published.account == null) {
            return;
        }
        if (!syncInFlight.compareAndSet(false, true)) {
            return;
        }
        worker.execute(new Runnable() {
            @Override
            public void run() {
                boolean ok;
                try {
                    syncOnce();
                    ok = true;
                } catch (RelayException e) {
                    ok = false;
                    if (e.isAuthFailure()) {
                        haltSync();
                        notice(appContext.getString(R.string.err_unauthorized));
                    } else if (e.kind == RelayException.Kind.RATE_LIMITED) {
                        notice(appContext.getString(R.string.err_rate_limited));
                    }
                } catch (Exception e) {
                    ok = false;
                } finally {
                    syncInFlight.set(false);
                }
                if (ok) {
                    resetBackoff();
                } else {
                    increaseBackoff();
                }
                final long delay = nextPollDelayMs;
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        scheduleNext(delay);
                    }
                });
            }
        });
    }

    /** 401 means the token is gone for good: there is no account recovery. */
    private void haltSync() {
        syncHalted = true;
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                foreground = false;
                mainHandler.removeCallbacks(pollRunnable);
            }
        });
    }

    private void scheduleNext(long delay) {
        if (!foreground || fatal || syncHalted || vault == null || published.account == null) {
            return;
        }
        mainHandler.removeCallbacks(pollRunnable);
        mainHandler.postDelayed(pollRunnable, Math.max(0L, delay));
    }

    private void resetBackoff() {
        nextPollDelayMs = POLL_INTERVAL_MS;
    }

    private void increaseBackoff() {
        nextPollDelayMs = Math.min(nextPollDelayMs * 2, POLL_MAX_BACKOFF_MS);
    }

    // --- registration --------------------------------------------------------

    public void register(final String rawUrl, final String rawHandle, final Op callback) {
        submit(callback, new Task() {
            @Override
            public void run() throws Exception {
                final java.net.URL url;
                try {
                    url = UrlPolicy.parse(rawUrl, BuildConfig.DEBUG);
                } catch (UrlException e) {
                    throw new UiError(urlMessage(e));
                }
                final String handle;
                try {
                    handle = HandleRules.normalize(rawHandle);
                } catch (IllegalArgumentException e) {
                    throw new UiError(appContext.getString(R.string.err_handle));
                }

                PendingRegistration pending = published.pending;
                if (pending != null && !pending.serverUrl.equals(url.toString())) {
                    throw new UiError("Незавершена реєстрація прив'язана до іншого сервера. "
                            + "Вкажіть ту саму адресу релею.");
                }

                syncHalted = false;
                final PendingRegistration prepared = vault.transaction(new Vault.Tx<PendingRegistration>() {
                    @Override
                    public PendingRegistration run(VaultState state) throws Exception {
                        SignalEngine.ensureIdentity(state.crypto,
                                SignalEngine.INITIAL_ONE_TIME_PREKEYS);
                        PendingRegistration current = state.pending;
                        if (current == null) {
                            current = new PendingRegistration(Uuid7.create(), handle,
                                    url.toString(), System.currentTimeMillis());
                        } else {
                            current = current.withHandle(handle);
                        }
                        state.pending = current;
                        return current;
                    }
                });
                publish();

                // The bundle is derived from the state that was just persisted,
                // so a retry always re-sends identical key material.
                final PublicBundle bundle = SignalEngine.buildBundle(
                        published.crypto, false);
                final RelayClient registrationClient = new RelayClient(url, null);
                final RelayClient.RegisterResponse response;
                try {
                    response = registrationClient.register(prepared.uid, prepared.handle, bundle);
                } catch (RelayException e) {
                    if (e.kind == RelayException.Kind.SERVER && e.status == 409) {
                        String detail = e.detail.toLowerCase(java.util.Locale.ROOT);
                        if (detail.contains("handle")) {
                            throw new UiError(appContext.getString(R.string.err_handle_taken));
                        }
                        throw new UiError("UID цього пристрою вже зареєстрований на сервері. "
                                + "Токен відновити неможливо: акаунт не має відновлення.");
                    }
                    if (e.isUncertain()) {
                        throw new UiError(appContext.getString(R.string.err_registration_pending));
                    }
                    throw e;
                }

                vault.transaction(new Vault.Tx<Void>() {
                    @Override
                    public Void run(VaultState state) {
                        state.account = new Account(response.uid, response.handle,
                                response.token, url.toString());
                        state.pending = null;
                        state.crypto.lastUploadedPreKeyId = maxPreKeyId(state);
                        return null;
                    }
                });
                client = new RelayClient(url, response.token);
                publish();
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        scheduleNext(0);
                    }
                });
            }
        });
    }

    // --- contacts ------------------------------------------------------------

    /** Exact directory lookup; nothing is persisted until the user saves. */
    public void lookupContact(final String rawHandle, final OpT<ContactInfo> callback) {
        submit(new Task() {
            @Override
            public void run() throws Exception {
                final Account account = requireAccount();
                final String handle;
                try {
                    handle = HandleRules.normalize(rawHandle);
                } catch (IllegalArgumentException e) {
                    throw new UiError(appContext.getString(R.string.err_handle));
                }
                if (client == null) {
                    throw new UiError(appContext.getString(R.string.err_not_ready));
                }
                final RelayClient.DirectoryEntry entry = client.directory(handle);
                if (entry.uid.equals(account.uid)) {
                    throw new UiError("Це ваш власний псевдонім.");
                }
                Contact existing = published.findContact(entry.uid);
                if (existing != null && !existing.identityKey.equals(entry.identityKey)) {
                    throw new UiError(appContext.getString(R.string.contact_identity_changed));
                }
                String fingerprint = SignalEngine.fingerprint(
                        published.crypto, account.uid, entry.uid, entry.identityKey);
                postSuccess(callback, new ContactInfo(entry.uid, entry.handle,
                        entry.identityKey, fingerprint,
                        existing != null && existing.verified));
            }
        }, callback);
    }

    public void saveContact(final ContactInfo info, final boolean verified, final Op callback) {
        submit(callback, new Task() {
            @Override
            public void run() throws Exception {
                vault.transaction(new Vault.Tx<Void>() {
                    @Override
                    public Void run(VaultState state) throws Exception {
                        Contact existing = state.findContact(info.uid);
                        if (existing != null
                                && !existing.identityKey.equals(info.identityKey)) {
                            throw new UiError(
                                    appContext.getString(R.string.contact_identity_changed));
                        }
                        // Pin the directory identity in the crypto store before
                        // any message can arrive, so the first inbound envelope
                        // is checked against the key the user actually added.
                        SignalEngine.pinIdentity(
                                state.crypto, info.uid, info.identityKey);
                        boolean isVerified = verified || (existing != null && existing.verified);
                        state.upsertContact(new Contact(
                                info.uid, info.handle, info.identityKey, isVerified));
                        return null;
                    }
                });
                publish();
            }
        });
    }

    public void verifyContact(final String uid, final boolean verified, final Op callback) {
        submit(callback, new Task() {
            @Override
            public void run() throws Exception {
                vault.transaction(new Vault.Tx<Void>() {
                    @Override
                    public Void run(VaultState state) {
                        Contact contact = state.findContact(uid);
                        if (contact == null) {
                            throw new IllegalStateException("contact is missing");
                        }
                        state.upsertContact(contact.withVerified(verified));
                        return null;
                    }
                });
                publish();
            }
        });
    }

    public void deleteContact(final String uid, final Op callback) {
        submit(callback, new Task() {
            @Override
            public void run() throws Exception {
                vault.transaction(new Vault.Tx<Void>() {
                    @Override
                    public Void run(VaultState state) {
                        state.removeContact(uid);
                        // Drop the session so a re-added contact starts fresh;
                        // the identity pin is dropped with the contact, which is
                        // the only explicit way to accept a changed key.
                        state.crypto.sessions.remove(uid);
                        state.crypto.identities.remove(uid);
                        return null;
                    }
                });
                publish();
            }
        });
    }

    public void fingerprintFor(final String uid, final OpT<String> callback) {
        submit(new Task() {
            @Override
            public void run() throws Exception {
                Account account = requireAccount();
                Contact contact = published.findContact(uid);
                if (contact == null) {
                    throw new UiError(appContext.getString(R.string.err_no_contact));
                }
                String fingerprint = SignalEngine.fingerprint(
                        published.crypto, account.uid, contact.uid, contact.identityKey);
                postSuccess(callback, fingerprint);
            }
        }, callback);
    }

    public void localFingerprint(final OpT<String> callback) {
        submit(new Task() {
            @Override
            public void run() throws Exception {
                requireAccount();
                postSuccess(callback, SignalEngine.localIdentityKey(published.crypto));
            }
        }, callback);
    }

    // --- messaging -----------------------------------------------------------

    public void sendText(final String uid, final String text, final Op callback) {
        submit(callback, new Task() {
            @Override
            public void run() throws Exception {
                Account account = requireAccount();
                final Contact contact = published.findContact(uid);
                if (contact == null) {
                    throw new UiError(appContext.getString(R.string.err_no_contact));
                }
                if (text == null || text.trim().isEmpty()) {
                    throw new UiError(appContext.getString(R.string.chat_empty_text));
                }
                if (Codec.utf8(text).length > SignalEngine.MAX_TEXT_BYTES) {
                    throw new UiError(appContext.getString(R.string.chat_too_long));
                }

                PublicBundle bundle = null;
                if (!SignalEngine.hasSession(published.crypto, uid)) {
                    if (client == null) {
                        throw new UiError(appContext.getString(R.string.err_not_ready));
                    }
                    bundle = client.prekeys(uid);
                    // Directory pin and bundle must agree exactly.
                    if (!bundle.identityKey.equals(contact.identityKey)) {
                        throw new UiError(appContext.getString(R.string.err_identity_changed));
                    }
                }

                final PublicBundle sessionBundle = bundle;
                vault.transaction(new Vault.Tx<Void>() {
                    @Override
                    public Void run(VaultState state) throws Exception {
                        SendQueue.enqueue(state, uid, text, sessionBundle);
                        return null;
                    }
                });
                publish();

                // Best-effort immediate delivery; failures stay durably queued
                // with the very same ciphertext and id.
                try {
                    flushOutbox();
                } catch (RelayException e) {
                    if (e.isAuthFailure()) {
                        throw new UiError(appContext.getString(R.string.err_unauthorized));
                    }
                    notice("Повідомлення в черзі. Надішлеться, коли буде зв'язок.");
                }
            }
        });
    }

    // --- sync ----------------------------------------------------------------

    private void syncOnce() throws Exception {
        if (client == null || published.account == null) {
            return;
        }
        flushOutbox();
        receiveFromRelay();
        maybeRefillPreKeys();
    }

    private void flushOutbox() throws RelayException {
        if (client == null) {
            return;
        }
        List<OutgoingEnvelope> pending = new ArrayList<>(published.outbox);
        for (final OutgoingEnvelope envelope : pending) {
            try {
                client.send(envelope);
            } catch (RelayException e) {
                if (e.isPermanentRejection()) {
                    final String reason = e.detail.isEmpty()
                            ? appContext.getString(R.string.err_server)
                            : e.detail;
                    try {
                        vault.transaction(new Vault.Tx<Void>() {
                            @Override
                            public Void run(VaultState state) {
                                SendQueue.markPermanentlyRejected(
                                        state, envelope.id, reason);
                                return null;
                            }
                        });
                        publish();
                    } catch (VaultException storageFailure) {
                        // Leave the entry queued; nothing is lost.
                    }
                    notice(appContext.getString(R.string.chat_failed_prefix, reason));
                    continue;
                }
                if (e.isAuthFailure()) {
                    throw e;
                }
                // Network/timeout/rate limit: keep the queue and stop pushing.
                throw e;
            }
            try {
                vault.transaction(new Vault.Tx<Void>() {
                    @Override
                    public Void run(VaultState state) {
                        SendQueue.markSent(state, envelope.id);
                        return null;
                    }
                });
                publish();
            } catch (VaultException e) {
                // The relay accepted it; the local status update will be
                // retried by re-sending the identical ciphertext (idempotent).
                throw new RelayException(RelayException.Kind.NETWORK,
                        "local commit failed after send", e);
            }
        }
    }

    private void receiveFromRelay() throws RelayException {
        if (client == null) {
            return;
        }
        final String localUid = published.account.uid;
        List<Envelope> envelopes = client.fetchMessages();
        final List<String> committed = new ArrayList<>();
        for (final Envelope envelope : envelopes) {
            final InboxProcessor.Result[] result = new InboxProcessor.Result[1];
            try {
                vault.transaction(new Vault.Tx<Void>() {
                    @Override
                    public Void run(VaultState state) throws Exception {
                        result[0] = InboxProcessor.process(state, envelope, localUid);
                        return null;
                    }
                });
            } catch (VaultException e) {
                Throwable cause = e.getCause();
                if (e.kind == VaultException.Kind.MUTATION
                        && cause instanceof CryptoException) {
                    // Ratchet mutation rolled back; never ACK this envelope.
                    notice(InboxProcessor.describe((CryptoException) cause));
                    continue;
                }
                if (e.kind == VaultException.Kind.MUTATION
                        && cause instanceof InboxProcessor.Failure) {
                    notice(cause.getMessage());
                    continue;
                }
                // Storage failure: stop the batch and keep everything unacked.
                break;
            }
            publish();
            InboxProcessor.Result outcome = result[0];
            if (outcome != null && outcome.acknowledge) {
                committed.add(envelope.id);
            }
        }
        if (!committed.isEmpty()) {
            // ACK only what is durably committed. A failed ACK is retried on the
            // next poll because processed ids are already persisted.
            client.acknowledge(committed);
        }
    }

    private void maybeRefillPreKeys() throws RelayException, VaultException, CryptoException {
        if (client == null) {
            return;
        }
        if (published.crypto.oneTimePreKeys.size() >= SignalEngine.PREKEY_LOW_WATER) {
            return;
        }
        vault.transaction(new Vault.Tx<Void>() {
            @Override
            public Void run(VaultState state) throws Exception {
                SignalEngine.addOneTimePreKeys(state.crypto, SignalEngine.PREKEY_REFILL);
                return null;
            }
        });
        publish();
        final PublicBundle upload = SignalEngine.buildBundle(published.crypto, true);
        client.uploadPrekeys(upload);
        vault.transaction(new Vault.Tx<Void>() {
            @Override
            public Void run(VaultState state) {
                state.crypto.lastUploadedPreKeyId = maxPreKeyId(state);
                return null;
            }
        });
        publish();
    }

    // --- plumbing ------------------------------------------------------------

    private void submit(final Op callback, final Task task) {
        worker.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    if (fatal) {
                        throw new UiError(fatalMessage);
                    }
                    if (vault == null) {
                        throw new UiError(appContext.getString(R.string.err_not_ready));
                    }
                    task.run();
                    if (callback != null) {
                        mainHandler.post(new Runnable() {
                            @Override
                            public void run() {
                                callback.onSuccess();
                            }
                        });
                    }
                } catch (UiError e) {
                    postFailure(callback, e.getMessage());
                } catch (VaultException e) {
                    postFailure(callback, mapVault(e));
                } catch (RelayException e) {
                    postFailure(callback, mapRelay(e));
                } catch (CryptoException e) {
                    postFailure(callback, mapCrypto(e));
                } catch (Exception e) {
                    postFailure(callback, appContext.getString(R.string.err_server));
                }
            }
        });
    }

    private <T> void submit(final Task task, final OpT<T> callback) {
        worker.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    if (fatal) {
                        throw new UiError(fatalMessage);
                    }
                    if (vault == null) {
                        throw new UiError(appContext.getString(R.string.err_not_ready));
                    }
                    task.run();
                } catch (UiError e) {
                    postFailure(callback, e.getMessage());
                } catch (VaultException e) {
                    postFailure(callback, mapVault(e));
                } catch (RelayException e) {
                    postFailure(callback, mapRelay(e));
                } catch (CryptoException e) {
                    postFailure(callback, mapCrypto(e));
                } catch (Exception e) {
                    postFailure(callback, appContext.getString(R.string.err_server));
                }
            }
        });
    }

    private <T> void postSuccess(final OpT<T> callback, final T value) {
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                callback.onSuccess(value);
            }
        });
    }

    private void postFailure(final Op callback, final String message) {
        if (callback == null) {
            return;
        }
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                callback.onFailure(message);
            }
        });
    }

    private <T> void postFailure(final OpT<T> callback, final String message) {
        if (callback == null) {
            return;
        }
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                callback.onFailure(message);
            }
        });
    }

    private void publish() {
        published = vault.snapshot();
        if (listeners.isEmpty()) {
            return;
        }
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                for (Listener active : listeners) {
                    active.onStateChanged();
                }
            }
        });
    }

    private void notice(final String message) {
        if (listeners.isEmpty()) {
            return;
        }
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                for (Listener active : listeners) {
                    active.onNotice(message);
                }
            }
        });
    }

    private Account requireAccount() throws UiError {
        Account account = published.account;
        if (account == null) {
            throw new UiError(appContext.getString(R.string.err_no_account));
        }
        return account;
    }

    private static int maxPreKeyId(VaultState state) {
        int max = 0;
        for (io.veil.messenger.crypto.CryptoState.PreKeyState key : state.crypto.oneTimePreKeys) {
            max = Math.max(max, key.id);
        }
        return max;
    }

    private String urlMessage(UrlException e) {
        switch (e.kind) {
            case EMPTY:
                return appContext.getString(R.string.err_url_empty);
            case INSECURE:
                return appContext.getString(R.string.err_url_insecure);
            default:
                return appContext.getString(R.string.err_url_invalid);
        }
    }

    private String mapRelay(RelayException e) {
        switch (e.kind) {
            case UNAUTHORIZED:
                return appContext.getString(R.string.err_unauthorized);
            case RATE_LIMITED:
                return appContext.getString(R.string.err_rate_limited);
            case TIMEOUT:
                return appContext.getString(R.string.err_timeout);
            case NETWORK:
                return appContext.getString(R.string.err_network);
            case DECODING:
                return appContext.getString(R.string.err_decoding);
            case SERVER:
                if (e.status == 409) {
                    return appContext.getString(R.string.err_conflict);
                }
                if (e.status == 413) {
                    return appContext.getString(R.string.err_too_large);
                }
                return e.detail.isEmpty()
                        ? appContext.getString(R.string.err_server)
                        : e.detail;
            default:
                return appContext.getString(R.string.err_server);
        }
    }

    private String mapCrypto(CryptoException e) {
        switch (e.kind) {
            case IDENTITY_CHANGED:
                return appContext.getString(R.string.err_identity_changed);
            case TEXT_TOO_LONG:
                return appContext.getString(R.string.chat_too_long);
            case DUPLICATE:
                return appContext.getString(R.string.chat_status_received);
            default:
                return appContext.getString(R.string.err_crypto);
        }
    }

    private String mapVault(VaultException e) {
        if (e.kind == VaultException.Kind.MUTATION && e.getCause() instanceof CryptoException) {
            return mapCrypto((CryptoException) e.getCause());
        }
        if (e.kind == VaultException.Kind.MUTATION && e.getCause() instanceof UiError) {
            return e.getCause().getMessage();
        }
        if (e.kind == VaultException.Kind.TOO_LARGE) {
            return appContext.getString(R.string.err_too_large);
        }
        return appContext.getString(R.string.fatal_body);
    }

    /** Contact plus the out-of-band fingerprint shown to the user. */
    public static final class ContactInfo {
        public final String uid;
        public final String handle;
        public final String identityKey;
        public final String fingerprint;
        public final boolean verified;

        ContactInfo(String uid, String handle, String identityKey, String fingerprint,
                    boolean verified) {
            this.uid = uid;
            this.handle = handle;
            this.identityKey = identityKey;
            this.fingerprint = fingerprint;
            this.verified = verified;
        }
    }

    /** User-presentable failure raised inside a task. */
    private static final class UiError extends Exception {
        UiError(String message) {
            super(message);
        }
    }
}
