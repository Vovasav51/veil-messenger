package io.veil.messenger.ui;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.CheckBox;
import android.widget.TextView;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.textfield.TextInputEditText;

import io.veil.messenger.R;
import io.veil.messenger.core.AppCore;
import io.veil.messenger.core.model.Contact;

/**
 * Contact add/verify screen. Exact directory lookup only; the 60-digit Signal
 * fingerprint must be compared out of band before trusting the key.
 */
public final class ContactActivity extends BaseActivity implements AppCore.Listener {

    public static final String EXTRA_UID = "io.veil.messenger.extra.CONTACT_UID";
    public static final String EXTRA_HANDLE = "io.veil.messenger.extra.CONTACT_HANDLE";

    private String existingUid;
    private AppCore.ContactInfo pendingInfo;
    private boolean fingerprintRequested;

    private View lookupSection;
    private TextInputEditText handleInput;
    private MaterialButton lookupButton;
    private View resultCard;
    private TextView contactHandle;
    private TextView contactUid;
    private TextView fingerprintView;
    private CheckBox verifiedCheck;
    private MaterialButton saveButton;
    private MaterialButton deleteButton;
    private MaterialButton copyButton;
    private boolean busy;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_contact);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(view -> finish());
        Insets.top(toolbar);
        Insets.bottom(findViewById(R.id.scroll));

        lookupSection = findViewById(R.id.lookupSection);
        handleInput = findViewById(R.id.handleInput);
        lookupButton = findViewById(R.id.lookupButton);
        resultCard = findViewById(R.id.resultCard);
        contactHandle = findViewById(R.id.contactHandle);
        contactUid = findViewById(R.id.contactUid);
        fingerprintView = findViewById(R.id.fingerprint);
        verifiedCheck = findViewById(R.id.verifiedCheck);
        saveButton = findViewById(R.id.saveButton);
        deleteButton = findViewById(R.id.deleteButton);
        copyButton = findViewById(R.id.copyButton);

        existingUid = getIntent().getStringExtra(EXTRA_UID);
        String handle = getIntent().getStringExtra(EXTRA_HANDLE);

        lookupButton.setOnClickListener(view -> lookup());
        saveButton.setOnClickListener(view -> save());
        copyButton.setOnClickListener(view -> copyFingerprint());
        deleteButton.setOnClickListener(view -> confirmDelete());

        if (existingUid != null) {
            existingMode();
        } else {
            lookupSection.setVisibility(View.VISIBLE);
            resultCard.setVisibility(View.GONE);
            deleteButton.setVisibility(View.GONE);
            if (handle != null) {
                handleInput.setText(handle);
            }
        }
    }

    @Override
    protected void onStart() {
        super.onStart();
        core().addListener(this);
        renderExisting();
    }

    @Override
    protected void onStop() {
        core().removeListener(this);
        super.onStop();
    }

    @Override
    public void onReady() {
        renderExisting();
    }

    @Override
    public void onStateChanged() {
        renderExisting();
    }

    @Override
    public void onFatal(String message) {
        showFatal();
    }

    @Override
    public void onNotice(String message) {
        showNotice(message);
    }

    private void existingMode() {
        lookupSection.setVisibility(View.GONE);
        resultCard.setVisibility(View.VISIBLE);
        deleteButton.setVisibility(View.VISIBLE);
        saveButton.setText(R.string.contact_save);
        renderExisting();
    }

    private void renderExisting() {
        if (existingUid == null || core().isFatal() || !core().isReady()) {
            return;
        }
        Contact contact = core().state().findContact(existingUid);
        if (contact == null) {
            finish();
            return;
        }
        contactHandle.setText(Formatting.displayName(contact));
        contactUid.setText(contact.uid);
        if (!busy) {
            verifiedCheck.setChecked(contact.verified);
        }
        if (!fingerprintRequested) {
            fingerprintRequested = true;
            core().fingerprintFor(contact.uid, new AppCore.OpT<String>() {
                @Override
                public void onSuccess(String value) {
                    fingerprintView.setText(Formatting.fingerprint(value));
                }

                @Override
                public void onFailure(String message) {
                    fingerprintRequested = false;
                    setStatusText(R.id.statusText, message);
                }
            });
        }
    }

    private void lookup() {
        if (busy) {
            return;
        }
        String handle = handleInput.getText() == null ? "" : handleInput.getText().toString();
        setBusy(true);
        setStatusText(R.id.statusText, null);
        core().lookupContact(handle, new AppCore.OpT<AppCore.ContactInfo>() {
            @Override
            public void onSuccess(AppCore.ContactInfo info) {
                setBusy(false);
                pendingInfo = info;
                resultCard.setVisibility(View.VISIBLE);
                lookupSection.setVisibility(View.GONE);
                contactHandle.setText(getString(R.string.contact_handle_at, info.handle));
                contactUid.setText(info.uid);
                fingerprintView.setText(Formatting.fingerprint(info.fingerprint));
                verifiedCheck.setChecked(info.verified);
                saveButton.setText(R.string.contact_save);
            }

            @Override
            public void onFailure(String message) {
                setBusy(false);
                setStatusText(R.id.statusText, message);
            }
        });
    }

    private void save() {
        if (busy) {
            return;
        }
        boolean verified = verifiedCheck.isChecked();
        if (existingUid != null) {
            setBusy(true);
            core().verifyContact(existingUid, verified, new AppCore.Op() {
                @Override
                public void onSuccess() {
                    setBusy(false);
                    showNotice(getString(R.string.contact_saved));
                    finish();
                }

                @Override
                public void onFailure(String message) {
                    setBusy(false);
                    setStatusText(R.id.statusText, message);
                }
            });
            return;
        }
        if (pendingInfo == null) {
            return;
        }
        setBusy(true);
        core().saveContact(pendingInfo, verified, new AppCore.Op() {
            @Override
            public void onSuccess() {
                setBusy(false);
                showNotice(getString(R.string.contact_saved));
                finish();
            }

            @Override
            public void onFailure(String message) {
                setBusy(false);
                setStatusText(R.id.statusText, message);
            }
        });
    }

    private void copyFingerprint() {
        String digits = fingerprintView.getText().toString().replace(" ", "");
        if (digits.isEmpty()) {
            return;
        }
        ClipboardManager clipboard =
                (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard != null) {
            clipboard.setPrimaryClip(ClipData.newPlainText("Veil fingerprint", digits));
        }
        showNotice(getString(R.string.contact_copied));
    }

    private void confirmDelete() {
        if (existingUid == null) {
            return;
        }
        new AlertDialog.Builder(this)
                .setMessage(R.string.contact_delete_confirm)
                .setNegativeButton(R.string.common_cancel, null)
                .setPositiveButton(R.string.common_delete, (dialog, which) -> delete())
                .show();
    }

    private void delete() {
        if (existingUid == null) {
            return;
        }
        setBusy(true);
        core().deleteContact(existingUid, new AppCore.Op() {
            @Override
            public void onSuccess() {
                setBusy(false);
                finish();
            }

            @Override
            public void onFailure(String message) {
                setBusy(false);
                setStatusText(R.id.statusText, message);
            }
        });
    }

    private void setBusy(boolean value) {
        busy = value;
        saveButton.setEnabled(!value);
        lookupButton.setEnabled(!value);
        deleteButton.setEnabled(!value);
        handleInput.setEnabled(!value);
    }
}
