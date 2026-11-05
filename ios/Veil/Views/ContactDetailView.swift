import SwiftUI

/// Contact detail: pinned identity key fingerprint, explicit verification
/// toggle, and the honest limits of what the metadata proves.
struct ContactDetailView: View {
    let contact: Contact

    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var fingerprint: String?
    @State private var fingerprintError: String?
    @State private var verified: Bool
    @State private var saveError: String?

    init(contact: Contact) {
        self.contact = contact
        _verified = State(initialValue: contact.verified)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    LabeledContent("Нікнейм", value: "@\(contact.handle)")
                    LabeledContent("UID", value: VeilFormat.shortUID(contact.uid))
                    LabeledContent("Ключ", value: contact.verified ? "закріплено · підтверджено" : "закріплено · не підтверджено")
                } header: {
                    Text("Контакт")
                }

                Section {
                    if let fingerprint {
                        FingerprintBlock(fingerprint: fingerprint)
                    } else if let fingerprintError {
                        Label(fingerprintError, systemImage: "exclamationmark.triangle.fill")
                            .font(.footnote)
                            .foregroundStyle(.red)
                    } else {
                        HStack(spacing: 8) {
                            ProgressView().controlSize(.small)
                            Text("Обчислення відбитка…").font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                } header: {
                    Text("Відбиток безпеки")
                }

                Section {
                    Toggle("Відбиток підтверджено", isOn: $verified)
                        .onChange(of: verified) { _, newValue in
                            save(newValue)
                        }
                    if let saveError {
                        Label(saveError, systemImage: "exclamationmark.triangle.fill")
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                } footer: {
                    Text("Підтвердження зберігається лише на цьому пристрої. Релей не знає про нього.")
                }

                Section {
                    Text("Відбиток підтверджує, що ключ співрозмовника не змінився з моменту першої зустрічі. Він не доводить особу без порівняння в іншому каналі. Метадані конверта (sender_uid) не є криптографічним доказом — автентичність дає Signal-пін.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Контакт")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Готово") { dismiss() }
                }
            }
            .task { await loadFingerprint() }
        }
    }

    private func loadFingerprint() async {
        do {
            fingerprint = try model.fingerprint(for: contact)
            fingerprintError = nil
        } catch {
            fingerprintError = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }

    private func save(_ value: Bool) {
        do {
            try model.setVerified(value, for: contact.uid)
            saveError = nil
        } catch {
            saveError = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            verified = contact.verified
        }
    }
}
