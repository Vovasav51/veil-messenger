import SwiftUI

/// Add a contact by exact handle. The directory identity and the prekey bundle
/// identity must match before the user can add (and later encrypt to) them.
struct ComposeView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var handle = ""
    @State private var draft: ContactDraft?
    @State private var verified = false
    @State private var errorText: String?
    @State private var addError: String?
    @FocusState private var handleFocused: Bool

    private var isLookingUp: Bool { model.busy == .lookingUp }
    private var canLookup: Bool {
        model.busy == .none && !handle.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("@нікнейм", text: $handle)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .textContentType(.username)
                        .focused($handleFocused)
                        .submitLabel(.search)
                        .onSubmit(lookup)
                } header: {
                    Text("Точний нікнейм")
                } footer: {
                    Text("Пошук лише за точним нікнеймом. Список контактів не завантажується і не надсилається.")
                }

                if let errorText {
                    Section {
                        Label(errorText, systemImage: "exclamationmark.triangle.fill")
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                }

                if let draft {
                    resultSection(draft)
                }

                Section {
                    Button(action: lookup) {
                        HStack {
                            if isLookingUp { ProgressView().controlSize(.small) }
                            Text(isLookingUp ? "Пошук…" : "Знайти за нікнеймом")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .disabled(!canLookup)
                }
            }
            .navigationTitle("Новий контакт")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Скасувати") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Додати") { add(draft) }
                        .disabled(draft == nil)
                }
            }
            .onAppear { handleFocused = true }
        }
    }

    // MARK: Result

    @ViewBuilder
    private func resultSection(_ draft: ContactDraft) -> some View {
        Section {
            LabeledContent("Нікнейм", value: "@\(draft.handle)")
            LabeledContent("UID", value: VeilFormat.shortUID(draft.uid))

            FingerprintBlock(fingerprint: draft.fingerprint)

            Toggle(isOn: $verified) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Я порівняв відбиток")
                        .font(.footnote.weight(.semibold))
                    Text("Позначайте лише після звірки в іншому каналі.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }

            if let addError {
                Label(addError, systemImage: "exclamationmark.triangle.fill")
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        } header: {
            Text("Перевірка ідентичності")
        } footer: {
            Text("Перший ключ контакту приймається за довірою (TOFU) і закріплюється. Якщо ключ згодом зміниться, шифрування буде зупинено.")
        }
    }

    // MARK: Actions

    private func lookup() {
        guard canLookup else { return }
        handleFocused = false
        errorText = nil
        addError = nil
        draft = nil
        verified = false

        Task {
            do {
                draft = try await model.lookupContact(handleText: handle)
            } catch {
                errorText = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            }
        }
    }

    private func add(_ draft: ContactDraft?) {
        guard let draft else { return }
        do {
            try model.addContact(draft, verified: verified)
            dismiss()
        } catch {
            addError = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }
}
