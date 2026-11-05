import SwiftUI

/// Onboarding: relay URL + handle only. No phone number, no e-mail, no contacts
/// upload. The local identity is generated on this device before the network
/// call; an interrupted registration can be retried with the same uid.
struct OnboardingView: View {
    @EnvironmentObject private var model: AppModel

    @State private var serverURL = ""
    @State private var handle = ""
    @FocusState private var focusedField: Field?

    private enum Field { case server, handle }

    private var canSubmit: Bool {
        model.busy == .none
            && !serverURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !handle.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private var isRegistering: Bool { model.busy == .registering }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 22) {
                    header
                    if let banner = model.banner {
                        BannerView(banner: banner) { model.dismissBanner() }
                            .padding(.horizontal, -4)
                    }
                    form
                    if model.pendingRegistration != nil { pendingNote }
                    if model.canRetryWithNewUID { newUIDAction }
                    footer
                }
                .padding(.horizontal, 22)
                .padding(.vertical, 26)
            }
            .scrollDismissesKeyboard(.interactively)
            .navigationBarTitleDisplayMode(.inline)
            .onAppear(perform: prefill)
        }
    }

    // MARK: Sections

    private var header: some View {
        VStack(spacing: 14) {
            VeilWordmark(subtitle: "Приватне листування 1:1 без номера телефону. Ключі створюються на цьому пристрої.")
            HStack(spacing: 6) {
                Image(systemName: "flask.fill")
                Text("експериментальна версія · без аудиту")
            }
            .font(.caption2.weight(.medium))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(Color.secondary.opacity(0.15), in: Capsule())
        }
        .padding(.bottom, 4)
    }

    private var form: some View {
        VStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Адреса релея")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                TextField("https://relay.example.com", text: $serverURL)
                    .textContentType(.URL)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .focused($focusedField, equals: .server)
                    .submitLabel(.next)
                    .onSubmit { focusedField = .handle }
                    .padding(12)
                    .background(Color.secondary.opacity(0.12), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("Нікнейм")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                TextField("@нікнейм", text: $handle)
                    .textContentType(.username)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .focused($focusedField, equals: .handle)
                    .submitLabel(.go)
                    .onSubmit { submit() }
                    .padding(12)
                    .background(Color.secondary.opacity(0.12), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                Text("3–24 символи: a–z, 0–9, _")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            Button(action: submit) {
                HStack(spacing: 8) {
                    if isRegistering {
                        ProgressView().controlSize(.small).tint(.white)
                    }
                    Text(isRegistering ? "Реєстрація…" : "Зареєструватися")
                        .font(.headline)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 13)
            }
            .buttonStyle(.borderedProminent)
            .buttonBorderShape(.roundedRectangle(radius: 14))
            .disabled(!canSubmit)

            Text("Реєстрація надсилає на релей лише публічні ключі, нікнейм і uid. Приватні ключі не залишають пристрій.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(16)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .strokeBorder(.quaternary, lineWidth: 1)
        )
    }

    private var pendingNote: some View {
        let pending = model.pendingRegistration
        return HStack(alignment: .top, spacing: 10) {
            Image(systemName: "arrow.clockwise.circle.fill")
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 4) {
                Text("Є незавершена реєстрація")
                    .font(.footnote.weight(.semibold))
                if let pending {
                    Text("@\(pending.handle) · \(pending.serverURL)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
                Text("Повторна спроба використає той самий uid і ту саму локальну ідентичність.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(Color.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
    }

    private var newUIDAction: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("uid уже зайнятий на сервері, а токен втрачено. Відновлення акаунта не підтримується. Новий uid збереже цю саму ідентичність пристрою.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button("Зареєструвати новий uid") {
                Task {
                    await model.retryRegistrationWithNewUID(serverURLText: serverURL, handleText: handle)
                }
            }
            .font(.footnote.weight(.semibold))
            .disabled(!canSubmit)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(Color.red.opacity(0.08), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
    }

    private var footer: some View {
        VStack(spacing: 8) {
            Divider()
            Text("Релей бачить, хто кому пише, коли і з якої IP-адреси. Захисту метаданих (sealed sender) немає. Push-сповіщень, груп, вкладень і відновлення акаунта немає.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.leading)
                .frame(maxWidth: .infinity, alignment: .leading)
            ExperimentalFootnote()
        }
        .padding(.top, 6)
    }

    // MARK: Actions

    private func prefill() {
        if serverURL.isEmpty, let pending = model.pendingRegistration {
            serverURL = pending.serverURL
            handle = pending.handle
        }
    }

    private func submit() {
        guard canSubmit else { return }
        focusedField = nil
        Task {
            await model.register(serverURLText: serverURL, handleText: handle)
        }
    }
}
