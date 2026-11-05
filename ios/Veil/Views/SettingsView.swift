import SwiftUI
import UIKit

/// Settings: account, own fingerprint, sync diagnostics and the honest list of
/// MVP limitations. Nothing here claims production readiness.
struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var ownFingerprint: String?
    @State private var fingerprintError: String?
    @State private var showCopied = false

    private var account: Account? { model.account }
    private var queuedCount: Int { model.vaultState.outbox.count }

    var body: some View {
        NavigationStack {
            Form {
                if let banner = model.banner {
                    Section {
                        BannerView(banner: banner) { model.dismissBanner() }
                            .listRowInsets(EdgeInsets())
                            .listRowBackground(Color.clear)
                    }
                }

                accountSection
                contactsSection
                syncSection
                limitationsSection
                aboutSection
            }
            .navigationTitle("Налаштування")
        }
    }

    // MARK: Sections

    private var accountSection: some View {
        Section {
            LabeledContent("Нікнейм", value: account.map { "@\($0.handle)" } ?? "—")
            if let account {
                Button {
                    UIPasteboard.general.string = account.uid
                    showCopied = true
                } label: {
                    HStack {
                        Text("UID")
                            .foregroundStyle(.primary)
                        Spacer()
                        Text(VeilFormat.shortUID(account.uid))
                            .font(.system(.footnote, design: .monospaced))
                            .foregroundStyle(.secondary)
                        Image(systemName: showCopied ? "checkmark" : "doc.on.doc")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .buttonStyle(.plain)

                LabeledContent("Релей") {
                    Text(account.serverURL)
                        .font(.footnote)
                        .lineLimit(2)
                        .multilineTextAlignment(.trailing)
                }
            }
        } header: {
            Text("Акаунт")
        } footer: {
            Text("Акаунт існує лише на цьому пристрої. Відновлення, експорту ключів і входу з іншого пристрою немає.")
        }
    }

    private var securitySection: some View {
        Section {
            if let ownFingerprint {
                FingerprintBlock(
                    fingerprint: ownFingerprint,
                    caption: "Ваш відбиток. Показуйте його співрозмовнику поза застосунком для перевірки."
                )
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
            Text("Мій відбиток")
        }
    }

    private var contactsSection: some View {
        Section {
            if model.contacts.isEmpty {
                Text("Контактів ще немає.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(model.contacts) { contact in
                    NavigationLink {
                        ContactDetailView(contact: contact)
                            .environmentObject(model)
                    } label: {
                        HStack(spacing: 10) {
                            Text("@\(contact.handle)")
                                .lineLimit(1)
                            Spacer()
                            if contact.verified {
                                Image(systemName: "checkmark.seal.fill")
                                    .font(.caption)
                                    .foregroundStyle(.green)
                            }
                        }
                    }
                }
            }
        } header: {
            Text("Контакти та відбитки")
        } footer: {
            Text("Перший ключ приймається за довірою (TOFU) і закріплюється на пристрої. Зміна ключа зупиняє шифрування.")
        }
    }

    private var syncSection: some View {
        Section {
            LabeledContent("Стан", value: SyncBadge.text(for: model.syncPhase))
            LabeledContent("Остання синхронізація") {
                Text(model.lastSyncAt.map { VeilFormat.messageTime($0) } ?? "—")
                    .foregroundStyle(.secondary)
            }
            LabeledContent("У черзі надсилання", value: "\(queuedCount)")
            if model.undecryptableCount > 0 {
                LabeledContent("Не розшифровано", value: "\(model.undecryptableCount)")
                    .foregroundStyle(.orange)
            }
            if model.rejectedOutboxCount > 0 {
                LabeledContent("Відхилено сервером", value: "\(model.rejectedOutboxCount)")
                    .foregroundStyle(.red)
            }

            Button {
                Task { await model.syncNow() }
            } label: {
                Label("Оновити зараз", systemImage: "arrow.clockwise")
            }

            Button {
                Task { await model.checkHealth() }
            } label: {
                Label("Перевірити релей", systemImage: "antenna.radiowaves.left.and.right")
            }
        } header: {
            Text("Синхронізація")
        } footer: {
            Text("Опитування працює лише коли застосунок активний. У фоні нові повідомлення не надходять: push-сповіщень немає.")
        }
    }

    private var limitationsSection: some View {
        Section {
            limitation("Релей бачить, хто кому пише, коли, скільки і з якої IP-адреси.", icon: "eye")
            limitation("Захисту метаданих (sealed sender) немає — приховування відправника не заявлено.", icon: "person.crop.circle.badge.questionmark")
            limitation("Немає push-сповіщень, груп, вкладень, дзвінків і мультипристрою.", icon: "bell.slash")
            limitation("Немає відновлення акаунта: втрата пристрою = втрата акаунта.", icon: "key.slash")
            limitation("Криптографію не аудитовано. Це експериментальний MVP, а не продакшн.", icon: "checkmark.shield")
        } header: {
            Text("Обмеження")
        } footer: {
            Text("Сервер зберігає лише шифротекст і метадані маршрутизації; історія чатів на пристрої — у зашифрованому сховищі.")
        }
    }

    private var aboutSection: some View {
        Section {
            LabeledContent("Застосунок", value: "Veil 0.1 (MVP)")
            LabeledContent("Протокол", value: "LibSignalClient 0.106.0, 1:1")
            LabeledContent("Платформа", value: "iOS 17+")
            Text("AGPL-3.0-only · без гарантій. Libsignal © Signal Messenger LLC та учасники. Вихідні коди надано у Veil-0.1.0-source.zip разом зі збіркою.")
                .font(.footnote)
            NavigationLink("Ліцензія AGPL-3.0") {
                ScrollView {
                    Text(licenseText).font(.footnote).textSelection(.enabled).padding()
                }.navigationTitle("AGPL-3.0")
            }
        } header: {
            Text("Про застосунок")
        } footer: {
            Text("Одна облікова одиниця на пристрій, лише текст 1:1, ліміт 4096 байтів UTF-8 на повідомлення. Ключі Signal фіксує окремий криптомодуль; точну версію бібліотеки вказує він.")
        }
    }

    private func limitation(_ text: String, icon: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .frame(width: 18)
            Text(text)
                .font(.footnote)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: Actions

    private var licenseText: String {
        guard let url = Bundle.main.url(forResource: "AGPL-3.0", withExtension: "txt"),
              let text = try? String(contentsOf: url, encoding: .utf8) else {
            return "Повний текст ліцензії: licenses/AGPL-3.0.txt у вихідному архіві Veil."
        }
        return text
    }

    private func loadFingerprint() {
        guard ownFingerprint == nil else { return }
        do {
            ownFingerprint = try model.ownFingerprint()
            fingerprintError = nil
        } catch {
            fingerprintError = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }
}
