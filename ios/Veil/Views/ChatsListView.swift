import SwiftUI

/// Chat list: existing conversations first, then contacts without messages.
/// Pull-to-refresh triggers one foreground sync cycle.
struct ChatsListView: View {
    @EnvironmentObject private var model: AppModel
    @State private var showCompose = false

    var body: some View {
        NavigationStack {
            List {
                if model.chatSummaries.isEmpty && model.contactsWithoutChat.isEmpty {
                    emptyState
                } else {
                    if !model.chatSummaries.isEmpty {
                        Section("Чати") {
                            ForEach(model.chatSummaries) { summary in
                                NavigationLink {
                                    ChatView(peerUID: summary.peerUID, contact: summary.contact)
                                } label: {
                                    ChatRow(summary: summary)
                                }
                            }
                        }
                    }
                    if !model.contactsWithoutChat.isEmpty {
                        Section("Контакти") {
                            ForEach(model.contactsWithoutChat) { contact in
                                NavigationLink {
                                    ChatView(peerUID: contact.uid, contact: contact)
                                } label: {
                                    ContactRow(contact: contact)
                                }
                            }
                        }
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Veil")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    SyncBadge(phase: model.syncPhase)
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showCompose = true
                    } label: {
                        Image(systemName: "square.and.pencil")
                    }
                    .accessibilityLabel("Додати контакт")
                }
            }
            .safeAreaInset(edge: .top) {
                if let banner = model.banner {
                    BannerView(banner: banner) { model.dismissBanner() }
                        .background(.bar)
                }
            }
            .refreshable {
                await model.syncNow()
            }
            .task {
                await model.syncIfNeeded()
            }
            .sheet(isPresented: $showCompose) {
                ComposeView()
                    .environmentObject(model)
            }
        }
    }

    private var emptyState: some View {
        Section {
            VStack(spacing: 12) {
                Image(systemName: "bubble.left.and.bubble.right")
                    .font(.system(size: 34))
                    .foregroundStyle(.secondary)
                Text("Ще немає розмов")
                    .font(.headline)
                Text("Додайте контакт за точним нікнеймом, порівняйте відбиток безпеки і надішліть перше повідомлення.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                Button("Додати контакт") { showCompose = true }
                    .buttonStyle(.borderedProminent)
                    .buttonBorderShape(.capsule)
                    .padding(.top, 4)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 28)
            .listRowBackground(Color.clear)
        }
    }
}

// MARK: - Rows

private struct ChatRow: View {
    let summary: ChatSummary

    var body: some View {
        HStack(spacing: 12) {
            HandleAvatar(handle: summary.displayHandle)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 4) {
                    Text(summary.contact.map { "@\($0.handle)" } ?? summary.displayHandle)
                        .font(.body.weight(.semibold))
                        .lineLimit(1)
                    if summary.contact?.verified == true {
                        Image(systemName: "checkmark.seal.fill")
                            .font(.caption2)
                            .foregroundStyle(.green)
                            .accessibilityLabel("Відбиток підтверджено")
                    }
                }
                Text(preview)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .privacySensitive()
            }
            Spacer(minLength: 4)
            VStack(alignment: .trailing, spacing: 4) {
                Text(VeilFormat.listTimestamp(summary.lastDate))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                if summary.lastOutgoing {
                    Image(systemName: "arrow.up.right")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 2)
    }

    private var preview: String {
        let prefix = summary.lastOutgoing ? "Ви: " : ""
        return prefix + summary.lastText.replacingOccurrences(of: "\n", with: " ")
    }
}

private struct ContactRow: View {
    let contact: Contact

    var body: some View {
        HStack(spacing: 12) {
            HandleAvatar(handle: contact.handle)
            VStack(alignment: .leading, spacing: 3) {
                Text("@\(contact.handle)")
                    .font(.body.weight(.semibold))
                Text(contact.verified ? "Відбиток підтверджено" : "Відбиток не підтверджено")
                    .font(.caption)
                    .foregroundStyle(contact.verified ? Color.green : Color.secondary)
            }
            Spacer(minLength: 4)
            if contact.verified {
                Image(systemName: "checkmark.seal.fill")
                    .font(.caption)
                    .foregroundStyle(.green)
                    .accessibilityLabel("Відбиток підтверджено")
            }
        }
        .padding(.vertical, 2)
    }
}
