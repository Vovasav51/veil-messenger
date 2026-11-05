import SwiftUI

/// 1:1 conversation. Outgoing bubbles carry the persisted status: a message is
/// "queued" until the relay accepted the stored ciphertext, then "sent".
struct ChatView: View {
    let peerUID: String
    let contact: Contact?

    @EnvironmentObject private var model: AppModel
    @State private var draft = ""
    @State private var sendError: String?
    @State private var showDetails = false
    @FocusState private var composerFocused: Bool

    private var messages: [ChatMessage] { model.messages(for: peerUID) }
    private var byteCount: Int { draft.utf8.count }
    private var isOverLimit: Bool { byteCount > 4096 }
    private var canSend: Bool {
        contact != nil
            && model.busy == .none
            && !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !isOverLimit
    }

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 6) {
                    if contact == nil {
                        unknownSenderNote
                    }
                    ForEach(messages) { message in
                        MessageBubble(message: message)
                            .id(message.id)
                    }
                    if messages.isEmpty {
                        emptyConversation
                    }
                    Color.clear.frame(height: 1).id("bottom")
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 10)
            }
            .defaultScrollAnchor(.bottom)
            .scrollDismissesKeyboard(.interactively)
            .onChange(of: messages.count) { _, _ in
                withAnimation(.easeOut(duration: 0.2)) {
                    proxy.scrollTo("bottom", anchor: .bottom)
                }
            }
        }
        .navigationTitle(contact.map { "@\($0.handle)" } ?? "Невідомий відправник")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .principal) {
                VStack(spacing: 1) {
                    HStack(spacing: 4) {
                        Text(contact.map { "@\($0.handle)" } ?? "Невідомий")
                            .font(.headline)
                            .lineLimit(1)
                        if contact?.verified == true {
                            Image(systemName: "checkmark.seal.fill")
                                .font(.caption2)
                                .foregroundStyle(.green)
                        }
                    }
                    if contact != nil {
                        Text(contact?.verified == true ? "Відбиток підтверджено" : "Відбиток не підтверджено")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    showDetails = true
                } label: {
                    Image(systemName: "info.circle")
                }
                .accessibilityLabel("Деталі контакту")
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) { composerBar }
        .safeAreaInset(edge: .top, spacing: 0) {
            if let banner = model.banner {
                BannerView(banner: banner) { model.dismissBanner() }
                    .background(.bar)
            }
        }
        .sheet(isPresented: $showDetails) {
            if let contact {
                ContactDetailView(contact: contact)
                    .environmentObject(model)
            } else {
                UnknownPeerSheet(peerUID: peerUID)
            }
        }
    }

    // MARK: Composer

    private var composerBar: some View {
        VStack(spacing: 0) {
            Divider()
            if let sendError {
                Text(sendError)
                    .font(.caption2)
                    .foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 16)
                    .padding(.top, 6)
            }
            HStack(alignment: .bottom, spacing: 8) {
                TextField(contact == nil ? "Відповідь недоступна" : "Повідомлення", text: $draft, axis: .vertical)
                    .lineLimit(1...5)
                    .focused($composerFocused)
                    .disabled(contact == nil)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 9)
                    .background(Color.secondary.opacity(0.12), in: RoundedRectangle(cornerRadius: 20, style: .continuous))

                Button(action: send) {
                    Image(systemName: "arrow.up.circle.fill")
                        .font(.system(size: 32))
                        .symbolRenderingMode(.hierarchical)
                }
                .disabled(!canSend)
                .accessibilityLabel("Надіслати")
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)

            if byteCount > 3000 {
                Text("\(byteCount) / 4096 байтів UTF-8")
                    .font(.caption2)
                    .foregroundStyle(isOverLimit ? Color.red : Color.secondary)
                    .frame(maxWidth: .infinity, alignment: .trailing)
                    .padding(.horizontal, 16)
                    .padding(.bottom, 6)
            }
        }
        .background(.bar)
    }

    private var unknownSenderNote: some View {
        Text("Повідомлення від відправника, якого немає в контактах. Метадані конверта не є підтвердженням особи — додайте контакт за нікнеймом, щоб побачити відбиток і відповісти.")
            .font(.caption)
            .foregroundStyle(.secondary)
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .padding(.bottom, 6)
    }

    private var emptyConversation: some View {
        VStack(spacing: 8) {
            Image(systemName: "lock.shield")
                .font(.system(size: 26))
                .foregroundStyle(.secondary)
            Text(contact == nil ? "Історія порожня" : "Повідомлення шифруються на пристрої. Релей не бачить вмісту.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 40)
    }

    // MARK: Actions

    private func send() {
        guard canSend, let contact = contact else { return }
        let text = draft
        draft = ""
        sendError = nil
        Task {
            do {
                try await model.send(text: text, to: contact)
            } catch {
                sendError = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                if draft.isEmpty { draft = text }
            }
        }
    }
}

// MARK: - Bubble

private struct MessageBubble: View {
    let message: ChatMessage

    private var isOutgoing: Bool { message.outgoing }

    private var statusSymbol: String? {
        guard isOutgoing else { return nil }
        switch message.status {
        case "sent":
            return "checkmark"
        default:
            return "clock"
        }
    }

    var body: some View {
        HStack(spacing: 0) {
            if isOutgoing { Spacer(minLength: 52) }
            VStack(alignment: isOutgoing ? .trailing : .leading, spacing: 3) {
                Text(message.text)
                    .font(.body)
                    .textSelection(.enabled)
                    .privacySensitive()
                HStack(spacing: 4) {
                    Text(VeilFormat.messageTime(message.createdAt))
                        .font(.caption2)
                    if let statusSymbol {
                        Image(systemName: statusSymbol)
                            .font(.caption2)
                            .accessibilityLabel(message.status == "sent" ? "Надіслано" : "У черзі")
                    }
                }
                .foregroundStyle(isOutgoing ? Color.white.opacity(0.75) : Color.secondary)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(bubbleBackground)
            .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
            if !isOutgoing { Spacer(minLength: 52) }
        }
    }

    private var bubbleBackground: AnyShapeStyle {
        if isOutgoing {
            return AnyShapeStyle(
                LinearGradient(
                    colors: [Color.accentColor.opacity(0.92), Color.accentColor.opacity(0.78)],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
            )
        }
        return AnyShapeStyle(Color.secondary.opacity(0.14))
    }
}

// MARK: - Detail sheets

struct UnknownPeerSheet: View {
    let peerUID: String

    var body: some View {
        NavigationStack {
            List {
                Section("Відправник") {
                    LabeledContent("UID", value: VeilFormat.shortUID(peerUID))
                    Text("Відправника не додано в контакти. Його ідентичність не перевірена і не закріплена, тому відповісти неможливо.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Невідомий")
            .navigationBarTitleDisplayMode(.inline)
        }
        .presentationDetents([.medium])
    }
}
