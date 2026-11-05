import SwiftUI

// MARK: - Brand

struct VeilMark: View {
    var size: CGFloat = 64

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.3, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: [
                            Color(red: 0.38, green: 0.33, blue: 0.90),
                            Color(red: 0.15, green: 0.12, blue: 0.40)
                        ],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
            Image(systemName: "eye.slash.fill")
                .font(.system(size: size * 0.42, weight: .semibold))
                .foregroundStyle(.white.opacity(0.95))
        }
        .frame(width: size, height: size)
        .shadow(color: .black.opacity(0.18), radius: size * 0.12, y: size * 0.05)
        .accessibilityHidden(true)
    }
}

struct VeilWordmark: View {
    var subtitle: String? = nil

    var body: some View {
        VStack(spacing: 10) {
            VeilMark(size: 64)
            Text("Veil")
                .font(.system(.largeTitle, design: .rounded).weight(.bold))
            if let subtitle {
                Text(subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
    }
}

// MARK: - Banner

struct BannerView: View {
    let banner: AppModel.Banner
    let onDismiss: () -> Void

    private var symbol: String {
        switch banner.kind {
        case .info: return "info.circle.fill"
        case .success: return "checkmark.circle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .error: return "xmark.octagon.fill"
        }
    }

    private var tint: Color {
        switch banner.kind {
        case .info: return .blue
        case .success: return .green
        case .warning: return .orange
        case .error: return .red
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: symbol)
                .foregroundStyle(tint)
                .font(.body)
            Text(banner.text)
                .font(.footnote)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button(action: onDismiss) {
                Image(systemName: "xmark")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Закрити")
        }
        .padding(12)
        .background(tint.opacity(0.10), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .strokeBorder(tint.opacity(0.25), lineWidth: 1)
        )
        .padding(.horizontal)
        .padding(.vertical, 6)
    }
}

// MARK: - Sync status

struct SyncBadge: View {
    let phase: AppModel.SyncPhase

    private var symbol: String {
        switch phase {
        case .idle: return "checkmark.circle"
        case .syncing: return "arrow.triangle.2.circlepath"
        case .paused: return "pause.circle"
        case .retry: return "clock.arrow.circlepath"
        case .failed: return "exclamationmark.triangle"
        }
    }

    private var tint: Color {
        switch phase {
        case .idle: return .secondary
        case .syncing: return .blue
        case .paused: return .secondary
        case .retry: return .orange
        case .failed: return .red
        }
    }

    var body: some View {
        Image(systemName: symbol)
            .foregroundStyle(tint)
            .symbolEffect(.pulse, isActive: phase == .syncing)
            .accessibilityLabel(Self.text(for: phase))
    }

    static func text(for phase: AppModel.SyncPhase) -> String {
        switch phase {
        case .idle: return "Синхронізовано"
        case .syncing: return "Синхронізація…"
        case .paused: return "Опитування призупинено"
        case .retry(let seconds): return "Повтор через \(seconds) с"
        case .failed(let message): return "Помилка: \(message)"
        }
    }
}

// MARK: - Privacy overlay

struct PrivacyOverlayView: View {
    var body: some View {
        ZStack {
            Rectangle()
                .fill(.ultraThinMaterial)
                .ignoresSafeArea()
            VStack(spacing: 14) {
                VeilMark(size: 72)
                Text("Veil приховано")
                    .font(.system(.title3, design: .rounded).weight(.semibold))
                Text("Вміст чатів не показується, поки застосунок не активний.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 40)
            }
        }
        .transition(.opacity)
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Fatal bootstrap screen

struct FatalBootView: View {
    let message: String

    var body: some View {
        ScrollView {
            VStack(spacing: 18) {
                Spacer(minLength: 60)
                Image(systemName: "exclamationmark.lock.fill")
                    .font(.system(size: 46))
                    .foregroundStyle(.red)
                Text("Сховище недоступне")
                    .font(.system(.title2, design: .rounded).weight(.bold))
                Text(message)
                    .font(.callout)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 8) {
                    Label("Дані не видалено і не перезаписано.", systemImage: "checkmark.shield")
                    Label("Скидання сховища вручну тут недоступне навмисно.", systemImage: "lock.slash")
                    Label("Експериментальна версія без аудиту криптографії.", systemImage: "exclamationmark.triangle")
                }
                .font(.footnote)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
                .background(Color.secondary.opacity(0.12), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                Spacer(minLength: 20)
            }
            .padding(24)
        }
    }
}

// MARK: - Formatting helpers

enum VeilFormat {
    private static let timeFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "uk_UA")
        formatter.dateFormat = "HH:mm"
        return formatter
    }()

    private static let dayFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "uk_UA")
        formatter.dateFormat = "dd.MM"
        return formatter
    }()

    static func messageTime(_ date: Date) -> String {
        timeFormatter.string(from: date)
    }

    static func listTimestamp(_ date: Date) -> String {
        let calendar = Calendar.current
        if calendar.isDateInToday(date) { return timeFormatter.string(from: date) }
        if calendar.isDateInYesterday(date) { return "Вчора" }
        return dayFormatter.string(from: date)
    }

    static func initials(for handle: String) -> String {
        let cleaned = handle.hasPrefix("@") ? String(handle.dropFirst()) : handle
        let letters = cleaned.prefix(2)
        return letters.isEmpty ? "?" : String(letters).uppercased()
    }

    static func shortUID(_ uid: String) -> String {
        uid.count > 12 ? "\(uid.prefix(8))…\(uid.suffix(4))" : uid
    }

    /// A 60-digit safety number is displayed as 12 groups of five, matching the
    /// Signal clients. Anything else (hex, unknown format) is shown verbatim.
    static func groupedFingerprint(_ value: String) -> String {
        let digits = Array(value)
        guard digits.count == 60, digits.allSatisfy({ $0.isASCII && $0.isNumber }) else {
            return value
        }
        var groups: [String] = []
        groups.reserveCapacity(12)
        var index = 0
        while index < digits.count {
            let end = min(index + 5, digits.count)
            groups.append(String(digits[index..<end]))
            index = end
        }
        return groups.joined(separator: " ")
    }
}

// MARK: - Reusable pieces

struct HandleAvatar: View {
    let handle: String
    var size: CGFloat = 40

    var body: some View {
        ZStack {
            Circle()
                .fill(
                    LinearGradient(
                        colors: [Color.accentColor.opacity(0.85), Color.accentColor.opacity(0.45)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
            Text(VeilFormat.initials(for: handle))
                .font(.system(size: size * 0.38, weight: .semibold, design: .rounded))
                .foregroundStyle(.white)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

struct FingerprintBlock: View {
    let fingerprint: String
    var caption: String = "Порівняйте цей відбиток зі співрозмовником в іншому каналі."

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(VeilFormat.groupedFingerprint(fingerprint))
                .font(.system(.footnote, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(Color.secondary.opacity(0.12), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            Text(caption)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

struct ExperimentalFootnote: View {
    var body: some View {
        Text("Експериментальний MVP без аудиту криптографії. Не для продакшну.")
            .font(.caption2)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
    }
}
