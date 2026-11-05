import Foundation
import Darwin

/// File storage for the sealed vault blob.
///
/// - Lives in `Application Support/Veil/vault.bin` (never Documents, never
///   Caches, never a shared container).
/// - Directory and file get `FileProtectionType.complete` and are excluded from
///   iCloud/iTunes backups, so a stolen locked device or a backup copy does not
///   expose the blob.
/// - Writes are atomic: the previous blob stays intact until the new one is
///   fully written, and the AES-GCM header authenticates the content.
final class FileVaultStore: VaultFileStoring {

    static let directoryName = "Veil"
    static let fileName = "vault.bin"

    let directoryURL: URL
    let fileURL: URL

    init(directoryURL: URL? = nil) throws {
        let resolvedDirectory: URL
        if let directoryURL {
            resolvedDirectory = directoryURL
        } else {
            let fileManager = FileManager.default
            let support: URL
            do {
                support = try fileManager.url(
                    for: .applicationSupportDirectory,
                    in: .userDomainMask,
                    appropriateFor: nil,
                    create: true
                )
            } catch {
                throw VeilStorageError.readFailed("каталог Application Support недоступний")
            }
            resolvedDirectory = support.appendingPathComponent(Self.directoryName, isDirectory: true)
        }

        self.directoryURL = resolvedDirectory
        self.fileURL = resolvedDirectory.appendingPathComponent(Self.fileName, isDirectory: false)

        try Self.prepareDirectory(resolvedDirectory)
    }

    // MARK: - VaultFileStoring

    func readEncryptedData() throws -> Data? {
        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: fileURL.path) else { return nil }
        do {
            return try Data(contentsOf: fileURL)
        } catch {
            throw VeilStorageError.readFailed("файл сховища не читається")
        }
    }

    func writeEncryptedData(_ data: Data) throws {
        let temporary = directoryURL.appendingPathComponent(".vault-\(UUID().uuidString).tmp")
        defer { try? FileManager.default.removeItem(at: temporary) }
        do {
            try data.write(to: temporary, options: [.withoutOverwriting, .completeFileProtection])
            let handle = try FileHandle(forWritingTo: temporary)
            do {
                try handle.synchronize()
                try handle.close()
            } catch {
                try? handle.close()
                throw error
            }
            let renamed = temporary.path.withCString { source in
                fileURL.path.withCString { destination in Darwin.rename(source, destination) }
            }
            guard renamed == 0 else {
                throw VeilStorageError.writeFailed("атомарна заміна файлу сховища")
            }
        } catch {
            throw VeilStorageError.writeFailed("атомарний запис файлу сховища")
        }
        // Rename is the commit point. Never throw after it: that would roll
        // memory back while the new ratchet is already on disk. Backup exclusion
        // is enforced on the containing directory before any write.
        try? Self.excludeFromBackup(fileURL)
        let directoryFD = Darwin.open(directoryURL.path, O_RDONLY)
        if directoryFD >= 0 {
            _ = Darwin.fsync(directoryFD)
            _ = Darwin.close(directoryFD)
        }
    }

    // MARK: - Private

    private static func prepareDirectory(_ url: URL) throws {
        let fileManager = FileManager.default
        var isDirectory: ObjCBool = false

        if fileManager.fileExists(atPath: url.path, isDirectory: &isDirectory) {
            guard isDirectory.boolValue else {
                throw VeilStorageError.readFailed("шлях сховища зайнятий не каталогом")
            }
        } else {
            do {
                try fileManager.createDirectory(
                    at: url,
                    withIntermediateDirectories: true,
                    attributes: [.protectionKey: FileProtectionType.complete]
                )
            } catch {
                throw VeilStorageError.readFailed("каталог сховища не створюється")
            }
        }

        do {
            try applyProtection(to: url)
            try excludeFromBackup(url)
        } catch {
            throw VeilStorageError.writeFailed("не вдалося захистити каталог і виключити його з резервних копій")
        }
    }

    private static func applyProtection(to url: URL) throws {
        try FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.complete],
            ofItemAtPath: url.path
        )
    }

    private static func excludeFromBackup(_ url: URL) throws {
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutableURL = url
        try mutableURL.setResourceValues(values)
    }
}
