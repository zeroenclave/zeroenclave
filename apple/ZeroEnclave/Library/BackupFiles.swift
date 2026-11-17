import Foundation
import ZeroEnclaveCore
import UniformTypeIdentifiers
import SwiftUI

extension UTType {
    /// Encrypted backup file; declared as an exported type in Info.plist.
    static let zeroEnclaveBackup = UTType(exportedAs: "com.zeroenclave.backup", conformingTo: .data)
}

/// Wraps an encrypted backup file on disk for `fileExporter`; the content is ciphertext only.
struct BackupDocument: FileDocument {
    static let readableContentTypes: [UTType] = [.zeroEnclaveBackup]

    let url: URL

    init(url: URL) { self.url = url }

    init(configuration: ReadConfiguration) throws {
        throw CocoaError(.fileReadUnsupportedScheme)
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        try FileWrapper(url: url, options: [])
    }
}

/// Temporary files of exports; everything lives below the app's tmp directory.
enum TemporaryFiles {
    private static let prefix = "ze-out-"

    /// A fresh directory for one exported file; the caller deletes it.
    static func makeDirectory() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appending(path: prefix + UUID().uuidString, directoryHint: .isDirectory)
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: false,
            attributes: [.protectionKey: FileProtectionType.complete])
        return dir
    }

    /// Removes the directory that contains `file`, if it was created by `makeDirectory`.
    static func remove(_ file: URL?) {
        guard let dir = file?.deletingLastPathComponent(),
            dir.lastPathComponent.hasPrefix(prefix)
        else { return }
        try? FileManager.default.removeItem(at: dir)
    }

    /// Drops leftovers of an earlier run that was killed mid-export.
    static func removeStale() {
        let tmp = FileManager.default.temporaryDirectory
        let entries = (try? FileManager.default.contentsOfDirectory(atPath: tmp.path)) ?? []
        for name in entries where name.hasPrefix(prefix) {
            try? FileManager.default.removeItem(at: tmp.appending(path: name))
        }
    }

    /// Strips path components and control characters from a file name.
    static func safeName(_ name: String?, fallback: String) -> String {
        let base = (name.map { ($0 as NSString).lastPathComponent } ?? "")
            .unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }
        let cleaned = String(String.UnicodeScalarView(base)).trimmingCharacters(in: .whitespaces)
        return cleaned.isEmpty || cleaned == "." || cleaned == ".." ? fallback : cleaned
    }
}

/// Progress callback of the core; may be called from any thread.
final class ClosureProgress: ProgressCallback, @unchecked Sendable {
    private let handler: @Sendable (UInt64, UInt64) -> Void
    init(_ handler: @escaping @Sendable (UInt64, UInt64) -> Void) { self.handler = handler }
    func progress(done: UInt64, total: UInt64) { handler(done, total) }
}

enum BackupName {
    /// `ZeroEnclave-Backup-YYYY-MM-DD`, without extension.
    static func defaultName(date: Date = .now) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd"
        return "ZeroEnclave-Backup-\(f.string(from: date))"
    }
}
