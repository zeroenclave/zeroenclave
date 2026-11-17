import Foundation
import Observation

/// Rules for the four-digit album view-lock code.
enum AlbumCode {
    static let length = 4

    /// Keeps only the leading ASCII digits, at most `length`.
    static func sanitized(_ raw: String) -> String {
        String(raw.filter { $0.isASCII && $0.isNumber }.prefix(length))
    }

    static func isValid(_ code: String) -> Bool {
        code.count == length && code.allSatisfy { $0.isASCII && $0.isNumber }
    }

    /// A valid code that was entered twice identically.
    static func matches(_ code: String, _ confirmation: String) -> Bool {
        isValid(code) && code == confirmation
    }
}

enum AlbumUnlockResult: Equatable {
    case opened
    case wrong(remaining: Int)
    case blocked
}

/// Which locked albums are open right now and how often a wrong code was entered.
/// Memory only: it lives as long as the store, so a new unlock starts from scratch.
@MainActor
@Observable
final class AlbumLock {
    static let maxAttempts = 5

    private(set) var openIDs: Set<String> = []
    private var failures: [String: Int] = [:]

    func isOpen(_ id: String) -> Bool { openIDs.contains(id) }

    func isBlocked(_ id: String) -> Bool { failures[id, default: 0] >= Self.maxAttempts }

    func remainingAttempts(_ id: String) -> Int {
        max(0, Self.maxAttempts - failures[id, default: 0])
    }

    /// Counts a wrong code.
    func recordFailure(_ id: String) -> AlbumUnlockResult {
        failures[id, default: 0] += 1
        return isBlocked(id) ? .blocked : .wrong(remaining: remainingAttempts(id))
    }

    /// Opens the album and clears its failure counter.
    func grant(_ id: String) {
        failures[id] = nil
        openIDs.insert(id)
    }

    /// Closes the album again, e.g. when it is left.
    func close(_ id: String) {
        openIDs.remove(id)
    }

    /// Drops all state of an album whose lock was removed or that was deleted.
    func forget(_ id: String) {
        openIDs.remove(id)
        failures[id] = nil
    }
}
