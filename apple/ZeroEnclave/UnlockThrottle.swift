import Foundation

/// UX-only delay after repeated wrong passwords. Argon2 is the actual protection.
struct UnlockThrottle {
    static let freeAttempts = 5
    static let baseDelay: TimeInterval = 5
    static let maxDelay: TimeInterval = 300

    private(set) var failures = 0
    private(set) var blockedUntil: Date?

    /// Delay applied after the given number of consecutive failures.
    static func delay(afterFailures n: Int) -> TimeInterval {
        guard n >= freeAttempts else { return 0 }
        let steps = min(n - freeAttempts, 16)
        return min(baseDelay * pow(2, Double(steps)), maxDelay)
    }

    mutating func recordFailure(now: Date = .now) {
        failures += 1
        let delay = Self.delay(afterFailures: failures)
        blockedUntil = delay > 0 ? now.addingTimeInterval(delay) : nil
    }

    mutating func reset() {
        failures = 0
        blockedUntil = nil
    }

    /// Seconds left until the next attempt is allowed.
    func remaining(now: Date = .now) -> TimeInterval {
        max(0, blockedUntil?.timeIntervalSince(now) ?? 0)
    }
}
