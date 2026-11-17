import Foundation
import Testing
import UIKit

@testable import ZeroEnclave

struct PasswordPolicyTests {
    private func policy(score: UInt8) -> PasswordPolicy {
        PasswordPolicy(scorer: { _ in score })
    }

    @Test func requiresLengthAndScore() {
        #expect(policy(score: 4).evaluate("short").isAcceptable == false)
        #expect(policy(score: 2).evaluate(String(repeating: "a", count: 20)).isAcceptable == false)
        #expect(policy(score: 3).evaluate(String(repeating: "a", count: 12)).isAcceptable)
        #expect(policy(score: 3).evaluate(String(repeating: "a", count: 11)).isAcceptable == false)
    }

    @Test func confirmationMustMatch() {
        let pw = String(repeating: "a", count: 14)
        #expect(policy(score: 4).canContinue(password: pw, confirmation: pw))
        #expect(!policy(score: 4).canContinue(password: pw, confirmation: pw + "b"))
    }

    @Test func realScorerRejectsCommonPassword() {
        let weak = PasswordPolicy().evaluate("passwordpassword")
        #expect(!weak.isAcceptable)
        let strong = PasswordPolicy().evaluate("glacier lantern velvet orchard mosaic")
        #expect(strong.isAcceptable)
    }
}

struct PasswordRequirementsTests {
    private func requirements(_ password: String, _ confirmation: String, score: UInt8) -> PasswordRequirements {
        PasswordRequirements(
            password: password, confirmation: confirmation, policy: PasswordPolicy(scorer: { _ in score }))
    }

    @Test func tracksEachRule() {
        let long = String(repeating: "a", count: 12)
        let empty = requirements("", "", score: 0)
        #expect(!empty.hasMinLength && !empty.isStrongEnough && !empty.matches)
        let short = requirements("abc", "abc", score: 4)
        #expect(!short.hasMinLength && short.isStrongEnough && short.matches)
        let weak = requirements(long, "", score: 2)
        #expect(weak.hasMinLength && !weak.isStrongEnough && !weak.matches)
        #expect(!requirements(long, long + "b", score: 4).matches)
    }

    @Test func allMetEqualsPolicyCanContinue() {
        let long = String(repeating: "a", count: 12)
        for score: UInt8 in [0, 2, 3, 4] {
            for (password, confirmation) in [(long, long), (long, ""), ("abc", "abc"), (long, long + "b")] {
                let policy = PasswordPolicy(scorer: { _ in score })
                #expect(
                    requirements(password, confirmation, score: score).allMet
                        == policy.canContinue(password: password, confirmation: confirmation))
            }
        }
    }
}

struct UnlockThrottleTests {
    @Test func noDelayForFirstFailures() {
        var throttle = UnlockThrottle()
        let now = Date(timeIntervalSince1970: 1_000)
        for _ in 0..<4 { throttle.recordFailure(now: now) }
        #expect(throttle.remaining(now: now) == 0)
    }

    @Test func delayGrowsAndIsCapped() {
        #expect(UnlockThrottle.delay(afterFailures: 5) == 5)
        #expect(UnlockThrottle.delay(afterFailures: 6) == 10)
        #expect(UnlockThrottle.delay(afterFailures: 7) == 20)
        #expect(UnlockThrottle.delay(afterFailures: 100) == UnlockThrottle.maxDelay)
    }

    @Test func blocksUntilDelayPassedAndResets() {
        var throttle = UnlockThrottle()
        let now = Date(timeIntervalSince1970: 1_000)
        for _ in 0..<5 { throttle.recordFailure(now: now) }
        #expect(throttle.remaining(now: now) == 5)
        #expect(throttle.remaining(now: now.addingTimeInterval(6)) == 0)
        throttle.reset()
        #expect(throttle.failures == 0 && throttle.remaining(now: now) == 0)
    }
}

@MainActor
struct RecoveryKeyCopyTests {
    @Test func copiesKeyToPasteboard() throws {
        let pasteboard = try #require(UIPasteboard(name: .init("ze-test-\(UUID().uuidString)"), create: true))
        defer { UIPasteboard.remove(withName: pasteboard.name) }
        RecoveryKeyView.copyToClipboard("ABCD-EFGH", pasteboard: pasteboard)
        #expect(pasteboard.string == "ABCD-EFGH")
        #expect(RecoveryKeyView.clipboardLifetime <= 120)
    }
}

struct DuressSetupGateTests {
    private func gate(score: UInt8) -> DuressSetupGate {
        DuressSetupGate(policy: PasswordPolicy(scorer: { _ in score }))
    }

    private func canSet(_ gate: DuressSetupGate, _ password: String, _ confirmation: String? = nil) -> Bool {
        gate.canSet(
            understood: true, password: password, confirmation: confirmation ?? password,
            isWorking: false, entitled: true)
    }

    @Test func requiresLengthAndScore() {
        let long = String(repeating: "a", count: 12)
        #expect(canSet(gate(score: 3), long))
        #expect(!canSet(gate(score: 4), String(repeating: "a", count: 11)))
        #expect(!canSet(gate(score: 2), long))
        #expect(!canSet(gate(score: 4), ""))
    }

    @Test func requiresMatchAcknowledgementAndEntitlement() {
        let long = String(repeating: "a", count: 14)
        #expect(!canSet(gate(score: 4), long, long + "b"))
        let g = gate(score: 4)
        #expect(!g.canSet(understood: false, password: long, confirmation: long, isWorking: false, entitled: true))
        #expect(!g.canSet(understood: true, password: long, confirmation: long, isWorking: true, entitled: true))
        #expect(!g.canSet(understood: true, password: long, confirmation: long, isWorking: false, entitled: false))
    }
}
