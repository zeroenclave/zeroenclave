import Foundation
import ZeroEnclaveCore

/// Gate for new master passwords: minimum length and estimated strength.
struct PasswordPolicy {
    static let minLength = 12
    static let minScore = 3

    struct Evaluation: Equatable {
        let length: Int
        let score: Int

        var meetsLength: Bool { length >= PasswordPolicy.minLength }
        var meetsScore: Bool { score >= PasswordPolicy.minScore }
        var isAcceptable: Bool { meetsLength && meetsScore }
    }

    let scorer: (String) -> UInt8

    init(scorer: @escaping (String) -> UInt8 = { passwordStrength(pw: $0) }) {
        self.scorer = scorer
    }

    func evaluate(_ password: String) -> Evaluation {
        Evaluation(length: password.count, score: Int(min(scorer(password), 4)))
    }

    /// Both fields must match and the password must pass the gate.
    func canContinue(password: String, confirmation: String) -> Bool {
        password == confirmation && evaluate(password).isAcceptable
    }
}

/// State of the checklist shown while creating a password; mirrors `PasswordPolicy.canContinue`.
struct PasswordRequirements: Equatable {
    let hasMinLength: Bool
    let isStrongEnough: Bool
    let matches: Bool

    init(password: String, confirmation: String, policy: PasswordPolicy = PasswordPolicy()) {
        let evaluation = policy.evaluate(password)
        hasMinLength = evaluation.meetsLength
        isStrongEnough = evaluation.meetsScore
        matches = !confirmation.isEmpty && confirmation == password
    }

    var allMet: Bool { hasMinLength && isStrongEnough && matches }
}
