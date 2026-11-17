import SwiftUI
import UIKit

/// Home screen icons; the alternate ones are premium (`Feature.themes`).
enum AppIconChoice: CaseIterable, Identifiable {
    case standard, mint

    var id: Self { self }

    /// Key in `CFBundleAlternateIcons`; nil selects the primary icon.
    var alternateName: String? {
        switch self {
        case .standard: nil
        case .mint: "AppIconMint"
        }
    }

    /// In-app copy of the icon, shown by `AppMark`.
    var logoName: String {
        switch self {
        case .standard: "Logo"
        case .mint: "LogoMint"
        }
    }

    /// The Z alone, without the icon background; shown on the privacy cover.
    var markName: String {
        switch self {
        case .standard: "Mark"
        case .mint: "MarkMint"
        }
    }

    var title: LocalizedStringResource {
        switch self {
        case .standard: "Standard"
        case .mint: "Mint"
        }
    }

    var isPremium: Bool { self != .standard }

    /// The icon currently on the home screen.
    @MainActor static var current: AppIconChoice {
        let name = UIApplication.shared.alternateIconName
        return allCases.first { $0.alternateName == name } ?? .standard
    }
}
