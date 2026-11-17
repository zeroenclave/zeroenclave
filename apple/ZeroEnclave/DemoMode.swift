#if DEBUG
    import SwiftUI
    import UIKit
    import UniformTypeIdentifiers
    import ZeroEnclaveCore

    /// Debug-only demo vault for simulator screenshots: `-ZEDemo` creates or opens a vault with demo
    /// photos, `-ZEDemoScreen <photos|albums|trash|settings|encryption|viewer|locked>` picks the screen.
    /// Not compiled into release builds.
    enum DemoMode {
        static var isRequested: Bool { ProcessInfo.processInfo.arguments.contains("-ZEDemo") }
        static var screen: String? { UserDefaults.standard.string(forKey: "ZEDemoScreen") }

        /// Synthetic password of the demo vault; never used for real data.
        static let password = "demo vault passphrase for screenshots"

        @MainActor static func prepare(vault: VaultService, entitlements: Entitlements) async {
            entitlements.activatePreRelease()
            switch vault.state {
            case .noVault:
                vault.beginOnboarding()
                guard await vault.createVault(password: password) == nil else { return }
                vault.acknowledgeRecoveryKey()
                vault.finishOnboarding()
                guard case .unlocked(let handle) = vault.state else { return }
                await seed(handle)
                // Reopen so the gallery loads the seeded library.
                vault.lock()
                if screen != "locked" { _ = await vault.unlock(password: password) }
            case .locked:
                if screen != "locked" { _ = await vault.unlock(password: password) }
            default:
                break
            }
        }

        private static var german: Bool { Locale.current.language.languageCode?.identifier == "de" }

        /// Folder with real demo photos in subfolders per album (`-ZEDemoPhotos <path>`, read from
        /// the Mac by the simulator). Without it, generated pictures are used.
        private static var photosFolder: URL? {
            UserDefaults.standard.string(forKey: "ZEDemoPhotos").map { URL(filePath: $0, directoryHint: .isDirectory) }
        }

        private static let albumNames: [String: (de: String, en: String)] = [
            "travel": ("Reisen", "Travel"), "nature": ("Natur", "Nature"),
            "food": ("Essen", "Food"), "pets": ("Haustiere", "Pets"),
        ]

        private static func seed(_ handle: VaultHandle) async {
            let pipeline = ImportPipeline(handle: handle)
            var albums: [String: [String]] = [:]
            if let folder = photosFolder {
                let fm = FileManager.default
                let groups = ((try? fm.contentsOfDirectory(atPath: folder.path)) ?? []).sorted()
                var queues = groups.map { group in
                    ((try? fm.contentsOfDirectory(atPath: folder.appending(path: group).path)) ?? [])
                        .filter { $0.lowercased().hasSuffix(".jpg") }.sorted()
                        .map { (group, folder.appending(path: group).appending(path: $0)) }
                }
                // Interleave the groups so the first screen of All Photos shows a mix.
                while queues.contains(where: { !$0.isEmpty }) {
                    for index in queues.indices where !queues[index].isEmpty {
                        let (group, url) = queues[index].removeFirst()
                        if let id = try? await pipeline.importItem(FileImportSource(url: url)) {
                            albums[group, default: []].append(id)
                        }
                    }
                }
            } else {
                for index in 0..<24 {
                    let image = DemoPicture.render(seed: index)
                    if let id = try? await pipeline.importItem(CameraImportSource(.photo(image))) {
                        albums[index < 12 ? "travel" : "nature", default: []].append(id)
                    }
                }
            }
            for (group, ids) in albums.sorted(by: { $0.key < $1.key }) {
                let names = albumNames[group] ?? (group, group)
                guard let id = try? handle.createAlbum(name: german ? names.de : names.en) else { continue }
                try? handle.addToAlbum(albumId: id, itemIds: ids)
            }
            // A locked album shows the code feature; its content is the first travel photos.
            if let travel = albums["travel"], travel.count > 3,
                let id = try? handle.createAlbum(name: german ? "Privat" : "Private")
            {
                try? handle.addToAlbum(albumId: id, itemIds: Array(travel.prefix(3)))
                try? handle.setAlbumPin(albumId: id, code: "4826")
            }
        }
    }

    /// A demo photo file on disk; read in place, never moved or deleted.
    struct FileImportSource: ImportSource {
        let url: URL
        var suggestedName: String? { url.lastPathComponent }
        var assetIdentifier: String? { nil }
        func withFile<T: Sendable>(_ body: @escaping @Sendable (URL, UTType) async throws -> T) async throws -> T {
            try await body(url, .jpeg)
        }
    }

    /// Generated landscape pictures: sky gradient, sun and layered hills. No real photos.
    enum DemoPicture {
        private static let palettes: [[UIColor]] = [
            [#colorLiteral(red: 0.98, green: 0.62, blue: 0.36, alpha: 1), #colorLiteral(red: 0.72, green: 0.25, blue: 0.4, alpha: 1), #colorLiteral(red: 0.35, green: 0.16, blue: 0.36, alpha: 1), #colorLiteral(red: 0.2, green: 0.1, blue: 0.25, alpha: 1)],
            [#colorLiteral(red: 0.55, green: 0.8, blue: 0.97, alpha: 1), #colorLiteral(red: 0.92, green: 0.95, blue: 0.98, alpha: 1), #colorLiteral(red: 0.36, green: 0.55, blue: 0.68, alpha: 1), #colorLiteral(red: 0.18, green: 0.32, blue: 0.42, alpha: 1)],
            [#colorLiteral(red: 0.99, green: 0.85, blue: 0.55, alpha: 1), #colorLiteral(red: 0.98, green: 0.66, blue: 0.42, alpha: 1), #colorLiteral(red: 0.42, green: 0.55, blue: 0.4, alpha: 1), #colorLiteral(red: 0.2, green: 0.33, blue: 0.27, alpha: 1)],
            [#colorLiteral(red: 0.1, green: 0.13, blue: 0.3, alpha: 1), #colorLiteral(red: 0.36, green: 0.29, blue: 0.6, alpha: 1), #colorLiteral(red: 0.2, green: 0.2, blue: 0.4, alpha: 1), #colorLiteral(red: 0.08, green: 0.08, blue: 0.18, alpha: 1)],
            [#colorLiteral(red: 0.67, green: 0.9, blue: 0.86, alpha: 1), #colorLiteral(red: 0.95, green: 0.97, blue: 0.9, alpha: 1), #colorLiteral(red: 0.24, green: 0.62, blue: 0.52, alpha: 1), #colorLiteral(red: 0.08, green: 0.36, blue: 0.32, alpha: 1)],
            [#colorLiteral(red: 1, green: 0.74, blue: 0.68, alpha: 1), #colorLiteral(red: 1, green: 0.9, blue: 0.75, alpha: 1), #colorLiteral(red: 0.62, green: 0.42, blue: 0.5, alpha: 1), #colorLiteral(red: 0.33, green: 0.22, blue: 0.33, alpha: 1)],
            [#colorLiteral(red: 0.74, green: 0.86, blue: 1, alpha: 1), #colorLiteral(red: 1, green: 0.96, blue: 0.86, alpha: 1), #colorLiteral(red: 0.5, green: 0.6, blue: 0.72, alpha: 1), #colorLiteral(red: 0.27, green: 0.33, blue: 0.45, alpha: 1)],
            [#colorLiteral(red: 0.98, green: 0.78, blue: 0.4, alpha: 1), #colorLiteral(red: 0.93, green: 0.45, blue: 0.27, alpha: 1), #colorLiteral(red: 0.55, green: 0.3, blue: 0.22, alpha: 1), #colorLiteral(red: 0.28, green: 0.14, blue: 0.12, alpha: 1)],
        ]

        static func render(seed: Int) -> UIImage {
            var rng = SplitMix(seed: UInt64(seed) &* 0x9E37_79B9 &+ 17)
            let portrait = seed % 3 == 1
            let size = portrait ? CGSize(width: 1200, height: 1600) : CGSize(width: 1600, height: 1200)
            let colors = palettes[seed % palettes.count]
            let format = UIGraphicsImageRendererFormat()
            format.scale = 1
            return UIGraphicsImageRenderer(size: size, format: format).image { context in
                let cg = context.cgContext
                let sky = CGGradient(
                    colorsSpace: CGColorSpaceCreateDeviceRGB(),
                    colors: [colors[0].cgColor, colors[1].cgColor] as CFArray, locations: [0, 1])!
                cg.drawLinearGradient(
                    sky, start: .zero, end: CGPoint(x: 0, y: size.height * 0.7), options: [.drawsAfterEndLocation])
                let sun = CGPoint(x: size.width * rng.next(0.2, 0.8), y: size.height * rng.next(0.18, 0.42))
                let radius = size.width * rng.next(0.06, 0.12)
                cg.setFillColor(UIColor.white.withAlphaComponent(0.75).cgColor)
                cg.fillEllipse(in: CGRect(x: sun.x - radius, y: sun.y - radius, width: radius * 2, height: radius * 2))
                for layer in 0..<3 {
                    let base = size.height * (0.55 + CGFloat(layer) * 0.13)
                    let color = blend(colors[2], colors[3], CGFloat(layer) / 2)
                    let path = UIBezierPath()
                    path.move(to: CGPoint(x: 0, y: size.height))
                    var x: CGFloat = 0
                    path.addLine(to: CGPoint(x: 0, y: base))
                    while x < size.width {
                        let step = size.width * rng.next(0.08, 0.18)
                        let peak = base - size.height * rng.next(0.02, 0.16)
                        path.addQuadCurve(
                            to: CGPoint(x: x + step, y: base - size.height * rng.next(0, 0.05)),
                            controlPoint: CGPoint(x: x + step / 2, y: peak))
                        x += step
                    }
                    path.addLine(to: CGPoint(x: size.width, y: size.height))
                    path.close()
                    color.setFill()
                    path.fill()
                }
            }
        }

        private static func blend(_ a: UIColor, _ b: UIColor, _ t: CGFloat) -> UIColor {
            var (r1, g1, b1, a1, r2, g2, b2, a2): (CGFloat, CGFloat, CGFloat, CGFloat, CGFloat, CGFloat, CGFloat, CGFloat) =
                (0, 0, 0, 0, 0, 0, 0, 0)
            a.getRed(&r1, green: &g1, blue: &b1, alpha: &a1)
            b.getRed(&r2, green: &g2, blue: &b2, alpha: &a2)
            return UIColor(red: r1 + (r2 - r1) * t, green: g1 + (g2 - g1) * t, blue: b1 + (b2 - b1) * t, alpha: 1)
        }
    }

    /// Small deterministic generator so the demo pictures look the same on every run.
    struct SplitMix {
        private var state: UInt64
        init(seed: UInt64) { state = seed }
        mutating func next(_ low: CGFloat, _ high: CGFloat) -> CGFloat {
            state &+= 0x9E37_79B9_7F4A_7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            z ^= z >> 31
            return low + (high - low) * CGFloat(Double(z >> 11) / Double(1 << 53))
        }
    }
#endif
