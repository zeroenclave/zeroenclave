import UIKit

/// Opaque cover that shows only the Z mark; used for the app switcher snapshot.
final class PrivacyViewController: UIViewController {
    let logoView = UIImageView()

    override func viewDidLoad() {
        super.viewDidLoad()
        // Dynamic color and asset: the system snapshots in light and dark, each shows only the cover.
        view.backgroundColor = .systemBackground
        logoView.contentMode = .scaleAspectFit
        logoView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(logoView)
        NSLayoutConstraint.activate([
            logoView.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            logoView.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            logoView.widthAnchor.constraint(equalToConstant: AppMark.coverSize),
            logoView.heightAnchor.constraint(equalToConstant: AppMark.coverSize),
        ])
        view.isAccessibilityElement = false
        updateLogo()
    }

    /// Follows the selected home screen icon.
    func updateLogo() {
        logoView.image = UIImage(named: AppIconChoice.current.markName)
    }
}

/// Dedicated window above everything else, shown synchronously when the scene resigns active.
@MainActor
final class PrivacyWindowController {
    private(set) var window: UIWindow?

    var isVisible: Bool { window.map { !$0.isHidden } ?? false }

    /// Creates the hidden window and loads its view, so showing it later is only `isHidden = false`.
    func prepare(in scene: UIWindowScene?) {
        if window == nil {
            let created = scene.map { UIWindow(windowScene: $0) } ?? UIWindow()
            created.windowLevel = UIWindow.Level.alert + 1
            let controller = PrivacyViewController()
            created.rootViewController = controller
            controller.loadViewIfNeeded()
            created.isHidden = true
            window = created
        }
        if let scene, window?.windowScene !== scene { window?.windowScene = scene }
        (window?.rootViewController as? PrivacyViewController)?.updateLogo()
    }

    /// False while the vault is locked: the unlock screen shows nothing private, and covering
    /// it would flash during the Face ID prompt (which makes the scene resign active).
    static var isNeeded = true

    /// Source of `isNeeded`; tests pass their own instead of the shared app state.
    private let needsCover: @MainActor () -> Bool

    init(needsCover: @escaping @MainActor () -> Bool = { PrivacyWindowController.isNeeded }) {
        self.needsCover = needsCover
    }

    /// Idempotent.
    func show(in scene: UIWindowScene?) {
        generation += 1
        guard needsCover() else {
            // Locked: nothing private on screen; drop a cover left over from before the lock.
            window?.isHidden = true
            return
        }
        prepare(in: scene)
        window?.isHidden = false
        // Layer order, not windowLevel, decides compositing once other windows were reparented
        // into secure layers; keep the cover on top and commit it before the system snapshots.
        if let layer = window?.layer {
            layer.zPosition = .greatestFiniteMagnitude
            layer.superlayer?.addSublayer(layer)
        }
        CATransaction.flush()
    }

    /// Bumped by every `show`; a pending hide only runs if no show happened in between.
    private var generation = 0

    /// `didBecomeActive` can arrive late, after a quick swipe has already put the app back into
    /// the app switcher. Hide only if the scene is still active a moment later and no new
    /// resign happened meanwhile.
    func hideWhenSettled(_ scene: UIScene) {
        // Locked: nothing private behind the cover, show the unlock screen right away.
        guard needsCover() else { return hide() }
        let expected = generation
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { [weak self, weak scene] in
            MainActor.assumeIsolated {
                guard let self, self.generation == expected,
                    scene?.activationState == .foregroundActive
                else { return }
                self.hide()
            }
        }
    }

    func hide() {
        window?.isHidden = true
    }
}

/// Removes the system's app-switcher snapshots from the app container (best effort).
enum SnapshotCleaner {
    static func removeSnapshots(in library: URL = .libraryDirectory) {
        let snapshots = library.appending(path: "SplashBoard/Snapshots", directoryHint: .isDirectory)
        try? FileManager.default.removeItem(at: snapshots)
    }
}

final class SceneDelegate: NSObject, UIWindowSceneDelegate {
    private let privacy = MainActor.assumeIsolated { PrivacyWindowController() }

    func scene(
        _ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions
    ) {
        let windowScene = scene as? UIWindowScene
        MainActor.assumeIsolated { privacy.prepare(in: windowScene) }
        // Second trigger: the application-level notification fires synchronously on resign as well.
        // Weak capture: the observer goes inert with the delegate.
        NotificationCenter.default.addObserver(
            forName: UIApplication.willResignActiveNotification, object: nil, queue: .main
        ) { [weak self, weak windowScene] _ in
            MainActor.assumeIsolated { self?.privacy.show(in: windowScene) }
        }
    }

    func sceneWillResignActive(_ scene: UIScene) {
        MainActor.assumeIsolated { privacy.show(in: scene as? UIWindowScene) }
    }

    func sceneDidEnterBackground(_ scene: UIScene) {
        // The privacy window is already visible; drop stored snapshots and skip the next one.
        SnapshotCleaner.removeSnapshots()
        UIApplication.shared.ignoreSnapshotOnNextApplicationLaunch()
    }

    func sceneDidBecomeActive(_ scene: UIScene) {
        MainActor.assumeIsolated {
            privacy.hideWhenSettled(scene)
        }
    }
}

final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        SnapshotCleaner.removeSnapshots()
        TemporaryFiles.removeStale()
        CameraImportSource.removeStale()
        #if DEBUG
            // Test aid: start without pre-release premium.
            if ProcessInfo.processInfo.arguments.contains("-ze-reset-premium") {
                UserDefaults.standard.removeObject(forKey: PreReleaseSource.defaultsKey)
            }
        #endif
        return true
    }

    // No UIKit state restoration: nothing of the app may land in Saved Application State.
    func application(_ application: UIApplication, shouldSaveSecureApplicationState coder: NSCoder) -> Bool {
        false
    }

    func application(_ application: UIApplication, shouldRestoreSecureApplicationState coder: NSCoder) -> Bool {
        false
    }

    func application(
        _ application: UIApplication, configurationForConnecting connectingSceneSession: UISceneSession,
        options: UIScene.ConnectionOptions
    ) -> UISceneConfiguration {
        Self.sceneConfiguration(role: connectingSceneSession.role)
    }

    /// Without `delegateClass` the SwiftUI lifecycle never creates the privacy window.
    static func sceneConfiguration(role: UISceneSession.Role) -> UISceneConfiguration {
        let configuration = UISceneConfiguration(name: nil, sessionRole: role)
        configuration.delegateClass = SceneDelegate.self
        return configuration
    }
}
