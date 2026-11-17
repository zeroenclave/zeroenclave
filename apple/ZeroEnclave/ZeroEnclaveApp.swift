import SwiftUI

@main
struct ZeroEnclaveApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var vault = VaultService()
    @State private var entitlements: Entitlements = {
        #if DEBUG
            PreReleaseSource.resetIfRequested()
        #endif
        return Entitlements()
    }()

    var body: some Scene {
        WindowGroup {
            #if DEBUG
                if ProcessInfo.processInfo.arguments.contains("-ze-lab") {
                    SecureLabView()
                } else {
                    RootView(vault: vault)
                        .environment(entitlements)
                        .task {
                            await entitlements.refreshDownloadDate()
                            if DemoMode.isRequested { await DemoMode.prepare(vault: vault, entitlements: entitlements) }
                        }
                }
            #else
                RootView(vault: vault)
                    .environment(entitlements)
                    .task { await entitlements.refreshDownloadDate() }
            #endif
        }
    }
}
