import SwiftUI

extension View {
    /// Asks for the master password; `onVerified` runs only if it is correct.
    func masterPasswordPrompt(
        store: LibraryStore, isPresented: Binding<Bool>, message: LocalizedStringKey,
        onVerified: @escaping () -> Void
    ) -> some View {
        modifier(
            MasterPasswordPrompt(
                store: store, isPresented: isPresented, message: message, onVerified: onVerified))
    }
}

private struct MasterPasswordPrompt: ViewModifier {
    let store: LibraryStore
    @Binding var isPresented: Bool
    let message: LocalizedStringKey
    let onVerified: () -> Void

    func body(content: Content) -> some View {
        content.sheet(isPresented: $isPresented) {
            MasterPasswordSheet(store: store, message: message) {
                isPresented = false
                onVerified()
            }
        }
    }
}

/// Centered master password entry with the error shown inline.
private struct MasterPasswordSheet: View {
    let store: LibraryStore
    let message: LocalizedStringKey
    let onVerified: () -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var wrong = false
    @State private var checking = false
    @FocusState private var focused: Bool

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                Image(systemName: "key.fill")
                    .font(.largeTitle)
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
                Text(message)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                PasswordInput(
                    title: "Master password", text: $password, onSubmit: submit, focus: $focused)
                if wrong {
                    Notice("Wrong master password.")
                }
                Button(action: submit) {
                    Group {
                        if checking { ProgressView() } else { Text("Continue") }
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .foregroundStyle(Theme.onAccent)
                .controlSize(.large)
                .disabled(password.isEmpty || checking)
                Spacer(minLength: 0)
            }
            .padding(24)
            .frame(maxWidth: 420)
            .frame(maxWidth: .infinity)
            .navigationTitle("Master password")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.disabled(checking)
                }
            }
        }
        .presentationDetents([.medium, .large])
        .interactiveDismissDisabled(checking)
        .autoFocus($focused)
    }

    private func submit() {
        let entered = password
        guard !entered.isEmpty, !checking else { return }
        password = ""
        wrong = false
        checking = true
        Task {
            let ok = await store.verifyMasterPassword(entered)
            checking = false
            if ok { onVerified() } else { wrong = true; focused = true }
        }
    }
}

/// Shown instead of the album content until the code is entered.
struct AlbumLockedView: View {
    private enum Step { case code, recovered }

    let store: LibraryStore
    let album: LibraryAlbum

    @State private var step = Step.code
    @State private var code = ""
    @State private var wrongRemaining: Int?
    @State private var showPassword = false
    @State private var showNewCode = false
    @State private var failed = false
    @State private var shake = 0

    private var blocked: Bool { store.albumLock.isBlocked(album.id) }

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "lock.fill")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            switch step {
            case .code: codeStep
            case .recovered: recoveredStep
            }
        }
        .padding()
        .frame(maxWidth: 420)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .masterPasswordPrompt(
            store: store, isPresented: $showPassword,
            message: "Enter your master password to open this album or change its code."
        ) {
            step = .recovered
        }
        .sheet(isPresented: $showNewCode) {
            AlbumNewCodeSheet(store: store, albumID: album.id)
        }
        .alert("The album could not be changed.", isPresented: $failed) {
            Button("OK") {}
        }
    }

    @ViewBuilder
    private var codeStep: some View {
        VStack(spacing: 6) {
            Text("Enter code").font(.headline)
            Text(album.name).font(.subheadline).foregroundStyle(.secondary)
        }
        if blocked {
            Notice("Too many wrong codes. Unlock the vault again to retry, or use your master password.")
                .multilineTextAlignment(.center)
            Button(action: askPassword) {
                Text("Use master password").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            .foregroundStyle(Theme.onAccent)
            .controlSize(.large)
        } else {
            PinPad(pin: $code, length: AlbumCode.length, shake: shake) { _ in submit() }
            // Reserves the line so the layout does not jump on a wrong code.
            Group {
                if let wrongRemaining {
                    Notice("Wrong code. \(wrongRemaining) attempts left.")
                } else {
                    Text(verbatim: " ").font(.footnote).accessibilityHidden(true)
                }
            }
            Button("Forgot code? Use master password", action: askPassword)
                .font(.subheadline)
        }
    }

    @ViewBuilder
    private var recoveredStep: some View {
        Text("Master password confirmed").font(.headline)
        VStack(spacing: 12) {
            Button { store.albumLock.grant(album.id) } label: {
                Text("View album").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            .foregroundStyle(Theme.onAccent)
            .controlSize(.large)
            Button { showNewCode = true } label: {
                Text("Set new code").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glass)
            .controlSize(.large)
            Button("Remove code", role: .destructive) {
                Task { if await !store.setAlbumCode(id: album.id, nil) { failed = true } }
            }
            .padding(.top, 4)
        }
    }

    private func askPassword() {
        showPassword = true
    }

    private func submit() {
        let entered = code
        code = ""
        Task {
            switch await store.unlockAlbum(id: album.id, code: entered) {
            case .opened: wrongRemaining = nil
            case .wrong(let remaining):
                wrongRemaining = remaining
                shake += 1
            case .blocked: wrongRemaining = nil
            }
        }
    }
}
