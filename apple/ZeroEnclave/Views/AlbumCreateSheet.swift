import SwiftUI

/// Creates an open or a locked album; the layout is centered.
struct AlbumCreateSheet: View {
    private enum Kind: Hashable { case open, locked }

    let store: LibraryStore
    var onCreated: (String) -> Void = { _ in }

    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var kind = Kind.open
    @State private var showCode = false
    @State private var working = false
    @State private var failed = false
    @FocusState private var nameFocused: Bool

    private var canContinue: Bool {
        !working && AlbumName.validated(name) != nil
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 24) {
                    TextField("Album name", text: $name)
                        .focused($nameFocused)
                        .multilineTextAlignment(.center)
                        .submitLabel(.done)
                        .inputFieldContainer()
                    Picker("Album type", selection: $kind) {
                        Text("Open").tag(Kind.open)
                        Text("Locked").tag(Kind.locked)
                    }
                    .pickerStyle(.segmented)
                    Group {
                        if kind == .locked {
                            Text("You choose a four-digit code on the next page.")
                        } else {
                            Text("Open albums need no code. Photos in them also appear in All Photos.")
                        }
                    }
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                }
                .padding()
                .frame(maxWidth: 420)
                .frame(maxWidth: .infinity)
            }
            .navigationTitle("New album")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    // A locked album gets its code on the next page.
                    if kind == .locked {
                        Button("Next") { showCode = true }.disabled(!canContinue)
                    } else {
                        Button("Create") { Task { _ = await create(code: nil) } }.disabled(!canContinue)
                    }
                }
            }
            .navigationDestination(isPresented: $showCode) {
                AlbumCodeFlow(context: AlbumName.validated(name)) { code in await create(code: code) }
            }
            .alert("The album could not be created.", isPresented: $failed) {
                Button("OK") {}
            }
        }
        .presentationDetents(kind == .locked ? [.large] : [.medium, .large])
        .autoFocus($nameFocused)
        .interactiveDismissDisabled(working)
    }

    private func create(code: String?) async -> Bool {
        working = true
        defer { working = false }
        guard let id = await store.createAlbum(named: name, code: code) else {
            if code == nil { failed = true }
            return false
        }
        onCreated(id)
        dismiss()
        return true
    }
}
