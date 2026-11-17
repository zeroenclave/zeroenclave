import Foundation
import Observation

/// Runs imports with bounded concurrency and reports progress.
@MainActor
@Observable
final class ImportCoordinator {
    struct Summary: Equatable {
        var imported = 0
        var failed = 0
        /// Photo library identifiers of the imported items.
        var assetIdentifiers: [String] = []
    }

    static let maxConcurrent = 3

    private enum Outcome: Sendable {
        case imported(assetIdentifier: String?, itemID: String)
        case failed
        case locked
        case cancelled
    }

    private(set) var isRunning = false
    private(set) var done = 0
    private(set) var total = 0
    var summary: Summary?

    @ObservationIgnored private let vault: VaultService
    @ObservationIgnored private let store: LibraryStore
    @ObservationIgnored private var task: Task<Void, Never>?

    init(vault: VaultService, store: LibraryStore) {
        self.vault = vault
        self.store = store
    }

    /// With `albumID`, every imported item is also added to that album.
    /// Without `reportSuccess`, the summary is only set if an item failed.
    func start(_ sources: [any ImportSource], albumID: String? = nil, reportSuccess: Bool = true) {
        guard !isRunning, !sources.isEmpty, case .unlocked(let handle) = vault.state else { return }
        isRunning = true
        done = 0
        total = sources.count
        summary = nil
        let pipeline = ImportPipeline(handle: handle)
        task = Task { [weak self] in
            await self?.run(sources, pipeline: pipeline, albumID: albumID, reportSuccess: reportSuccess)
        }
    }

    /// Aborts the running imports; items that were already committed stay.
    func cancel() {
        task?.cancel()
    }

    private func run(
        _ sources: [any ImportSource], pipeline: ImportPipeline, albumID: String?, reportSuccess: Bool
    ) async {
        var result = Summary()
        var lockedOut = false
        await withTaskGroup(of: Outcome.self) { group in
            var iterator = sources.makeIterator()
            var running = 0
            while running < Self.maxConcurrent, let source = iterator.next() {
                group.addTask { await Self.run(source, pipeline: pipeline) }
                running += 1
            }
            for await outcome in group {
                running -= 1
                switch outcome {
                case .imported(let identifier, let itemID):
                    result.imported += 1
                    if let identifier { result.assetIdentifiers.append(identifier) }
                    done += 1
                    if let albumID {
                        _ = await store.add(ids: [itemID], to: albumID)
                    } else {
                        await store.reload()
                    }
                case .failed:
                    result.failed += 1
                    done += 1
                case .locked:
                    lockedOut = true
                    group.cancelAll()
                case .cancelled:
                    break
                }
                if !lockedOut, !Task.isCancelled, let source = iterator.next() {
                    group.addTask { await Self.run(source, pipeline: pipeline) }
                    running += 1
                }
            }
        }
        isRunning = false
        task = nil
        if lockedOut {
            vault.noteImportCancelledByLock()
        } else if result.failed > 0 || (reportSuccess && result.imported > 0) {
            summary = result
        }
    }

    private nonisolated static func run(
        _ source: any ImportSource, pipeline: ImportPipeline
    ) async -> Outcome {
        do {
            let itemID = try await pipeline.importItem(source)
            return .imported(assetIdentifier: source.assetIdentifier, itemID: itemID)
        } catch ImportError.locked {
            return .locked
        } catch is CancellationError {
            return .cancelled
        } catch {
            return Task.isCancelled ? .cancelled : .failed
        }
    }
}
