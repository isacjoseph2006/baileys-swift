import Foundation

/// Mirrors Baileys' `SignalDataTypeMap` bucket names (`src/Types/Auth.ts`).
/// Values are stored as opaque `Data` here — typed (de)serialization for
/// each bucket lands with the Signal session engine in a later phase; only
/// the bucket *names* matter for now so the on-disk layout doesn't need to
/// change shape later.
public enum SignalDataType: String, Codable {
    case preKey = "pre-key"
    case session
    case senderKey = "sender-key"
    case senderKeyMemory = "sender-key-memory"
    case appStateSyncKey = "app-state-sync-key"
    case appStateSyncVersion = "app-state-sync-version"
    case lidMapping = "lid-mapping"
    case deviceList = "device-list"
    case tcToken = "tctoken"
    case identityKey = "identity-key"
}

/// Mirrors Baileys' `SignalKeyStore` interface (`src/Types/Auth.ts`): a
/// keyed store of opaque per-(type, id) blobs.
public protocol SignalKeyStore: AnyObject {
    func get(_ type: SignalDataType, ids: [String]) async throws -> [String: Data]
    func set(_ type: SignalDataType, id: String, value: Data?) async throws
    func clear() async throws
}

/// File-backed `SignalKeyStore`: one file per `(type, id)` pair under
/// `keys/<type>/<id>`, mirroring the shape (if not the exact file-per-entry
/// mechanics) of Baileys' reference `use-multi-file-auth-state.ts` store.
public final class FileSignalKeyStore: SignalKeyStore {
    private let directory: URL

    public init(directory: URL) throws {
        self.directory = directory
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    private func fileURL(_ type: SignalDataType, _ id: String) -> URL {
        let safeId = id.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? id
        return directory.appendingPathComponent("\(type.rawValue)-\(safeId)")
    }

    public func get(_ type: SignalDataType, ids: [String]) async throws -> [String: Data] {
        var result: [String: Data] = [:]
        for id in ids {
            let url = fileURL(type, id)
            if let data = try? Data(contentsOf: url) {
                result[id] = data
            }
        }
        return result
    }

    public func set(_ type: SignalDataType, id: String, value: Data?) async throws {
        let url = fileURL(type, id)
        if let value {
            try value.write(to: url)
        } else {
            try? FileManager.default.removeItem(at: url)
        }
    }

    public func clear() async throws {
        try? FileManager.default.removeItem(at: directory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }
}

/// Mirrors Baileys' `AuthenticationState` (`src/Types/Auth.ts`): the pairing
/// of `creds` (a single serializable blob) and `keys` (the keyed store).
public final class AuthenticationState {
    public var creds: AuthenticationCreds
    public let keys: SignalKeyStore

    public init(creds: AuthenticationCreds, keys: SignalKeyStore) {
        self.creds = creds
        self.keys = keys
    }
}
