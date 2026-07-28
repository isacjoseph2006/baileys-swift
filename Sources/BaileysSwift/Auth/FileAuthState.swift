import Foundation

/// Loads/saves an `AuthenticationState` from a directory on disk — a
/// `creds.json` file plus a `keys/` subdirectory (via `FileSignalKeyStore`),
/// analogous to Baileys' `useMultiFileAuthState` reference implementation
/// (`src/Utils/use-multi-file-auth-state.ts`), though the exact file layout
/// doesn't need to match since nothing else reads it.
public enum FileAuthState {
    public static func load(directory: URL) throws -> AuthenticationState {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let credsURL = directory.appendingPathComponent("creds.json")
        let creds: AuthenticationCreds
        if let data = try? Data(contentsOf: credsURL) {
            creds = try JSONDecoder().decode(AuthenticationCreds.self, from: data)
        } else {
            creds = try WAAuth.initAuthCreds()
        }

        let keys = try FileSignalKeyStore(directory: directory.appendingPathComponent("keys"))
        return AuthenticationState(creds: creds, keys: keys)
    }

    public static func save(_ state: AuthenticationState, directory: URL) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let credsURL = directory.appendingPathComponent("creds.json")
        let data = try JSONEncoder().encode(state.creds)
        try data.write(to: credsURL, options: .atomic)
    }
}
