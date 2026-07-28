import BaileysSwift
import Foundation
import NIOPosix

// Unbuffered stdout: without this, prints are fully block-buffered whenever
// stdout isn't a tty (e.g. piped to a log file), which can hide output for a
// long time and make a slow/stuck connection look identical to a silent one.
setvbuf(stdout, nil, _IONBF, 0)

enum RunOutcome: Equatable {
    case reconnect
    case done
}

func printQR(_ data: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = ["qrencode", "-t", "ANSIUTF8", "-o", "-", data]
    do {
        try process.run()
        process.waitUntilExit()
    } catch {
        print("(install `qrencode` via `brew install qrencode` to render a scannable QR here)")
    }
    print(data)
}

func runConnection(authState: AuthenticationState, authDir: URL, eventLoopGroup: MultiThreadedEventLoopGroup) async -> RunOutcome {
    let socket = WhatsAppSocket(authState: authState, eventLoopGroup: eventLoopGroup)
    var outcome: RunOutcome = .done

    await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
        var resumed = false
        func finish() {
            guard !resumed else { return }
            resumed = true
            continuation.resume()
        }

        socket.onDebugLog = { message in
            print("[debug] \(message)")
        }

        socket.onCredsUpdate = { creds in
            authState.creds = creds
            do {
                try FileAuthState.save(authState, directory: authDir)
            } catch {
                print("warning: failed to persist credentials: \(error)")
            }
        }

        socket.onConnectionUpdate = { update in
            switch update {
            case .qrCode(let data):
                print("\nScan this QR with WhatsApp: Linked Devices > Link a Device\n")
                printQR(data)
            case .qrPairingSuccess:
                print("\nPaired! Reconnecting to complete login (WhatsApp closes the pairing connection by design)...")
                outcome = .reconnect
            case .open:
                print("\nConnection open — logged in as \(authState.creds.me?.id ?? "unknown")")
            case .closed(let error):
                if let error {
                    print("\nConnection closed: \(error)")
                } else {
                    print("\nConnection closed.")
                }
                finish()
            }
        }

        Task {
            do {
                try await socket.connect()
            } catch {
                print("Failed to connect: \(error)")
                finish()
            }
        }
    }

    return outcome
}

let authDir = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent("auth_info")
print("Using auth state directory: \(authDir.path)")

let authState = try FileAuthState.load(directory: authDir)
let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)

while true {
    let outcome = await runConnection(authState: authState, authDir: authDir, eventLoopGroup: eventLoopGroup)
    if outcome == .done {
        break
    }
    try? await Task.sleep(nanoseconds: 1_000_000_000)
}

try? await eventLoopGroup.shutdownGracefully()
