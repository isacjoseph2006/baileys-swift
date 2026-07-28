import Foundation
import NIOCore
import NIOPosix
import NIOWebSocket
import WebSocketKit

enum WebSocketTransportError: Error, CustomStringConvertible {
    case notConnected(closeCode: WebSocketErrorCode?)

    var description: String {
        switch self {
        case .notConnected(let closeCode):
            return "WebSocket not connected (server close code: \(closeCode.map { String(describing: $0) } ?? "none"))"
        }
    }
}

/// Thin wrapper around WebSocketKit for the one thing Baileys' socket layer
/// needs: an outbound `wss://` client connection with binary send/receive
/// and a close callback. Framing (the Noise intro header + 3-byte length
/// prefix) is handled one layer up in `NoiseHandshake`/`NoiseFrameDecoder` —
/// this type just moves bytes.
final class WebSocketTransport: @unchecked Sendable {
    private let eventLoopGroup: EventLoopGroup
    private var socket: WebSocket?

    var onBinary: ((Data) -> Void)?
    var onClose: ((Error?) -> Void)?

    init(eventLoopGroup: EventLoopGroup) {
        self.eventLoopGroup = eventLoopGroup
    }

    var isOpen: Bool {
        guard let socket else { return false }
        return !socket.isClosed
    }

    var closeCode: WebSocketErrorCode? {
        socket?.closeCode
    }

    /// Connects to `url` with the given `Origin` header (WhatsApp checks
    /// this — see `DEFAULT_ORIGIN` in Baileys' `Defaults/index.ts`), no
    /// WebSocket subprotocol.
    func connect(url: URL, origin: String) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let future = WebSocket.connect(
                to: url,
                headers: ["Origin": origin],
                on: eventLoopGroup
            ) { [weak self] ws in
                guard let self else { return }
                self.socket = ws
                ws.onBinary { [weak self] _, buffer in
                    self?.onBinary?(Data(buffer.readableBytesView))
                }
                ws.onClose.whenComplete { [weak self] _ in
                    self?.onClose?(nil)
                }
            }
            future.whenComplete { result in
                switch result {
                case .success:
                    continuation.resume()
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    func send(_ data: Data) async throws {
        guard let socket, !socket.isClosed else {
            throw WebSocketTransportError.notConnected(closeCode: socket?.closeCode)
        }
        let promise = eventLoopGroup.any().makePromise(of: Void.self)
        socket.send(data, promise: promise)
        try await promise.futureResult.get()
    }

    func close() async throws {
        guard let socket, !socket.isClosed else { return }
        try await socket.close().get()
    }
}
