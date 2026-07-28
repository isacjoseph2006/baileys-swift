import Foundation
import NIOCore
import NIOPosix

public enum ConnectionUpdate {
    case qrCode(String)
    case qrPairingSuccess
    case open
    case closed(Error?)
}

public enum SocketError: Error {
    case notConnected
    case timeout
    case connectionLost
    case connectionClosed
    case qrRefsExhausted
}

/// Drives one WhatsApp Web multi-device connection: the Noise handshake,
/// QR device pairing, and the post-login keepalive — a Swift port of the
/// connection-lifecycle parts of Baileys' `makeSocket`
/// (`src/Socket/socket.ts`). Message send/receive (Signal-encrypted chat
/// messages) is out of scope here; this only gets the connection to the
/// "open" state.
///
/// This intentionally replaces Baileys' generic `CB:tag,attrKey:val,...`
/// event-emitter dispatch with direct `if`-chains in `handle(node:)` — we
/// only ever need to react to a fixed handful of stanza shapes
/// (`pair-device`, `pair-success`, `success`, errors), so the generic
/// pattern-matching machinery isn't worth reproducing.
public actor WhatsAppSocket {
    public nonisolated(unsafe) var onConnectionUpdate: ((ConnectionUpdate) -> Void)?
    public nonisolated(unsafe) var onCredsUpdate: ((AuthenticationCreds) -> Void)?
    /// Optional verbose step-by-step logging of the connect sequence —
    /// useful for diagnosing where a connection attempt is failing against
    /// the real server (vs. guessing from just the final error).
    public nonisolated(unsafe) var onDebugLog: ((String) -> Void)?

    private let authState: AuthenticationState
    private let config: WAConnectionConfig
    private let eventLoopGroup: EventLoopGroup

    private var noise: NoiseHandshake?
    private var frameDecoder: NoiseFrameDecoder?
    private var transport: WebSocketTransport?

    private var pendingRawFrameContinuation: CheckedContinuation<Data, Error>?
    private var pendingQueryContinuations: [String: CheckedContinuation<BinaryNode, Error>] = [:]
    private var pendingQRRefs: [String] = []
    private var qrRotationTask: Task<Void, Never>?
    private var keepAliveTask: Task<Void, Never>?
    private var lastReceivedAt = Date()

    private lazy var tagPrefix: String = {
        let bytes = WACrypto.randomBytes(4)
        let a = (UInt16(bytes[0]) << 8) | UInt16(bytes[1])
        let b = (UInt16(bytes[2]) << 8) | UInt16(bytes[3])
        return "\(a).\(b)-"
    }()
    private var epoch = 1

    public init(authState: AuthenticationState, config: WAConnectionConfig = WAConnectionConfig(), eventLoopGroup: EventLoopGroup) {
        self.authState = authState
        self.config = config
        self.eventLoopGroup = eventLoopGroup
    }

    public var creds: AuthenticationCreds { authState.creds }

    // MARK: - Connection lifecycle

    /// Opens the WebSocket, performs the Noise_XX handshake (including cert
    /// chain verification), and sends the client payload (login or
    /// registration, depending on whether `creds.me` is already set).
    /// Matches `validateConnection` in `socket.ts`.
    public func connect() async throws {
        let ephemeralKeyPair = WACrypto.generateX25519KeyPair()
        let noise = NoiseHandshake(ephemeralKeyPair: ephemeralKeyPair, routingInfo: authState.creds.routingInfo)
        self.noise = noise
        self.frameDecoder = NoiseFrameDecoder(noise: noise)

        let transport = WebSocketTransport(eventLoopGroup: eventLoopGroup)
        self.transport = transport
        transport.onBinary = { [weak self] data in
            Task { await self?.handleIncomingBytes(data) }
        }
        transport.onClose = { [weak self] error in
            Task { await self?.handleTransportClosed(error) }
        }

        let url = WADefaults.webSocketURL(routingInfo: authState.creds.routingInfo)
        onDebugLog?("opening WebSocket to \(url)")
        try await withTimeout(seconds: WADefaults.connectTimeoutSeconds) {
            try await transport.connect(url: url, origin: WADefaults.origin)
        }
        onDebugLog?("WebSocket connected, isOpen=\(transport.isOpen)")

        var hello = Proto_HandshakeMessage()
        hello.clientHello.ephemeral = ephemeralKeyPair.publicKey
        try await sendRaw(try hello.serializedData())
        onDebugLog?("sent ClientHello, isOpen=\(transport.isOpen)")

        let serverHelloBytes = try await withTimeout(seconds: WADefaults.connectTimeoutSeconds) {
            try await self.awaitNextRawFrame()
        }
        onDebugLog?("received ServerHello (\(serverHelloBytes.count) bytes)")
        let handshakeMsg = try Proto_HandshakeMessage(serializedBytes: serverHelloBytes)
        let keyEnc = try noise.processHandshake(serverHello: handshakeMsg.serverHello, noiseKey: authState.creds.noiseKey)
        onDebugLog?("cert chain verified, noise handshake processed")

        let clientPayload: Proto_ClientPayload
        if let me = authState.creds.me {
            clientPayload = ClientPayloadBuilder.loginNode(userJid: me.id, config: config)
        } else {
            clientPayload = ClientPayloadBuilder.registrationNode(creds: authState.creds, config: config)
        }
        let payloadEnc = try noise.encrypt(try clientPayload.serializedData())

        var finish = Proto_HandshakeMessage()
        finish.clientFinish.static = keyEnc
        finish.clientFinish.payload = payloadEnc
        try await sendRaw(try finish.serializedData())

        noise.finishInit()
        startKeepAlive()
    }

    public func disconnect() async {
        keepAliveTask?.cancel()
        qrRotationTask?.cancel()
        try? await transport?.close()
    }

    // MARK: - Sending

    private func sendRaw(_ data: Data) async throws {
        guard let noise, let transport else { throw SocketError.notConnected }
        let framed = try noise.encodeFrame(data)
        try await transport.send(framed)
    }

    func sendNode(_ node: BinaryNode) async throws {
        try await sendRaw(try encodeBinaryNode(node))
    }

    private func generateMessageTag() -> String {
        let tag = "\(tagPrefix)\(epoch)"
        epoch += 1
        return tag
    }

    /// Sends `node` and awaits the response with the same `id` attribute,
    /// matching `query` in `socket.ts`. The continuation is registered
    /// *before* the send goes out (mirroring Baileys' own
    /// register-then-send ordering) so a fast response can't race ahead of
    /// us starting to listen for it.
    @discardableResult
    func query(_ node: BinaryNode, timeoutSeconds: Int64 = 60) async throws -> BinaryNode {
        var node = node
        let id = node.attrs["id"] ?? generateMessageTag()
        node.attrs["id"] = id

        return try await withCheckedThrowingContinuation { continuation in
            pendingQueryContinuations[id] = continuation
            Task {
                do {
                    try await self.sendNode(node)
                } catch {
                    await self.failQuery(id: id, error: error)
                }
            }
            Task {
                try? await Task.sleep(nanoseconds: UInt64(timeoutSeconds) * 1_000_000_000)
                await self.timeoutQuery(id: id)
            }
        }
    }

    private func failQuery(id: String, error: Error) {
        if let cont = pendingQueryContinuations.removeValue(forKey: id) {
            cont.resume(throwing: error)
        }
    }

    private func timeoutQuery(id: String) {
        if let cont = pendingQueryContinuations.removeValue(forKey: id) {
            cont.resume(throwing: SocketError.timeout)
        }
    }

    // MARK: - Receiving

    private func awaitNextRawFrame() async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            self.pendingRawFrameContinuation = continuation
        }
    }

    private func handleIncomingBytes(_ data: Data) async {
        guard let frameDecoder else { return }
        do {
            let frames = try frameDecoder.addData(data)
            for frame in frames {
                lastReceivedAt = Date()
                switch frame {
                case .raw(let bytes):
                    if let cont = pendingRawFrameContinuation {
                        pendingRawFrameContinuation = nil
                        cont.resume(returning: bytes)
                    }
                case .node(let node):
                    await handle(node: node)
                }
            }
        } catch {
            onConnectionUpdate?(.closed(error))
            await disconnect()
        }
    }

    private func handleTransportClosed(_ error: Error?) async {
        keepAliveTask?.cancel()
        qrRotationTask?.cancel()

        for (_, cont) in pendingQueryContinuations {
            cont.resume(throwing: SocketError.connectionClosed)
        }
        pendingQueryContinuations.removeAll()

        if let cont = pendingRawFrameContinuation {
            pendingRawFrameContinuation = nil
            cont.resume(throwing: SocketError.connectionClosed)
        }

        onConnectionUpdate?(.closed(error))
    }

    private func handle(node: BinaryNode) async {
        if let id = node.attrs["id"], let cont = pendingQueryContinuations.removeValue(forKey: id) {
            cont.resume(returning: node)
            return
        }

        if node.tag == "iq", node.attrs["type"] == "set", node.child("pair-device") != nil {
            await handlePairDevice(node)
        } else if node.tag == "iq", node.child("pair-success") != nil {
            await handlePairSuccess(node)
        } else if node.tag == "success" {
            await handleLoginSuccess(node)
        } else if node.tag == "stream:error" {
            onConnectionUpdate?(.closed(StreamError(node: node)))
            await disconnect()
        } else if node.tag == "failure" {
            onConnectionUpdate?(.closed(StreamError(node: node)))
            await disconnect()
        } else if node.tag == "ib" {
            handleInfoNode(node)
        }
    }

    /// `CB:ib,,edge_routing` (`socket.ts`): caches the server-provided
    /// edge-routing hint so the *next* connection can be routed to the same
    /// edge node via `?ED=` on the URL, instead of a fresh generic connect.
    private func handleInfoNode(_ node: BinaryNode) {
        guard let edgeRouting = node.child("edge_routing"),
              let routingInfoNode = edgeRouting.child("routing_info"),
              let bytes = routingInfoNode.content?.bytesValue else { return }
        authState.creds.routingInfo = bytes
        onCredsUpdate?(authState.creds)
        onDebugLog?("cached edge routing info (\(bytes.count) bytes)")
    }

    // MARK: - QR pairing

    private func handlePairDevice(_ node: BinaryNode) async {
        do {
            try await sendNode(BinaryNode(tag: "iq", attrs: ["to": "s.whatsapp.net", "type": "result", "id": node.attrs["id"] ?? ""]))
        } catch {
            onConnectionUpdate?(.closed(error))
            return
        }

        guard let pairDeviceNode = node.child("pair-device"), case .children(let children)? = pairDeviceNode.content else {
            return
        }
        pendingQRRefs = children
            .filter { $0.tag == "ref" }
            .compactMap { $0.content?.bytesValue }
            .compactMap { String(data: $0, encoding: .utf8) }

        startQRRotation()
    }

    private func startQRRotation() {
        qrRotationTask?.cancel()
        qrRotationTask = Task { [weak self] in
            guard let self else { return }
            var first = true
            while !Task.isCancelled {
                guard let ref = await self.popNextQRRef() else {
                    self.onConnectionUpdate?(.closed(SocketError.qrRefsExhausted))
                    await self.disconnect()
                    return
                }
                let qr = await self.buildQRString(ref: ref)
                self.onConnectionUpdate?(.qrCode(qr))

                let seconds: UInt64 = first ? 60 : 20
                first = false
                try? await Task.sleep(nanoseconds: seconds * 1_000_000_000)
            }
        }
    }

    private func popNextQRRef() -> String? {
        guard !pendingQRRefs.isEmpty else { return nil }
        return pendingQRRefs.removeFirst()
    }

    private func buildQRString(ref: String) -> String {
        PairingQR.data(
            ref: ref,
            noiseKeyB64: authState.creds.noiseKey.publicKey.base64EncodedString(),
            identityKeyB64: authState.creds.signedIdentityKey.publicKey.base64EncodedString(),
            advB64: authState.creds.advSecretKey,
            browser: config.browser
        )
    }

    private func handlePairSuccess(_ node: BinaryNode) async {
        qrRotationTask?.cancel()
        do {
            let result = try Pairing.configureSuccessfulPairing(stanza: node, creds: authState.creds)
            authState.creds.me = result.me
            authState.creds.account = result.account
            authState.creds.signalIdentities.append(result.signalIdentity)
            authState.creds.platform = result.platform
            onCredsUpdate?(authState.creds)
            onConnectionUpdate?(.qrPairingSuccess)

            try await sendNode(result.reply)
            // The server closes the connection shortly after this — the
            // caller should reconnect using the now-updated (and, ideally,
            // persisted) creds, which will take the login-node path instead
            // of registration since `creds.me` is set.
        } catch {
            onConnectionUpdate?(.closed(error))
            await disconnect()
        }
    }

    // MARK: - Post-login

    private func handleLoginSuccess(_ node: BinaryNode) async {
        _ = try? await query(BinaryNode(
            tag: "iq",
            attrs: ["to": "s.whatsapp.net", "xmlns": "passive", "type": "set"],
            content: .children([BinaryNode(tag: "active")])
        ))

        if let lid = node.attrs["lid"], authState.creds.me != nil {
            authState.creds.me?.lid = lid
            onCredsUpdate?(authState.creds)
        }

        onConnectionUpdate?(.open)
    }

    private func startKeepAlive() {
        keepAliveTask?.cancel()
        keepAliveTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(WADefaults.keepAliveIntervalSeconds) * 1_000_000_000)
                guard let self, !Task.isCancelled else { return }
                await self.sendKeepAlivePing()
            }
        }
    }

    private func sendKeepAlivePing() async {
        let diff = Date().timeIntervalSince(lastReceivedAt)
        if diff > Double(WADefaults.keepAliveIntervalSeconds + 5) {
            onConnectionUpdate?(.closed(SocketError.connectionLost))
            await disconnect()
            return
        }
        guard let transport, transport.isOpen else { return }
        _ = try? await query(BinaryNode(
            tag: "iq",
            attrs: ["to": "s.whatsapp.net", "type": "get", "xmlns": "w:p"],
            content: .children([BinaryNode(tag: "ping")])
        ))
    }
}

struct StreamError: Error, CustomStringConvertible {
    let node: BinaryNode
    var description: String { "WhatsApp stream error: \(node)" }
}

/// Races `operation` against a timeout so a stalled network call surfaces
/// as `SocketError.timeout` instead of hanging the connection attempt
/// forever — matches Baileys' `promiseTimeout` wrapping around
/// `connectTimeoutMs` (`src/Utils/generics.ts`).
func withTimeout<T: Sendable>(seconds: Int64, operation: @escaping @Sendable () async throws -> T) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(seconds) * 1_000_000_000)
            throw SocketError.timeout
        }
        guard let result = try await group.next() else {
            throw SocketError.timeout
        }
        group.cancelAll()
        return result
    }
}
