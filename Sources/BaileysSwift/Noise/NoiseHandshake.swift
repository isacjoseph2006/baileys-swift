import Foundation

public enum NoiseError: Error {
    case invalidCertificate(String)
}

/// Post-handshake AEAD channel: fixed encrypt/decrypt keys, each with its
/// own monotonically-incrementing 32-bit counter embedded in bytes 8-11 of
/// an otherwise-zero 12-byte IV. Matches `TransportState` in
/// `src/Utils/noise-handler.ts`.
final class NoiseTransportState {
    private let encKey: Data
    private let decKey: Data
    private var writeCounter: UInt32 = 0
    private var readCounter: UInt32 = 0

    init(encKey: Data, decKey: Data) {
        self.encKey = encKey
        self.decKey = decKey
    }

    private func iv(for counter: UInt32) -> Data {
        var iv = Data(repeating: 0, count: 12)
        iv[8] = UInt8((counter >> 24) & 0xFF)
        iv[9] = UInt8((counter >> 16) & 0xFF)
        iv[10] = UInt8((counter >> 8) & 0xFF)
        iv[11] = UInt8(counter & 0xFF)
        return iv
    }

    func encrypt(_ plaintext: Data) throws -> Data {
        let c = writeCounter
        writeCounter += 1
        return try WACrypto.aesEncryptGCM(plaintext: plaintext, key: encKey, iv: iv(for: c))
    }

    func decrypt(_ ciphertext: Data) throws -> Data {
        let c = readCounter
        readCounter += 1
        return try WACrypto.aesDecryptGCM(ciphertextAndTag: ciphertext, key: decKey, iv: iv(for: c))
    }
}

/// Port of Baileys' `makeNoiseHandler` (`src/Utils/noise-handler.ts`):
/// drives the `Noise_XX_25519_AESGCM_SHA256` handshake used to establish
/// WhatsApp's encrypted WebSocket channel, including the WhatsApp-specific
/// cert-chain verification step layered on top of vanilla Noise_XX.
///
/// Not thread-safe by itself — only ever touched from within
/// `WhatsAppSocket`'s actor isolation.
final class NoiseHandshake {
    private var hash: Data
    private var salt: Data
    private var encKey: Data
    private var decKey: Data
    private var counter: UInt32 = 0
    private var sentIntro = false
    private var transport: NoiseTransportState?

    private let ephemeralKeyPair: WACrypto.KeyPair
    private let introHeader: Data

    var hasTransport: Bool { transport != nil }

    init(ephemeralKeyPair: WACrypto.KeyPair, routingInfo: Data? = nil) {
        self.ephemeralKeyPair = ephemeralKeyPair

        let modeData = Data(WADefaults.noiseMode.utf8)
        let h = modeData.count == 32 ? modeData : WACrypto.sha256(modeData)
        hash = h
        salt = h
        encKey = h
        decKey = h

        if let routingInfo {
            var intro = Data()
            intro.append(contentsOf: "ED".utf8)
            intro.append(0)
            intro.append(1)
            intro.append(UInt8((routingInfo.count >> 16) & 0xFF))
            let lowLen = UInt16(routingInfo.count & 0xFFFF)
            intro.append(UInt8((lowLen >> 8) & 0xFF))
            intro.append(UInt8(lowLen & 0xFF))
            intro.append(routingInfo)
            intro.append(WADefaults.noiseWAHeader)
            introHeader = intro
        } else {
            introHeader = WADefaults.noiseWAHeader
        }

        authenticate(WADefaults.noiseWAHeader)
        authenticate(ephemeralKeyPair.publicKey)
    }

    private func authenticate(_ data: Data) {
        guard transport == nil else { return }
        hash = WACrypto.sha256(hash + data)
    }

    private func generateIV(_ counter: UInt32) -> Data {
        var iv = Data(repeating: 0, count: 12)
        iv[8] = UInt8((counter >> 24) & 0xFF)
        iv[9] = UInt8((counter >> 16) & 0xFF)
        iv[10] = UInt8((counter >> 8) & 0xFF)
        iv[11] = UInt8(counter & 0xFF)
        return iv
    }

    /// Handshake-phase encrypt: AES-GCM keyed by `encKey`, AAD = the running
    /// transcript hash (standard Noise `EncryptAndHash`). Delegates to the
    /// post-handshake transport once established.
    func encrypt(_ plaintext: Data) throws -> Data {
        if let transport { return try transport.encrypt(plaintext) }
        let iv = generateIV(counter)
        counter += 1
        let result = try WACrypto.aesEncryptGCM(plaintext: plaintext, key: encKey, iv: iv, additionalData: hash)
        authenticate(result)
        return result
    }

    /// Handshake-phase decrypt (see `encrypt`).
    func decrypt(_ ciphertext: Data) throws -> Data {
        if let transport { return try transport.decrypt(ciphertext) }
        let iv = generateIV(counter)
        counter += 1
        let result = try WACrypto.aesDecryptGCM(ciphertextAndTag: ciphertext, key: decKey, iv: iv, additionalData: hash)
        authenticate(ciphertext)
        return result
    }

    private func localHKDF(_ data: Data) -> (write: Data, read: Data) {
        let key = WACrypto.hkdfSha256(ikm: data, salt: salt, info: Data(), outputByteCount: 64)
        return (key.prefix(32), key.suffix(32))
    }

    /// Standard Noise `MixKey`: re-derive `(salt, key)` from a fresh DH
    /// output, resetting the nonce counter. During the handshake, both
    /// directions share one key (encKey == decKey == read) until
    /// `finishInit` splits them.
    func mixIntoKey(_ data: Data) {
        let (write, read) = localHKDF(data)
        salt = write
        encKey = read
        decKey = read
        counter = 0
    }

    /// Transitions from the handshake's shared-key mode to the final
    /// transport state with independent, correctly-directioned read/write
    /// keys.
    func finishInit() {
        let (write, read) = localHKDF(Data())
        transport = NoiseTransportState(encKey: write, decKey: read)
    }

    /// Processes the server's `ServerHello` (mixing `ee`/`es`, verifying the
    /// WhatsApp Noise cert chain against the hardcoded root key), and
    /// returns the encrypted client static key to send back as
    /// `ClientFinish.static`. Matches `processHandshake` in
    /// `noise-handler.ts`.
    func processHandshake(serverHello: Proto_HandshakeMessage.ServerHello, noiseKey: WACrypto.KeyPair) throws -> Data {
        authenticate(serverHello.ephemeral)
        mixIntoKey(try WACrypto.sharedKey(privateKey: ephemeralKeyPair.privateKey, publicKey: serverHello.ephemeral))

        let decStaticContent = try decrypt(serverHello.static)
        mixIntoKey(try WACrypto.sharedKey(privateKey: ephemeralKeyPair.privateKey, publicKey: decStaticContent))

        let certDecoded = try decrypt(serverHello.payload)
        let certChain = try Proto_CertChain(serializedBytes: certDecoded)

        guard certChain.hasLeaf, !certChain.leaf.details.isEmpty, !certChain.leaf.signature.isEmpty else {
            throw NoiseError.invalidCertificate("invalid noise leaf certificate")
        }
        guard certChain.hasIntermediate, !certChain.intermediate.details.isEmpty, !certChain.intermediate.signature.isEmpty else {
            throw NoiseError.invalidCertificate("invalid noise intermediate certificate")
        }

        let details = try Proto_CertChain.NoiseCertificate.Details(serializedBytes: certChain.intermediate.details)

        let verify = XEdDSA.verify(signature: certChain.leaf.signature, publicKey: details.key, message: certChain.leaf.details)
        let verifyIntermediate = XEdDSA.verify(
            signature: certChain.intermediate.signature,
            publicKey: WADefaults.waCertRootPublicKey,
            message: certChain.intermediate.details
        )

        guard verify else {
            throw NoiseError.invalidCertificate("noise certificate signature invalid")
        }
        guard verifyIntermediate else {
            throw NoiseError.invalidCertificate("noise intermediate certificate signature invalid")
        }
        guard details.issuerSerial == WADefaults.waCertSerial else {
            throw NoiseError.invalidCertificate("certification match failed")
        }

        let keyEnc = try encrypt(noiseKey.publicKey)
        mixIntoKey(try WACrypto.sharedKey(privateKey: noiseKey.privateKey, publicKey: serverHello.ephemeral))

        return keyEnc
    }

    /// Frames `data` for the wire: `[one-time intro][3-byte big-endian
    /// length][payload]`, encrypting `data` first once the transport state
    /// is established. Matches `encodeFrame`.
    func encodeFrame(_ data: Data) throws -> Data {
        let payload = transport != nil ? try transport!.encrypt(data) : data

        var frame = Data()
        if !sentIntro {
            frame.append(introHeader)
            sentIntro = true
        }
        let len = payload.count
        frame.append(UInt8((len >> 16) & 0xFF))
        frame.append(UInt8((len >> 8) & 0xFF))
        frame.append(UInt8(len & 0xFF))
        frame.append(payload)
        return frame
    }
}

/// What a decoded frame is, depending on whether the transport state has
/// been established yet: raw handshake-protobuf bytes beforehand, decrypted
/// + WABinary-decoded nodes afterward. Matches the `Uint8Array | BinaryNode`
/// union `onFrame` receives in `noise-handler.ts`.
enum DecodedFrame {
    case raw(Data)
    case node(BinaryNode)
}

/// Buffers incoming WebSocket byte chunks and slices out
/// `[3-byte length][payload]` frames, matching `processData`/`decodeFrame`
/// in `noise-handler.ts`. The one-time intro header is only ever sent, never
/// received, so there's nothing to strip on the read side.
final class NoiseFrameDecoder {
    private var inBytes = Data()
    private let noise: NoiseHandshake

    init(noise: NoiseHandshake) {
        self.noise = noise
    }

    func addData(_ data: Data) throws -> [DecodedFrame] {
        inBytes.append(data)

        var frames: [DecodedFrame] = []
        while true {
            guard inBytes.count >= 3 else { break }
            let start = inBytes.startIndex
            let size = (Int(inBytes[start]) << 16) | (Int(inBytes[start + 1]) << 8) | Int(inBytes[start + 2])
            guard inBytes.count >= size + 3 else { break }

            let frameStart = inBytes.index(start, offsetBy: 3)
            let frameEnd = inBytes.index(frameStart, offsetBy: size)
            let frameData = Data(inBytes[frameStart..<frameEnd])
            inBytes.removeSubrange(start..<frameEnd)

            if noise.hasTransport {
                let decrypted = try noise.decrypt(frameData)
                let decompressed = try decompressingIfRequired(decrypted)
                frames.append(.node(try decodeBinaryNode(decompressed)))
            } else {
                frames.append(.raw(frameData))
            }
        }
        return frames
    }
}
