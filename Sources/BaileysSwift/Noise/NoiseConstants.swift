import Foundation

/// Constants from Baileys' `src/Defaults/index.ts`, pinned to whatever
/// WhatsApp Web protocol/build version Baileys' `master` targets as of
/// 2026-07-28. These drift as WhatsApp ships updates — keep in sync with
/// upstream Baileys' `Defaults/index.ts` (specifically `NOISE_WA_HEADER`'s
/// version byte and `version`), or the server will reject the handshake.
public enum WADefaults {
    /// `Noise_XX_25519_AESGCM_SHA256\0\0\0\0` — hashed down to 32 bytes
    /// since it isn't already exactly 32 (standard Noise protocol-name
    /// convention).
    static let noiseMode = "Noise_XX_25519_AESGCM_SHA256\0\0\0\0"

    static let dictVersion: UInt8 = 3

    /// `"W", "A", 0x06, DICT_VERSION` — the Noise prologue, and also the
    /// literal first bytes physically sent on the wire (see
    /// `NoiseHandshake.introHeader`).
    static let noiseWAHeader = Data([87, 65, 6, dictVersion])

    static let waCertSerial: UInt32 = 0
    /// WhatsApp's hardcoded Noise-cert root public key (32 bytes, raw
    /// Curve25519 — verified via `XEdDSA.verify`, not a Signal-prefixed key).
    static let waCertRootPublicKey = Data(hex: "142375574d0a587166aae71ebe516437c4a28b73e3695c6ce1f7f9545da8ee6b")

    static let waAdvAccountSigPrefix = Data([6, 0])
    static let waAdvDeviceSigPrefix = Data([6, 1])
    static let waAdvHostedAccountSigPrefix = Data([6, 5])
    static let waAdvHostedDeviceSigPrefix = Data([6, 6])

    /// `[major, minor, patch]`-ish triple Baileys sends as its WhatsApp Web
    /// client version.
    static let version = (2, 3000, 1035194821)

    static let waWebSocketURL = URL(string: "wss://web.whatsapp.com/ws/chat")!
    static let origin = "https://web.whatsapp.com"
    static let connectTimeoutSeconds: Int64 = 20
    static let keepAliveIntervalSeconds: Int64 = 30

    /// Appends `?ED=<base64url routingInfo>` when we have a cached
    /// edge-routing hint from a prior session (see the `CB:ib,,edge_routing`
    /// handling in `WhatsAppSocket`), matching `socket.ts`'s
    /// `url.searchParams.append('ED', ...)`.
    static func webSocketURL(routingInfo: Data?) -> URL {
        guard let routingInfo, !routingInfo.isEmpty else { return waWebSocketURL }
        var components = URLComponents(url: waWebSocketURL, resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "ED", value: routingInfo.base64URLEncodedString())]
        return components.url ?? waWebSocketURL
    }
}

extension Data {
    /// Decodes a hex string into `Data`. Traps on malformed input — only
    /// used for compile-time-known constants above.
    init(hex: String) {
        var bytes = [UInt8]()
        bytes.reserveCapacity(hex.count / 2)
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            bytes.append(UInt8(hex[idx..<next], radix: 16)!)
            idx = next
        }
        self = Data(bytes)
    }

    /// Base64url (RFC 4648 §5), no padding — Node's `buffer.toString('base64url')`.
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
