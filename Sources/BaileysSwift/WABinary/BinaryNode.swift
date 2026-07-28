import Foundation

/// The content payload of a `BinaryNode`, mirroring Baileys' `BinaryNode['content']`
/// union of `undefined | string | Buffer | BinaryNode[]`.
public enum BinaryNodeContent: Equatable {
    case string(String)
    case bytes(Data)
    case children([BinaryNode])

    /// Coerces string-shaped content to a `String`, matching Baileys'
    /// `getBinaryNodeChildString`/`getBinaryNodeChildBuffer` helpers
    /// (`src/WABinary/generic-utils.ts`): on the wire, any string content
    /// that isn't a token/nibble/hex/JID match is indistinguishable from
    /// arbitrary bytes once decoded (both go through the same `BINARY_8/20/32`
    /// length-prefixed form), so `decodeBinaryNode` always surfaces those as
    /// `.bytes` and callers who expect text decode it as UTF-8 themselves.
    public var utf8String: String? {
        switch self {
        case .string(let value): return value
        case .bytes(let data): return String(decoding: data, as: UTF8.self)
        case .children: return nil
        }
    }
}

/// A node in WhatsApp's binary "WABinary" tree format — the wire representation
/// used for all stanzas once the Noise transport is established.
public struct BinaryNode: Equatable {
    public var tag: String
    public var attrs: [String: String]
    public var content: BinaryNodeContent?

    public init(tag: String, attrs: [String: String] = [:], content: BinaryNodeContent? = nil) {
        self.tag = tag
        self.attrs = attrs
        self.content = content
    }
}

/// Mirrors Baileys' `WAJIDDomains` enum (`src/WABinary/jid-utils.ts`).
public enum WAJIDDomain: Int {
    case whatsapp = 0
    case lid = 1
    case hosted = 128
    case hostedLid = 129
}

/// Mirrors Baileys' `FullJid` (`src/WABinary/jid-utils.ts`).
public struct FullJid: Equatable {
    public var user: String
    public var server: String
    public var device: Int?
    public var domainType: Int?

    public init(user: String, server: String, device: Int? = nil, domainType: Int? = nil) {
        self.user = user
        self.server = server
        self.device = device
        self.domainType = domainType
    }
}

/// Splits `str` on `separator` the way JavaScript's `String.prototype.split`
/// does: empty subsequences are preserved, and splitting `""` yields `[""]`.
/// Swift's `split(separator:)` (even with `omittingEmptySubsequences: false`)
/// returns `[]` for an empty string, so this needs its own tiny helper for
/// `jidDecode` to match Baileys' behavior exactly.
func jsSplit(_ str: String, _ separator: Character) -> [String] {
    if str.isEmpty { return [""] }
    return str.split(separator: separator, omittingEmptySubsequences: false).map(String.init)
}

/// Mirrors Baileys' `jidEncode` (`src/WABinary/jid-utils.ts`).
public func jidEncode(_ user: String?, _ server: String, device: Int? = nil, agent: Int? = nil) -> String {
    var result = user ?? ""
    if let agent, agent != 0 {
        result += "_\(agent)"
    }
    if let device, device != 0 {
        result += ":\(device)"
    }
    return result + "@" + server
}

/// Mirrors Baileys' `jidDecode` (`src/WABinary/jid-utils.ts`).
public func jidDecode(_ jid: String?) -> FullJid? {
    guard let jid, let sepIdx = jid.firstIndex(of: "@") else { return nil }

    let server = String(jid[jid.index(after: sepIdx)...])
    let userCombined = String(jid[jid.startIndex..<sepIdx])

    let userDeviceParts = jsSplit(userCombined, ":")
    let userAgentPart = userDeviceParts[0]
    let devicePart = userDeviceParts.count > 1 ? userDeviceParts[1] : nil

    let userAgentParts = jsSplit(userAgentPart, "_")
    let user = userAgentParts[0]
    let agentPart = userAgentParts.count > 1 ? userAgentParts[1] : nil

    var domainType = WAJIDDomain.whatsapp.rawValue
    if server == "lid" {
        domainType = WAJIDDomain.lid.rawValue
    } else if server == "hosted" {
        domainType = WAJIDDomain.hosted.rawValue
    } else if server == "hosted.lid" {
        domainType = WAJIDDomain.hostedLid.rawValue
    } else if let agentPart, !agentPart.isEmpty, let agentValue = Int(agentPart) {
        domainType = agentValue
    }

    let device: Int?
    if let devicePart, !devicePart.isEmpty, let deviceValue = Int(devicePart) {
        device = deviceValue
    } else {
        device = nil
    }

    return FullJid(user: user, server: server, device: device, domainType: domainType)
}
