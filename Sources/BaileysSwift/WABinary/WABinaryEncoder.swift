import Foundation

/// `[token: String: (dict: Int?, index: Int)]`, built once from `WATokens`,
/// mirroring Baileys' `TOKEN_MAP` (`src/WABinary/constants.ts`).
private let tokenMap: [String: (dict: Int?, index: Int)] = {
    var map: [String: (dict: Int?, index: Int)] = [:]
    for (i, token) in WATokens.singleByteTokens.enumerated() {
        map[token] = (dict: nil, index: i)
    }
    for (dict, tokens) in WATokens.doubleByteTokens.enumerated() {
        for (index, token) in tokens.enumerated() {
            map[token] = (dict: dict, index: index)
        }
    }
    return map
}()

enum WABinaryEncodingError: Error, Equatable {
    case stringTooLarge(Int)
    case tooManyBytesToPack
    case invalidNibbleChar(Character)
    case invalidHexChar(Character)
    case invalidContent(String)
}

/// Encodes a `BinaryNode` tree into WhatsApp's binary wire format, matching
/// Baileys' `encodeBinaryNode` (`src/WABinary/encode.ts`) byte for byte.
///
/// The returned buffer always starts with a single `0x00` flags byte — Baileys
/// never sets the "content is zlib-deflated" bit (bit 1) on outgoing frames;
/// see `decodeDecompressedBinaryNode`/`decompressingIfRequired` on the decode
/// side, which strips/inflates based on that same byte.
public func encodeBinaryNode(_ node: BinaryNode) throws -> Data {
    var buffer: [UInt8] = [0]
    try encodeBinaryNodeInner(node, into: &buffer)
    return Data(buffer)
}

private func encodeBinaryNodeInner(_ node: BinaryNode, into buffer: inout [UInt8]) throws {
    func pushByte(_ value: Int) {
        buffer.append(UInt8(value & 0xFF))
    }

    func pushInt(_ value: Int, _ n: Int, littleEndian: Bool = false) {
        for i in 0..<n {
            let curShift = littleEndian ? i : (n - 1 - i)
            buffer.append(UInt8((value >> (curShift * 8)) & 0xFF))
        }
    }

    func pushBytes<S: Sequence>(_ bytes: S) where S.Element == UInt8 {
        buffer.append(contentsOf: bytes)
    }

    func pushInt16(_ value: Int) {
        pushBytes([UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)])
    }

    func pushInt20(_ value: Int) {
        pushBytes([UInt8((value >> 16) & 0x0F), UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)])
    }

    func writeByteLength(_ length: Int) throws {
        if length >= 4_294_967_296 {
            throw WABinaryEncodingError.stringTooLarge(length)
        }
        if length >= (1 << 20) {
            pushByte(Int(WATags.binary32))
            pushInt(length, 4)
        } else if length >= 256 {
            pushByte(Int(WATags.binary20))
            pushInt20(length)
        } else {
            pushByte(Int(WATags.binary8))
            pushByte(length)
        }
    }

    func writeStringRaw(_ str: String) throws {
        let bytes = Array(str.utf8)
        try writeByteLength(bytes.count)
        pushBytes(bytes)
    }

    func writeJid(_ jid: FullJid) throws {
        if let device = jid.device {
            pushByte(Int(WATags.adJid))
            pushByte(jid.domainType ?? 0)
            pushByte(device)
            try writeString(jid.user)
        } else {
            pushByte(Int(WATags.jidPair))
            if !jid.user.isEmpty {
                try writeString(jid.user)
            } else {
                pushByte(Int(WATags.listEmpty))
            }
            try writeString(jid.server)
        }
    }

    func packNibble(_ char: Character) throws -> Int {
        switch char {
        case "-": return 10
        case ".": return 11
        case "\0": return 15
        default:
            if char >= "0" && char <= "9" {
                return Int(char.asciiValue!) - Int(Character("0").asciiValue!)
            }
            throw WABinaryEncodingError.invalidNibbleChar(char)
        }
    }

    func packHex(_ char: Character) throws -> Int {
        if char >= "0" && char <= "9" {
            return Int(char.asciiValue!) - Int(Character("0").asciiValue!)
        }
        if char >= "A" && char <= "F" {
            return 10 + Int(char.asciiValue!) - Int(Character("A").asciiValue!)
        }
        if char >= "a" && char <= "f" {
            return 10 + Int(char.asciiValue!) - Int(Character("a").asciiValue!)
        }
        if char == "\0" {
            return 15
        }
        throw WABinaryEncodingError.invalidHexChar(char)
    }

    func writePackedBytes(_ str: String, nibble: Bool) throws {
        let chars = Array(str)
        if chars.count > WATags.packedMax {
            throw WABinaryEncodingError.tooManyBytesToPack
        }
        pushByte(Int(nibble ? WATags.nibble8 : WATags.hex8))

        var roundedLength = Int(ceil(Double(chars.count) / 2.0))
        if chars.count % 2 != 0 {
            roundedLength |= 128
        }
        pushByte(roundedLength)

        func pack(_ c: Character) throws -> Int {
            try nibble ? packNibble(c) : packHex(c)
        }
        func packBytePair(_ v1: Character, _ v2: Character) throws -> Int {
            (try pack(v1) << 4) | (try pack(v2))
        }

        let half = chars.count / 2
        for i in 0..<half {
            pushByte(try packBytePair(chars[2 * i], chars[2 * i + 1]))
        }
        if chars.count % 2 != 0 {
            pushByte(try packBytePair(chars[chars.count - 1], "\0"))
        }
    }

    func isNibble(_ str: String) -> Bool {
        if str.count > WATags.packedMax { return false }
        for char in str {
            let inRange = char >= "0" && char <= "9"
            if !inRange && char != "-" && char != "." {
                return false
            }
        }
        return true
    }

    func isHex(_ str: String) -> Bool {
        if str.count > WATags.packedMax { return false }
        for char in str {
            let inRange = char >= "0" && char <= "9"
            if !inRange && !(char >= "A" && char <= "F") {
                return false
            }
        }
        return true
    }

    func writeString(_ str: String?) throws {
        guard let str else {
            pushByte(Int(WATags.listEmpty))
            return
        }
        if str.isEmpty {
            try writeStringRaw(str)
            return
        }
        if let token = tokenMap[str] {
            if let dict = token.dict {
                pushByte(Int(WATags.dictionary0) + dict)
            }
            pushByte(token.index)
        } else if isNibble(str) {
            try writePackedBytes(str, nibble: true)
        } else if isHex(str) {
            try writePackedBytes(str, nibble: false)
        } else if let decodedJid = jidDecode(str) {
            try writeJid(decodedJid)
        } else {
            try writeStringRaw(str)
        }
    }

    func writeListStart(_ listSize: Int) {
        if listSize == 0 {
            pushByte(Int(WATags.listEmpty))
        } else if listSize < 256 {
            pushBytes([WATags.list8, UInt8(listSize)])
        } else {
            pushByte(Int(WATags.list16))
            pushInt16(listSize)
        }
    }

    if node.tag.isEmpty {
        throw WABinaryEncodingError.invalidContent("Invalid node: tag cannot be empty")
    }

    let validAttributes = node.attrs.keys.sorted()

    writeListStart(2 * validAttributes.count + 1 + (node.content != nil ? 1 : 0))
    try writeString(node.tag)

    for key in validAttributes {
        try writeString(key)
        try writeString(node.attrs[key])
    }

    switch node.content {
    case .string(let str):
        try writeString(str)
    case .bytes(let data):
        try writeByteLength(data.count)
        pushBytes(data)
    case .children(let children):
        writeListStart(children.count)
        for child in children {
            try encodeBinaryNodeInner(child, into: &buffer)
        }
    case nil:
        break
    }
}
