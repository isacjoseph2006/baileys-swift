import Foundation

enum WABinaryDecodingError: Error, Equatable {
    case endOfStream
    case invalidTag(Int)
    case invalidListTag(Int)
    case invalidJidPair(String, String)
    case invalidDoubleTokenDict(Int)
    case invalidDoubleToken(Int)
    case invalidNode
    case invalidNibble(Int)
    case invalidHex(Int)
}

/// Strips/inflates the leading flags byte Baileys prefixes every decrypted
/// application frame with, matching `decompressingIfRequired`
/// (`src/WABinary/decode.ts`): bit 1 (`0x02`) set means the remainder is
/// zlib-deflated; otherwise the remaining bytes are the raw node encoding.
public func decompressingIfRequired(_ buffer: Data) throws -> Data {
    guard let first = buffer.first else { return Data() }
    let rest = buffer.dropFirst()
    if first & 2 != 0 {
        return try zlibInflate(Data(rest))
    } else {
        return Data(rest)
    }
}

/// Decodes one `BinaryNode` from a buffer that has already had the leading
/// flags byte removed (i.e. the output of `decompressingIfRequired`),
/// matching `decodeDecompressedBinaryNode` (`src/WABinary/decode.ts`).
public func decodeBinaryNode(_ buffer: Data) throws -> BinaryNode {
    var index = buffer.startIndex
    let bytes = buffer

    func checkEOS(_ length: Int) throws {
        if index + length > bytes.endIndex {
            throw WABinaryDecodingError.endOfStream
        }
    }

    func next() -> UInt8 {
        let value = bytes[index]
        index += 1
        return value
    }

    func readByte() throws -> UInt8 {
        try checkEOS(1)
        return next()
    }

    func readBytes(_ n: Int) throws -> Data {
        try checkEOS(n)
        let value = bytes[index..<(index + n)]
        index += n
        return Data(value)
    }

    func readStringFromChars(_ length: Int) throws -> String {
        let data = try readBytes(length)
        return String(decoding: data, as: UTF8.self)
    }

    func readInt(_ n: Int, littleEndian: Bool = false) throws -> Int {
        try checkEOS(n)
        var val = 0
        for i in 0..<n {
            let shift = littleEndian ? i : (n - 1 - i)
            val |= Int(next()) << (shift * 8)
        }
        return val
    }

    func readInt20() throws -> Int {
        try checkEOS(3)
        return (Int(next() & 15) << 16) + (Int(next()) << 8) + Int(next())
    }

    func unpackHex(_ value: Int) throws -> Character {
        guard value >= 0 && value < 16 else { throw WABinaryDecodingError.invalidHex(value) }
        let code = value < 10
            ? Int(Character("0").asciiValue!) + value
            : Int(Character("A").asciiValue!) + value - 10
        return Character(UnicodeScalar(UInt8(code)))
    }

    func unpackNibble(_ value: Int) throws -> Character {
        if value >= 0 && value <= 9 {
            return Character(UnicodeScalar(UInt8(Int(Character("0").asciiValue!) + value)))
        }
        switch value {
        case 10: return "-"
        case 11: return "."
        case 15: return "\0"
        default: throw WABinaryDecodingError.invalidNibble(value)
        }
    }

    func unpackByte(_ tag: UInt8, _ value: Int) throws -> Character {
        if tag == WATags.nibble8 {
            return try unpackNibble(value)
        } else if tag == WATags.hex8 {
            return try unpackHex(value)
        } else {
            throw WABinaryDecodingError.invalidTag(Int(tag))
        }
    }

    func readPacked8(_ tag: UInt8) throws -> String {
        let startByte = try readByte()
        var value = ""
        for _ in 0..<(Int(startByte) & 127) {
            let curByte = try readByte()
            value.append(try unpackByte(tag, Int(curByte & 0xF0) >> 4))
            value.append(try unpackByte(tag, Int(curByte & 0x0F)))
        }
        if startByte >> 7 != 0 {
            value.removeLast()
        }
        return value
    }

    func isListTag(_ tag: UInt8) -> Bool {
        tag == WATags.listEmpty || tag == WATags.list8 || tag == WATags.list16
    }

    func readListSize(_ tag: UInt8) throws -> Int {
        switch tag {
        case WATags.listEmpty: return 0
        case WATags.list8: return Int(try readByte())
        case WATags.list16: return try readInt(2)
        default: throw WABinaryDecodingError.invalidListTag(Int(tag))
        }
    }

    func getTokenDouble(_ index1: Int, _ index2: Int) throws -> String {
        guard index1 >= 0 && index1 < WATokens.doubleByteTokens.count else {
            throw WABinaryDecodingError.invalidDoubleTokenDict(index1)
        }
        let dict = WATokens.doubleByteTokens[index1]
        guard index2 >= 0 && index2 < dict.count else {
            throw WABinaryDecodingError.invalidDoubleToken(index2)
        }
        return dict[index2]
    }

    func readJidPair() throws -> String {
        let i = try readString(readByte())
        let j = try readString(readByte())
        if !j.isEmpty {
            return i + "@" + j
        }
        throw WABinaryDecodingError.invalidJidPair(i, j)
    }

    func readAdJid() throws -> String {
        let domainType = Int(try readByte())
        let device = Int(try readByte())
        let user = try readString(readByte())

        var server = "s.whatsapp.net"
        if domainType == WAJIDDomain.lid.rawValue {
            server = "lid"
        } else if domainType == WAJIDDomain.hosted.rawValue {
            server = "hosted"
        } else if domainType == WAJIDDomain.hostedLid.rawValue {
            server = "hosted.lid"
        }
        return jidEncode(user, server, device: device)
    }

    func readFbJid() throws -> String {
        let user = try readString(readByte())
        let device = try readInt(2)
        let server = try readString(readByte())
        return "\(user):\(device)@\(server)"
    }

    func readInteropJid() throws -> String {
        let user = try readString(readByte())
        let device = try readInt(2)
        let integrator = try readInt(2)

        var server = "interop"
        let beforeServer = index
        do {
            server = try readString(readByte())
        } catch {
            index = beforeServer
        }
        return "\(integrator)-\(user):\(device)@\(server)"
    }

    func readString(_ tag: UInt8) throws -> String {
        if tag >= 1 && Int(tag) < WATokens.singleByteTokens.count {
            return WATokens.singleByteTokens[Int(tag)]
        }
        switch tag {
        case WATags.dictionary0, WATags.dictionary1, WATags.dictionary2, WATags.dictionary3:
            return try getTokenDouble(Int(tag) - Int(WATags.dictionary0), Int(try readByte()))
        case WATags.listEmpty:
            return ""
        case WATags.binary8:
            return try readStringFromChars(Int(try readByte()))
        case WATags.binary20:
            return try readStringFromChars(try readInt20())
        case WATags.binary32:
            return try readStringFromChars(try readInt(4))
        case WATags.jidPair:
            return try readJidPair()
        case WATags.fbJid:
            return try readFbJid()
        case WATags.interopJid:
            return try readInteropJid()
        case WATags.adJid:
            return try readAdJid()
        case WATags.hex8, WATags.nibble8:
            return try readPacked8(tag)
        default:
            throw WABinaryDecodingError.invalidTag(Int(tag))
        }
    }

    func readList(_ tag: UInt8) throws -> [BinaryNode] {
        var items: [BinaryNode] = []
        let size = try readListSize(tag)
        for _ in 0..<size {
            items.append(try decodeNode())
        }
        return items
    }

    func decodeNode() throws -> BinaryNode {
        let listSize = try readListSize(try readByte())
        let header = try readString(try readByte())
        if listSize == 0 || header.isEmpty {
            throw WABinaryDecodingError.invalidNode
        }

        var attrs: [String: String] = [:]
        let attributesLength = (listSize - 1) >> 1
        for _ in 0..<attributesLength {
            let key = try readString(try readByte())
            let value = try readString(try readByte())
            attrs[key] = value
        }

        var content: BinaryNodeContent?
        if listSize % 2 == 0 {
            let tag = try readByte()
            if isListTag(tag) {
                content = .children(try readList(tag))
            } else {
                switch tag {
                case WATags.binary8:
                    content = .bytes(try readBytes(Int(try readByte())))
                case WATags.binary20:
                    content = .bytes(try readBytes(try readInt20()))
                case WATags.binary32:
                    content = .bytes(try readBytes(try readInt(4)))
                default:
                    content = .string(try readString(tag))
                }
            }
        }

        return BinaryNode(tag: header, attrs: attrs, content: content)
    }

    return try decodeNode()
}
