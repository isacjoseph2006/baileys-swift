import XCTest
@testable import BaileysSwift

final class WABinaryTests: XCTestCase {
    private func roundTrip(_ node: BinaryNode) throws -> BinaryNode {
        let encoded = try encodeBinaryNode(node)
        let decompressed = try decompressingIfRequired(encoded)
        return try decodeBinaryNode(decompressed)
    }

    func testSimpleNodeWithTokenTagAndAttrs() throws {
        let node = BinaryNode(tag: "iq", attrs: ["type": "get", "xmlns": "w:p", "id": "abc123"])
        let decoded = try roundTrip(node)
        XCTAssertEqual(decoded.tag, "iq")
        XCTAssertEqual(decoded.attrs, node.attrs)
        XCTAssertNil(decoded.content)
    }

    func testNodeWithStringContent() throws {
        // "hello world" doesn't match a token/nibble/hex/JID encoding, so it
        // goes out as a raw length-prefixed string — and, matching Baileys'
        // own decode.ts, comes back decoded as `.bytes`, not `.string`: the
        // wire format can't distinguish "this Buffer is UTF-8 text" from
        // arbitrary binary once it takes the BINARY_8/20/32 path. Callers
        // that expect text use `.utf8String` (mirroring Baileys'
        // `getBinaryNodeChildString`), which handles both cases.
        let node = BinaryNode(tag: "body", attrs: [:], content: .string("hello world"))
        let decoded = try roundTrip(node)
        XCTAssertEqual(decoded.tag, "body")
        XCTAssertEqual(decoded.content, .bytes(Data("hello world".utf8)))
        XCTAssertEqual(decoded.content?.utf8String, "hello world")
    }

    func testNodeWithBytesContent() throws {
        let payload = Data([0x00, 0x01, 0x02, 0xFF, 0xAB, 0xCD])
        let node = BinaryNode(tag: "enc", attrs: ["type": "pkmsg", "v": "2"], content: .bytes(payload))
        let decoded = try roundTrip(node)
        XCTAssertEqual(decoded.content, .bytes(payload))
    }

    func testNodeWithChildren() throws {
        let child1 = BinaryNode(tag: "ping")
        let child2 = BinaryNode(tag: "item", attrs: ["index": "1"], content: .string("x"))
        let node = BinaryNode(tag: "iq", attrs: ["type": "set", "xmlns": "urn:xmpp:ping"], content: .children([child1, child2]))
        let decoded = try roundTrip(node)
        guard case .children(let children)? = decoded.content else {
            return XCTFail("expected children content")
        }
        XCTAssertEqual(children.count, 2)
        XCTAssertEqual(children[0].tag, "ping")
        XCTAssertEqual(children[1].tag, "item")
        XCTAssertEqual(children[1].attrs, ["index": "1"])
        XCTAssertEqual(children[1].content?.utf8String, "x")
    }

    func testLargeListOfChildrenUsesList16() throws {
        // > 255 children forces the LIST_16 path instead of LIST_8.
        let children = (0..<300).map { BinaryNode(tag: "item", attrs: ["i": "\($0)"]) }
        let node = BinaryNode(tag: "list", content: .children(children))
        let decoded = try roundTrip(node)
        guard case .children(let decodedChildren)? = decoded.content else {
            return XCTFail("expected children content")
        }
        XCTAssertEqual(decodedChildren.count, 300)
        XCTAssertEqual(decodedChildren[299].attrs["i"], "299")
    }

    func testLongRawStringUsesBinary20() throws {
        // >= 256 bytes forces the BINARY_20 length-prefix path.
        let longString = String(repeating: "z", count: 1000)
        let node = BinaryNode(tag: "body", content: .string(longString))
        let decoded = try roundTrip(node)
        XCTAssertEqual(decoded.content?.utf8String, longString)
    }

    func testPhoneNumberJidRoundTrip() throws {
        // Numeric user + device -> AD_JID wire form.
        let node = BinaryNode(tag: "message", attrs: ["to": "15551234567:5@s.whatsapp.net"])
        let decoded = try roundTrip(node)
        XCTAssertEqual(decoded.attrs["to"], "15551234567:5@s.whatsapp.net")
    }

    func testGroupJidRoundTrip() throws {
        // No device -> JID_PAIR wire form.
        let node = BinaryNode(tag: "message", attrs: ["to": "123456789-987654321@g.us"])
        let decoded = try roundTrip(node)
        XCTAssertEqual(decoded.attrs["to"], "123456789-987654321@g.us")
    }

    func testLidJidRoundTrip() throws {
        let node = BinaryNode(tag: "message", attrs: ["from": "98765:2@lid"])
        let decoded = try roundTrip(node)
        XCTAssertEqual(decoded.attrs["from"], "98765:2@lid")
    }

    func testHexPackedAttribute() throws {
        // All-uppercase-hex, no token match -> HEX_8 packed path.
        let node = BinaryNode(tag: "key", attrs: ["value": "DEADBEEF"])
        let decoded = try roundTrip(node)
        XCTAssertEqual(decoded.attrs["value"], "DEADBEEF")
    }

    func testOddLengthNibblePackedAttribute() throws {
        // Odd-length digit string exercises the padding-nibble branch.
        let node = BinaryNode(tag: "count", attrs: ["value": "12345"])
        let decoded = try roundTrip(node)
        XCTAssertEqual(decoded.attrs["value"], "12345")
    }

    func testEmptyContentIsPreservedAsNil() throws {
        let node = BinaryNode(tag: "active")
        let decoded = try roundTrip(node)
        XCTAssertNil(decoded.content)
    }

    func testDoubleByteTokenEncoding() throws {
        // "pair-device" lives in DOUBLE_BYTE_TOKENS dict 1, exercising the
        // DICTIONARY_n + index-byte path rather than a single-byte token.
        let node = BinaryNode(tag: "pair-device")
        let decoded = try roundTrip(node)
        XCTAssertEqual(decoded.tag, "pair-device")
    }

    func testJidDecodeEncodeHelpers() {
        let jid = jidDecode("15551234567:5@s.whatsapp.net")
        XCTAssertEqual(jid?.user, "15551234567")
        XCTAssertEqual(jid?.server, "s.whatsapp.net")
        XCTAssertEqual(jid?.device, 5)
        XCTAssertEqual(jid?.domainType, WAJIDDomain.whatsapp.rawValue)
        XCTAssertEqual(jidEncode(jid?.user, jid?.server ?? "", device: jid?.device), "15551234567:5@s.whatsapp.net")
    }

    func testJidDecodeLidDomain() {
        let jid = jidDecode("12345@lid")
        XCTAssertEqual(jid?.user, "12345")
        XCTAssertEqual(jid?.server, "lid")
        XCTAssertEqual(jid?.domainType, WAJIDDomain.lid.rawValue)
        XCTAssertNil(jid?.device)
    }

    func testUncompressedFlagByteStripped() throws {
        let node = BinaryNode(tag: "active")
        let encoded = try encodeBinaryNode(node)
        XCTAssertEqual(encoded.first, 0, "Baileys never sets the compression bit on outgoing frames")
    }

    func testZlibInflateRoundTrip() throws {
        // Sanity-check the CZlib binding independent of WABinary: compress
        // with system `zlib` via Foundation's stream, then confirm our
        // hand-rolled zlibInflate (used for the decode-time compression
        // flag) recovers the original bytes.
        let original = Data(repeating: 0x41, count: 5000) + Data("hello world".utf8)
        let compressed = try zlibDeflateForTesting(original)
        let inflated = try zlibInflate(compressed)
        XCTAssertEqual(inflated, original)
    }
}
