import XCTest
@testable import BaileysSwift

final class CryptoPrimitivesTests: XCTestCase {
    private func data(_ hex: String) -> Data {
        var bytes = [UInt8]()
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            bytes.append(UInt8(hex[idx..<next], radix: 16)!)
            idx = next
        }
        return Data(bytes)
    }

    // MARK: - Known-answer vectors (RFC / NIST), verified against sources fetched live in this session.

    func testSHA256KnownVector() {
        // NIST FIPS 180-2 example: SHA256("abc")
        let digest = WACrypto.sha256(Data("abc".utf8))
        XCTAssertEqual(digest.map { String(format: "%02x", $0) }.joined(),
                       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    func testMD5KnownVector() {
        // RFC 1321: MD5("abc")
        let digest = WACrypto.md5(Data("abc".utf8))
        XCTAssertEqual(digest.map { String(format: "%02x", $0) }.joined(),
                       "900150983cd24fb0d6963f7d28e17f72")
    }

    func testHMACSHA256KnownVector() {
        // RFC 4231 Test Case 1
        let key = data("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        let msg = Data("Hi There".utf8)
        let mac = WACrypto.hmacSha256(key: key, data: msg)
        XCTAssertEqual(mac.map { String(format: "%02x", $0) }.joined(),
                       "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    }

    func testHKDFSHA256KnownVector() {
        // RFC 5869 Appendix A.1
        let ikm = data("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        let salt = data("000102030405060708090a0b0c")
        let info = data("f0f1f2f3f4f5f6f7f8f9")
        let okm = WACrypto.hkdfSha256(ikm: ikm, salt: salt, info: info, outputByteCount: 42)
        XCTAssertEqual(okm.map { String(format: "%02x", $0) }.joined(),
                       "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    }

    func testX25519KnownVector() throws {
        // RFC 7748 §6.1
        let alicePriv = data("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let alicePub = data("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        let bobPriv = data("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        let bobPub = data("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        let expectedShared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

        XCTAssertEqual(alicePriv.count, 32)
        XCTAssertEqual(bobPriv.count, 32)

        let sharedFromAlice = try WACrypto.sharedKey(privateKey: alicePriv, publicKey: bobPub)
        let sharedFromBob = try WACrypto.sharedKey(privateKey: bobPriv, publicKey: alicePub)

        XCTAssertEqual(sharedFromAlice, sharedFromBob)
        XCTAssertEqual(sharedFromAlice.map { String(format: "%02x", $0) }.joined(), expectedShared)
    }

    func testAESGCMRoundTrip() throws {
        let key = Data((0..<32).map { UInt8($0) })
        let iv = Data((0..<12).map { UInt8($0 + 1) })
        let plaintext = Data("the quick brown fox jumps over the lazy dog".utf8)
        let aad = Data("associated-data".utf8)

        let sealed = try WACrypto.aesEncryptGCM(plaintext: plaintext, key: key, iv: iv, additionalData: aad)
        // ciphertext || 16-byte tag, matching Baileys' aesEncryptGCM convention.
        XCTAssertEqual(sealed.count, plaintext.count + 16)

        let opened = try WACrypto.aesDecryptGCM(ciphertextAndTag: sealed, key: key, iv: iv, additionalData: aad)
        XCTAssertEqual(opened, plaintext)
    }

    func testAESGCMTamperedTagFailsToOpen() throws {
        let key = Data(repeating: 0x11, count: 32)
        let iv = Data(repeating: 0x22, count: 12)
        let plaintext = Data("secret".utf8)

        var sealed = try WACrypto.aesEncryptGCM(plaintext: plaintext, key: key, iv: iv)
        sealed[sealed.count - 1] ^= 0xFF // corrupt the tag

        XCTAssertThrowsError(try WACrypto.aesDecryptGCM(ciphertextAndTag: sealed, key: key, iv: iv))
    }

    // MARK: - XEdDSA

    func testXEdDSASignAndVerifyRoundTrip() throws {
        let keyPair = WACrypto.generateX25519KeyPair()
        let message = Data("signed prekey payload".utf8)

        let signature = try XEdDSA.sign(privateKey: keyPair.privateKey, message: message)
        XCTAssertEqual(signature.count, 64)
        XCTAssertTrue(XEdDSA.verify(signature: signature, publicKey: keyPair.publicKey, message: message))
    }

    func testXEdDSAVerifyFailsForTamperedMessage() throws {
        let keyPair = WACrypto.generateX25519KeyPair()
        let message = Data("signed prekey payload".utf8)
        let signature = try XEdDSA.sign(privateKey: keyPair.privateKey, message: message)

        XCTAssertFalse(XEdDSA.verify(signature: signature, publicKey: keyPair.publicKey, message: Data("tampered".utf8)))
    }

    func testXEdDSAVerifyFailsForWrongKey() throws {
        let keyPair = WACrypto.generateX25519KeyPair()
        let otherKeyPair = WACrypto.generateX25519KeyPair()
        let message = Data("signed prekey payload".utf8)
        let signature = try XEdDSA.sign(privateKey: keyPair.privateKey, message: message)

        XCTAssertFalse(XEdDSA.verify(signature: signature, publicKey: otherKeyPair.publicKey, message: message))
    }

    func testXEdDSAManyRandomKeysRoundTrip() throws {
        // Exercises both branches of the sign-bit-forcing logic (the
        // Edwards public key's natural sign bit is a coin flip per key), so
        // run enough iterations to hit both with high probability.
        for _ in 0..<20 {
            let keyPair = WACrypto.generateX25519KeyPair()
            let message = XEdDSA.randomBytes(32)
            let signature = try XEdDSA.sign(privateKey: keyPair.privateKey, message: message)
            XCTAssertTrue(XEdDSA.verify(signature: signature, publicKey: keyPair.publicKey, message: message))
        }
    }
}
