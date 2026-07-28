import Crypto
import Foundation

/// Thin wrappers over swift-crypto matching the primitives Baileys uses in
/// `src/Utils/crypto.ts`: X25519 key agreement, AES-256-GCM (ciphertext with
/// the 16-byte tag appended, matching Node's
/// `Buffer.concat([ciphertext, tag])` convention), HKDF-SHA256, SHA-256,
/// HMAC-SHA256, and MD5 (only used for the registration `buildHash`).
public enum WACrypto {
    public struct KeyPair {
        public let privateKey: Data
        public let publicKey: Data

        public init(privateKey: Data, publicKey: Data) {
            self.privateKey = privateKey
            self.publicKey = publicKey
        }
    }

    public static func generateX25519KeyPair() -> KeyPair {
        let priv = Curve25519.KeyAgreement.PrivateKey()
        return KeyPair(privateKey: priv.rawRepresentation, publicKey: priv.publicKey.rawRepresentation)
    }

    /// Raw X25519 shared secret (`Curve.sharedKey` in Baileys), not yet run
    /// through HKDF.
    public static func sharedKey(privateKey: Data, publicKey: Data) throws -> Data {
        let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
        let secret = try priv.sharedSecretFromKeyAgreement(with: pub)
        return secret.withUnsafeBytes { Data($0) }
    }

    public static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    public static func hmacSha256(key: Data, data: Data) -> Data {
        let mac = HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key))
        return Data(mac)
    }

    public static func md5(_ data: Data) -> Data {
        Data(Insecure.MD5.hash(data: data))
    }

    /// `HKDF-SHA256(ikm, salt, info) -> outputByteCount` bytes, matching
    /// Baileys' `hkdf` helper (`src/Utils/crypto.ts`).
    public static func hkdfSha256(ikm: Data, salt: Data = Data(), info: Data = Data(), outputByteCount: Int) -> Data {
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: salt,
            info: info,
            outputByteCount: outputByteCount
        )
        return key.withUnsafeBytes { Data($0) }
    }

    /// AES-256-GCM seal, returning `ciphertext || tag` (16-byte tag
    /// appended) to match Baileys' `aesEncryptGCM`.
    public static func aesEncryptGCM(plaintext: Data, key: Data, iv: Data, additionalData: Data = Data()) throws -> Data {
        let sealed = try AES.GCM.seal(
            plaintext,
            using: SymmetricKey(data: key),
            nonce: try AES.GCM.Nonce(data: iv),
            authenticating: additionalData
        )
        return sealed.ciphertext + sealed.tag
    }

    /// AES-256-GCM open, expecting `ciphertext || tag` (16-byte tag
    /// appended) to match Baileys' `aesDecryptGCM`.
    public static func aesDecryptGCM(ciphertextAndTag: Data, key: Data, iv: Data, additionalData: Data = Data()) throws -> Data {
        precondition(ciphertextAndTag.count >= 16, "ciphertext too short to contain a GCM tag")
        let tagStart = ciphertextAndTag.index(ciphertextAndTag.endIndex, offsetBy: -16)
        let ciphertext = ciphertextAndTag[ciphertextAndTag.startIndex..<tagStart]
        let tag = ciphertextAndTag[tagStart...]
        let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: iv), ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: additionalData)
    }
}
