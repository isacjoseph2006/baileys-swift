import Crypto
import Foundation

/// XEdDSA: sign/verify with a Curve25519 (X25519) keypair, per Signal's
/// "XEdDSA and VXEdDSA Using Curve25519" spec. WhatsApp (via Baileys' Noise
/// cert-chain verification and ADV device-identity signatures) reuses the
/// exact same scheme, ported here from the canonical reference
/// implementation `xeddsa.c` / `sign_modified.c` in
/// `signalapp/libsignal-protocol-c` (`src/curve25519/ed25519/additions/`).
///
/// The trick that makes this work: a clamped X25519 private scalar is,
/// bit-for-bit, also a valid Ed25519 signing scalar — Curve25519 (Montgomery)
/// and Edwards25519 (twisted Edwards) are birationally equivalent over the
/// same scalar field, so `scalar * basePoint` lands on the same curve group
/// either way. Signing forces the resulting Edwards public key's sign bit to
/// 0 (negating the scalar mod `L` if needed) because the Montgomery
/// `u`-coordinate the wire format actually carries has no sign information;
/// verification reconstructs `y = (u-1)/(u+1)` and always assumes sign 0 to
/// match.
public enum XEdDSA {
    public enum Error: Swift.Error {
        case invalidPrivateKeyLength
        case invalidPublicKeyLength
        case invalidSignatureLength
        case invalidPublicKeyEncoding
    }

    /// `a[0] &= 248; a[31] &= 127; a[31] |= 64;` — RFC 7748 X25519 scalar
    /// clamping, applied defensively so signing is correct regardless of
    /// whether the caller's private key bytes were already clamped (X25519
    /// clamps unconditionally on every use, so this is idempotent when they
    /// were).
    private static func clamped(_ scalar: [UInt8]) -> [UInt8] {
        var a = scalar
        a[0] &= 248
        a[31] &= 127
        a[31] |= 64
        return a
    }

    /// Signs `message` with a Curve25519 private key, matching
    /// `xed25519_sign`. `random` must be 64 bytes of fresh randomness per
    /// signature (mixed into the nonce derivation).
    public static func sign(privateKey: Data, message: Data, random: Data = randomBytes(64)) throws -> Data {
        guard privateKey.count == 32 else { throw Error.invalidPrivateKeyLength }
        precondition(random.count == 64, "XEdDSA requires 64 bytes of randomness")

        let a0 = clamped([UInt8](privateKey))
        let msg = [UInt8](message)
        let rnd = [UInt8](random)

        var A = Ed25519Field.packPoint(Ed25519Field.scalarBase(a0))
        let signBit = (A[31] & 0x80) >> 7
        let scalar = signBit == 1 ? Ed25519Field.scalarNegate(a0) : a0
        A[31] &= 0x7F

        // nonce = SHA512(0xFE || 0xFF*31 || scalar || message || random) mod L
        // The 0xFE/0xFF-filled prefix is a domain separator ensuring this
        // hash can never collide with a standard Ed25519 signature's
        // (seed-derived) nonce hash, whose input can't start that way for a
        // scalar produced by clamping (bit 254 of a valid scalar is always
        // set, but this specific all-0xFF-after-a-0xFE prefix pattern is
        // reserved for this construction only).
        var nonceInput: [UInt8] = [0xFE]
        nonceInput.append(contentsOf: [UInt8](repeating: 0xFF, count: 31))
        nonceInput.append(contentsOf: scalar)
        nonceInput.append(contentsOf: msg)
        nonceInput.append(contentsOf: rnd)
        let nonce = Ed25519Field.reduceModL(sha512(nonceInput))

        let R = Ed25519Field.packPoint(Ed25519Field.scalarBase(nonce))

        var hramInput = R
        hramInput.append(contentsOf: A)
        hramInput.append(contentsOf: msg)
        let hram = Ed25519Field.reduceModL(sha512(hramInput))

        let S = Ed25519Field.scalarMulAdd(hram, scalar, nonce)

        var signature = R
        signature.append(contentsOf: S)
        return Data(signature)
    }

    /// Verifies a signature produced by `sign` against the corresponding
    /// Curve25519 **public** key (the X25519 `u`-coordinate), matching
    /// `xed25519_verify`.
    public static func verify(signature: Data, publicKey: Data, message: Data) -> Bool {
        guard publicKey.count == 32 else { return false }
        guard signature.count == 64 else { return false }

        let u = [UInt8](publicKey)
        let sig = [UInt8](signature)
        let msg = [UInt8](message)

        let R = Array(sig[0..<32])
        let S = Array(sig[32..<64])

        // Strict scalar parsing: reject if any of S's top 3 bits are set
        // (i.e. S must be < 2^253, matching ref10's `sm[63] & 224` check).
        if S[31] & 0xE0 != 0 { return false }

        let A = Ed25519Field.montgomeryUToEdwardsY(u)
        guard let negA = Ed25519Field.unpackNeg(A) else { return false }

        var hramInput = R
        hramInput.append(contentsOf: A)
        hramInput.append(contentsOf: msg)
        let h = Ed25519Field.reduceModL(sha512(hramInput))

        let checkPoint = Ed25519Field.pointAdd(Ed25519Field.scalarMult(negA, h), Ed25519Field.scalarBase(S))
        let RCheck = Ed25519Field.packPoint(checkPoint)

        return RCheck == R
    }

    private static func sha512(_ bytes: [UInt8]) -> [UInt8] {
        Array(SHA512.hash(data: bytes))
    }

    public static func randomBytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        for i in 0..<count {
            bytes[i] = UInt8.random(in: 0...255)
        }
        return Data(bytes)
    }
}
