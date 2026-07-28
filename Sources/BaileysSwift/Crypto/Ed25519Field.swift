import Foundation

// Curve25519/Ed25519 field and group arithmetic, ported line-for-line from
// TweetNaCl (tweetnacl.c, public domain, Bernstein/Lange/Schwabe/et al,
// https://tweetnacl.cr.yp.to/). This file intentionally sticks to the exact
// TweetNaCl algorithm/variable structure rather than a from-scratch design —
// it's a widely reviewed, minimal reference implementation, which matters a
// lot more than elegance for hand-transliterated field arithmetic. Only the
// pieces needed for Ed25519 sign/verify are ported (no Salsa20/Poly1305/box).
//
// `GF` is a field element mod 2^255-19 in radix 2^16, 16 `Int64` limbs —
// TweetNaCl's `gf` type.
enum Ed25519Field {
    typealias GF = [Int64]

    static func gf(_ values: [Int64] = []) -> GF {
        var result = [Int64](repeating: 0, count: 16)
        for (i, v) in values.enumerated() { result[i] = v }
        return result
    }

    static let gf0: GF = gf()
    static let gf1: GF = gf([1])
    static let _121665: GF = gf([0xDB41, 1])
    static let D: GF = gf([0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203])
    static let D2: GF = gf([0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406])
    static let baseX: GF = gf([0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169])
    static let baseY: GF = gf([0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666])
    static let sqrtNeg1: GF = gf([0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83])

    /// Ed25519 group order `L = 2^252 + 27742317777372353535851937790883648493`.
    static let L: [Int64] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ]

    /// `L - 1`, used to compute `-a mod L` as `scMulAdd(lMinus1, a, 0)`.
    static let lMinus1: [UInt8] = [
        0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ]

    static func car25519(_ o: inout GF) {
        var c: Int64 = 0
        for i in 0..<16 {
            o[i] += 1 << 16
            c = o[i] >> 16
            let idx = (i + 1) * (i < 15 ? 1 : 0)
            o[idx] += c - 1 + 37 * (c - 1) * Int64(i == 15 ? 1 : 0)
            o[i] -= c << 16
        }
    }

    static func sel25519(_ p: inout GF, _ q: inout GF, _ b: Int64) {
        let c: Int64 = ~(b - 1)
        for i in 0..<16 {
            let t = c & (p[i] ^ q[i])
            p[i] ^= t
            q[i] ^= t
        }
    }

    static func pack25519(_ o: inout [UInt8], _ n: GF) {
        var m = gf()
        var t = n
        car25519(&t)
        car25519(&t)
        car25519(&t)
        for _ in 0..<2 {
            m[0] = t[0] &- 0xffed
            for i in 1..<15 {
                m[i] = t[i] &- 0xffff &- ((m[i - 1] >> 16) & 1)
                m[i - 1] &= 0xffff
            }
            m[15] = t[15] &- 0x7fff &- ((m[14] >> 16) & 1)
            let b = (m[15] >> 16) & 1
            m[14] &= 0xffff
            sel25519(&t, &m, 1 - b)
        }
        for i in 0..<16 {
            o[2 * i] = UInt8(truncatingIfNeeded: t[i] & 0xff)
            o[2 * i + 1] = UInt8(truncatingIfNeeded: t[i] >> 8)
        }
    }

    static func neq25519(_ a: GF, _ b: GF) -> Bool {
        var c = [UInt8](repeating: 0, count: 32)
        var d = [UInt8](repeating: 0, count: 32)
        pack25519(&c, a)
        pack25519(&d, b)
        return c != d
    }

    static func par25519(_ a: GF) -> UInt8 {
        var d = [UInt8](repeating: 0, count: 32)
        pack25519(&d, a)
        return d[0] & 1
    }

    static func unpack25519(_ n: [UInt8]) -> GF {
        var o = gf()
        for i in 0..<16 {
            o[i] = Int64(n[2 * i]) + (Int64(n[2 * i + 1]) << 8)
        }
        o[15] &= 0x7fff
        return o
    }

    static func add(_ a: GF, _ b: GF) -> GF {
        var o = gf()
        for i in 0..<16 { o[i] = a[i] + b[i] }
        return o
    }

    static func sub(_ a: GF, _ b: GF) -> GF {
        var o = gf()
        for i in 0..<16 { o[i] = a[i] - b[i] }
        return o
    }

    static func mul(_ a: GF, _ b: GF) -> GF {
        var t = [Int64](repeating: 0, count: 31)
        for i in 0..<16 {
            for j in 0..<16 {
                t[i + j] += a[i] * b[j]
            }
        }
        for i in 0..<15 {
            t[i] += 38 * t[i + 16]
        }
        var o = gf()
        for i in 0..<16 { o[i] = t[i] }
        car25519(&o)
        car25519(&o)
        return o
    }

    static func sq(_ a: GF) -> GF { mul(a, a) }

    static func inv25519(_ i: GF) -> GF {
        var c = i
        var a = 0
        for exp in stride(from: 253, through: 0, by: -1) {
            a = exp
            c = sq(c)
            if a != 2 && a != 4 { c = mul(c, i) }
        }
        return c
    }

    static func pow2523(_ i: GF) -> GF {
        var c = i
        for exp in stride(from: 250, through: 0, by: -1) {
            c = sq(c)
            if exp != 1 { c = mul(c, i) }
        }
        return c
    }

    // MARK: - Edwards point (extended coordinates X, Y, Z, T)

    struct EdPoint {
        var x: GF
        var y: GF
        var z: GF
        var t: GF

        static var zero: EdPoint { EdPoint(x: gf0, y: gf1, z: gf1, t: gf0) }
    }

    static func pointAdd(_ p: EdPoint, _ q: EdPoint) -> EdPoint {
        let a = mul(sub(p.y, p.x), sub(q.y, q.x))
        let b = mul(add(p.y, p.x), add(q.y, q.x))
        let c = mul(mul(p.t, q.t), D2)
        var d = mul(p.z, q.z)
        d = add(d, d)
        let e = sub(b, a)
        let f = sub(d, c)
        let g = add(d, c)
        let h = add(b, a)
        return EdPoint(x: mul(e, f), y: mul(h, g), z: mul(g, f), t: mul(e, h))
    }

    static func cswap(_ p: inout EdPoint, _ q: inout EdPoint, _ b: UInt8) {
        sel25519(&p.x, &q.x, Int64(b))
        sel25519(&p.y, &q.y, Int64(b))
        sel25519(&p.z, &q.z, Int64(b))
        sel25519(&p.t, &q.t, Int64(b))
    }

    static func packPoint(_ p: EdPoint) -> [UInt8] {
        var r = [UInt8](repeating: 0, count: 32)
        let zi = inv25519(p.z)
        let tx = mul(p.x, zi)
        let ty = mul(p.y, zi)
        pack25519(&r, ty)
        r[31] ^= par25519(tx) << 7
        return r
    }

    /// Variable-base scalar multiplication: `s * q`. `s` is a 32-byte
    /// little-endian scalar (may exceed `L`, e.g. a clamped X25519 scalar).
    static func scalarMult(_ q: EdPoint, _ s: [UInt8]) -> EdPoint {
        var p = EdPoint.zero
        var qVar = q
        for i in stride(from: 255, through: 0, by: -1) {
            let b = (s[i / 8] >> (i % 8)) & 1
            cswap(&p, &qVar, b)
            qVar = pointAdd(qVar, p)
            p = pointAdd(p, p)
            cswap(&p, &qVar, b)
        }
        return p
    }

    static func scalarBase(_ s: [UInt8]) -> EdPoint {
        let q = EdPoint(x: baseX, y: baseY, z: gf1, t: mul(baseX, baseY))
        return scalarMult(q, s)
    }

    /// Decodes a packed point and negates it (i.e. produces `-P`), matching
    /// TweetNaCl's `unpackneg` / ref10's `ge_frombytes_negate_vartime` — used
    /// only on the verification path.
    static func unpackNeg(_ p: [UInt8]) -> EdPoint? {
        var r = EdPoint.zero
        r.y = unpack25519(p)
        r.z = gf1
        let num0 = sq(r.y)
        var den = mul(num0, D)
        let num = sub(num0, r.z)
        den = add(r.z, den)

        let den2 = sq(den)
        let den4 = sq(den2)
        let den6 = mul(den4, den2)
        var t = mul(den6, num)
        t = mul(t, den)

        t = pow2523(t)
        t = mul(t, num)
        t = mul(t, den)
        t = mul(t, den)
        r.x = mul(t, den)

        var chk = sq(r.x)
        chk = mul(chk, den)
        if neq25519(chk, num) {
            r.x = mul(r.x, sqrtNeg1)
        }

        chk = sq(r.x)
        chk = mul(chk, den)
        if neq25519(chk, num) {
            return nil
        }

        if par25519(r.x) == (p[31] >> 7) {
            r.x = sub(gf0, r.x)
        }

        r.t = mul(r.x, r.y)
        return r
    }

    // MARK: - Scalar (mod L) arithmetic

    /// Reduces a 64-limb little-endian accumulator mod `L` to a 32-byte
    /// scalar, matching TweetNaCl's `modL`.
    static func modL(_ x: inout [Int64]) -> [UInt8] {
        var r = [UInt8](repeating: 0, count: 32)
        var i = 63
        while i >= 32 {
            var carry: Int64 = 0
            var j = i - 32
            while j < i - 12 {
                x[j] += carry - 16 * x[i] * L[j - (i - 32)]
                carry = (x[j] + 128) >> 8
                x[j] -= carry << 8
                j += 1
            }
            x[j] += carry
            x[i] = 0
            i -= 1
        }
        var carry: Int64 = 0
        for j in 0..<32 {
            x[j] += carry - (x[31] >> 4) * L[j]
            carry = x[j] >> 8
            x[j] &= 255
        }
        for j in 0..<32 {
            x[j] -= carry * L[j]
        }
        for j in 0..<32 {
            x[j + 1] += x[j] >> 8
            r[j] = UInt8(truncatingIfNeeded: x[j] & 255)
        }
        return r
    }

    /// Reduces an arbitrary-length little-endian byte string mod `L`
    /// (`reduce` in TweetNaCl, specialized here to a 64-byte hash output).
    static func reduceModL(_ input: [UInt8]) -> [UInt8] {
        precondition(input.count == 64)
        var x = [Int64](repeating: 0, count: 64)
        for i in 0..<64 { x[i] = Int64(input[i]) }
        return modL(&x)
    }

    /// `(h * a + r) mod L` for 32-byte little-endian `h`, `a`, `r` — the
    /// scalar step at the end of TweetNaCl's `crypto_sign`, generalized to
    /// take an explicit scalar `a` instead of one derived from a seed hash
    /// (needed for XEdDSA, which signs with an existing X25519 scalar).
    static func scalarMulAdd(_ h: [UInt8], _ a: [UInt8], _ r: [UInt8]) -> [UInt8] {
        var x = [Int64](repeating: 0, count: 64)
        for i in 0..<32 { x[i] = Int64(r[i]) }
        for i in 0..<32 {
            for j in 0..<32 {
                x[i + j] += Int64(h[i]) * Int64(a[j])
            }
        }
        return modL(&x)
    }

    /// `-a mod L`, matching `sc_neg` (implemented there as
    /// `scMulAdd(L-1, a, 0)`).
    static func scalarNegate(_ a: [UInt8]) -> [UInt8] {
        let zero = [UInt8](repeating: 0, count: 32)
        return scalarMulAdd(lMinus1, a, zero)
    }

    /// `y = (u - 1) / (u + 1) mod p` — converts a Curve25519 (Montgomery)
    /// `u`-coordinate to the corresponding Ed25519 (twisted Edwards)
    /// `y`-coordinate, matching `fe_montx_to_edy`.
    static func montgomeryUToEdwardsY(_ u: [UInt8]) -> [UInt8] {
        let uField = unpack25519(u)
        let one = gf1
        let umOne = sub(uField, one)
        let upOne = add(uField, one)
        let inv = inv25519(upOne)
        let y = mul(umOne, inv)
        var out = [UInt8](repeating: 0, count: 32)
        pack25519(&out, y)
        return out
    }
}
