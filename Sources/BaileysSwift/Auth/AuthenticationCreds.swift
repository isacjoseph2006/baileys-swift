import Foundation

/// Mirrors Baileys' `SignedKeyPair` (`src/Types/Auth.ts`).
public struct WASignedKeyPair: Codable, Equatable {
    public var keyPair: WACrypto.KeyPair
    public var signature: Data
    public var keyId: Int

    public init(keyPair: WACrypto.KeyPair, signature: Data, keyId: Int) {
        self.keyPair = keyPair
        self.signature = signature
        self.keyId = keyId
    }
}

/// Mirrors Baileys' `Contact` as used for `creds.me` (id/name/lid only —
/// the full `Contact` type has more optional fields not needed here).
public struct WAContact: Codable, Equatable {
    public var id: String
    public var name: String?
    public var lid: String?

    public init(id: String, name: String? = nil, lid: String? = nil) {
        self.id = id
        self.name = name
        self.lid = lid
    }
}

/// Mirrors Baileys' `ProtocolAddress` (`src/Types/Auth.ts`).
public struct WAProtocolAddress: Codable, Equatable {
    public var name: String
    public var deviceId: Int

    public init(name: String, deviceId: Int) {
        self.name = name
        self.deviceId = deviceId
    }
}

/// Mirrors Baileys' `SignalIdentity`.
public struct WASignalIdentity: Codable, Equatable {
    public var identifier: WAProtocolAddress
    public var identifierKey: Data

    public init(identifier: WAProtocolAddress, identifierKey: Data) {
        self.identifier = identifier
        self.identifierKey = identifierKey
    }
}

/// Mirrors Baileys' `AccountSettings`.
public struct WAAccountSettings: Codable, Equatable {
    public var unarchiveChats: Bool

    public init(unarchiveChats: Bool = false) {
        self.unarchiveChats = unarchiveChats
    }
}

/// Mirrors Baileys' `AuthenticationCreds` (`src/Types/Auth.ts`). `account`
/// (a `proto.IADVSignedDeviceIdentity`) is stored as serialized protobuf
/// bytes (`accountData`) rather than the generated message type directly,
/// since SwiftProtobuf messages aren't `Codable` — `account` decodes/encodes
/// it lazily.
public struct AuthenticationCreds: Codable {
    public var noiseKey: WACrypto.KeyPair
    public var pairingEphemeralKeyPair: WACrypto.KeyPair
    public var signedIdentityKey: WACrypto.KeyPair
    public var signedPreKey: WASignedKeyPair
    public var registrationId: Int
    /// Base64-encoded, matching Baileys' `advSecretKey: string`.
    public var advSecretKey: String

    public var me: WAContact?
    public var accountData: Data?
    public var signalIdentities: [WASignalIdentity]
    public var firstUnuploadedPreKeyId: Int
    public var nextPreKeyId: Int
    public var accountSyncCounter: Int
    public var accountSettings: WAAccountSettings
    public var registered: Bool
    public var platform: String?
    public var routingInfo: Data?

    public var account: Proto_ADVSignedDeviceIdentity? {
        get { accountData.flatMap { try? Proto_ADVSignedDeviceIdentity(serializedBytes: $0) } }
        set { accountData = try? newValue?.serializedData() }
    }

    public init(
        noiseKey: WACrypto.KeyPair,
        pairingEphemeralKeyPair: WACrypto.KeyPair,
        signedIdentityKey: WACrypto.KeyPair,
        signedPreKey: WASignedKeyPair,
        registrationId: Int,
        advSecretKey: String,
        me: WAContact? = nil,
        accountData: Data? = nil,
        signalIdentities: [WASignalIdentity] = [],
        firstUnuploadedPreKeyId: Int = 1,
        nextPreKeyId: Int = 1,
        accountSyncCounter: Int = 0,
        accountSettings: WAAccountSettings = WAAccountSettings(),
        registered: Bool = false,
        platform: String? = nil,
        routingInfo: Data? = nil
    ) {
        self.noiseKey = noiseKey
        self.pairingEphemeralKeyPair = pairingEphemeralKeyPair
        self.signedIdentityKey = signedIdentityKey
        self.signedPreKey = signedPreKey
        self.registrationId = registrationId
        self.advSecretKey = advSecretKey
        self.me = me
        self.accountData = accountData
        self.signalIdentities = signalIdentities
        self.firstUnuploadedPreKeyId = firstUnuploadedPreKeyId
        self.nextPreKeyId = nextPreKeyId
        self.accountSyncCounter = accountSyncCounter
        self.accountSettings = accountSettings
        self.registered = registered
        self.platform = platform
        self.routingInfo = routingInfo
    }
}

public enum WAAuth {
    /// `KEY_BUNDLE_TYPE` (`src/Defaults/index.ts`) — the Signal-protocol
    /// "DJB Curve25519" version byte prefixed onto public keys for signing
    /// (not for XEdDSA verification itself, which always takes the raw
    /// 32-byte key — see `XEdDSA.swift`).
    static let keyBundleType: UInt8 = 5

    /// `generateRegistrationId` (`src/Utils/generics.ts`):
    /// `Uint16Array.from(randomBytes(2))[0] & 16383`. `Uint16Array.from` on a
    /// 2-byte source casts each byte independently into its own 16-bit slot
    /// rather than reinterpreting the pair as a combined value, so this is,
    /// bug-for-bug, just "one random byte" (range 0-255) — replicated as-is
    /// for fidelity since it's an opaque client-generated id WhatsApp
    /// doesn't validate the range of.
    public static func generateRegistrationId() -> Int {
        Int(WACrypto.randomBytes(1)[0]) & 16383
    }

    /// `signedKeyPair` (`src/Utils/crypto.ts`): signs the *version-byte
    /// prefixed* form of the prekey's public key (`[0x05] + pubKey`, i.e.
    /// Signal's "DJB Curve25519" pubkey encoding), not the raw 32-byte key.
    public static func signedKeyPair(identityKeyPair: WACrypto.KeyPair, keyId: Int) throws -> WASignedKeyPair {
        let preKey = WACrypto.generateX25519KeyPair()
        var prefixedPub = Data([keyBundleType])
        prefixedPub.append(preKey.publicKey)
        let signature = try XEdDSA.sign(privateKey: identityKeyPair.privateKey, message: prefixedPub)
        return WASignedKeyPair(keyPair: preKey, signature: signature, keyId: keyId)
    }

    /// `initAuthCreds` (`src/Utils/auth-utils.ts`) — fresh credentials for a
    /// brand-new (unpaired) session.
    public static func initAuthCreds() throws -> AuthenticationCreds {
        let identityKey = WACrypto.generateX25519KeyPair()
        return AuthenticationCreds(
            noiseKey: WACrypto.generateX25519KeyPair(),
            pairingEphemeralKeyPair: WACrypto.generateX25519KeyPair(),
            signedIdentityKey: identityKey,
            signedPreKey: try signedKeyPair(identityKeyPair: identityKey, keyId: 1),
            registrationId: generateRegistrationId(),
            advSecretKey: WACrypto.randomBytes(32).base64EncodedString()
        )
    }
}
