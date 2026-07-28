import Foundation

/// Mirrors Baileys' `CompanionWebClientType` (`src/Utils/companion-reg-client-utils.ts`).
enum CompanionWebClientType: Int {
    case unknown = 0
    case chrome = 1
    case edge = 2
    case firefox = 3
    case ie = 4
    case opera = 5
    case safari = 6
    case electron = 7
    case uwp = 8
    case otherWebClient = 9
}

enum PairingQR {
    /// `getCompanionWebClientType`/`getCompanionPlatformId`
    /// (`src/Utils/companion-reg-client-utils.ts`).
    static func companionPlatformId(browser: (String, String, String)) -> String {
        let (os, browserName, _) = browser
        let type: CompanionWebClientType
        if browserName == "Desktop" {
            type = os == "Windows" ? .uwp : .electron
        } else {
            switch browserName {
            case "Chrome": type = .chrome
            case "Edge": type = .edge
            case "Firefox": type = .firefox
            case "IE": type = .ie
            case "Opera": type = .opera
            case "Safari": type = .safari
            default: type = .otherWebClient
            }
        }
        return String(type.rawValue)
    }

    /// `buildPairingQRData` (`src/Utils/companion-reg-client-utils.ts`) — the
    /// exact string to render as a QR code for `wa.me/settings/linked_devices`
    /// to scan.
    static func data(ref: String, noiseKeyB64: String, identityKeyB64: String, advB64: String, browser: (String, String, String)) -> String {
        let fields = [ref, noiseKeyB64, identityKeyB64, advB64, companionPlatformId(browser: browser)]
        return "https://wa.me/settings/linked_devices#" + fields.joined(separator: ",")
    }
}

enum PairingError: Error {
    case missingDeviceIdentity
    case invalidAccountSignature
    case invalidAccountHMAC
}

struct PairingResult {
    var reply: BinaryNode
    var me: WAContact
    var account: Proto_ADVSignedDeviceIdentity
    var signalIdentity: WASignalIdentity
    var platform: String?
}

enum Pairing {
    /// `createSignalIdentity` (`src/Utils/signal.ts`).
    private static func signalIdentity(lid: String, accountSignatureKey: Data) -> WASignalIdentity {
        var key = accountSignatureKey
        if key.count != 33 {
            key = Data([WAAuth.keyBundleType]) + key
        }
        return WASignalIdentity(identifier: WAProtocolAddress(name: lid, deviceId: 0), identifierKey: key)
    }

    /// `configureSuccessfulPairing` (`src/Utils/validate-connection.ts`):
    /// verifies the phone's ADV (Account/Device Verification) identity blob
    /// against our own `advSecretKey`, countersigns it, and builds the
    /// `pair-device-sign` reply node. Throws on any verification failure —
    /// callers should treat that as a fatal pairing error, not retry.
    static func configureSuccessfulPairing(stanza: BinaryNode, creds: AuthenticationCreds) throws -> PairingResult {
        let msgId = stanza.attrs["id"] ?? ""
        let pairSuccessNode = stanza.child("pair-success")
        let deviceIdentityNode = pairSuccessNode?.child("device-identity")
        let platformNode = pairSuccessNode?.child("platform")
        let deviceNode = pairSuccessNode?.child("device")
        let businessNode = pairSuccessNode?.child("biz")

        guard let deviceIdentityContent = deviceIdentityNode?.content?.bytesValue,
              let deviceNode, let jid = deviceNode.attrs["jid"] else {
            throw PairingError.missingDeviceIdentity
        }
        let lid = deviceNode.attrs["lid"]
        let bizName = businessNode?.attrs["name"]

        let identityHMAC = try Proto_ADVSignedDeviceIdentityHMAC(serializedBytes: deviceIdentityContent)

        var hmacPrefix = Data()
        if identityHMAC.accountType == .hosted {
            hmacPrefix = WADefaults.waAdvHostedAccountSigPrefix
        }
        guard let advSecretKeyData = Data(base64Encoded: creds.advSecretKey) else {
            throw PairingError.invalidAccountHMAC
        }
        let advSign = WACrypto.hmacSha256(key: advSecretKeyData, data: hmacPrefix + identityHMAC.details)
        guard advSign == identityHMAC.hmac else {
            throw PairingError.invalidAccountHMAC
        }

        var account = try Proto_ADVSignedDeviceIdentity(serializedBytes: identityHMAC.details)
        let deviceIdentity = try Proto_ADVDeviceIdentity(serializedBytes: account.details)

        let accountSigPrefix = deviceIdentity.deviceType == .hosted
            ? WADefaults.waAdvHostedAccountSigPrefix
            : WADefaults.waAdvAccountSigPrefix
        let accountMsg = accountSigPrefix + account.details + creds.signedIdentityKey.publicKey
        guard XEdDSA.verify(signature: account.accountSignature, publicKey: account.accountSignatureKey, message: accountMsg) else {
            throw PairingError.invalidAccountSignature
        }

        let deviceMsg = WADefaults.waAdvDeviceSigPrefix + account.details + creds.signedIdentityKey.publicKey + account.accountSignatureKey
        account.deviceSignature = try XEdDSA.sign(privateKey: creds.signedIdentityKey.privateKey, message: deviceMsg)

        let identity = signalIdentity(lid: lid ?? jid, accountSignatureKey: account.accountSignatureKey)

        // encodeSignedDeviceIdentity(account, includeSignatureKey: false): the
        // reply re-serializes `account` with `accountSignatureKey` cleared.
        var accountForReply = account
        accountForReply.clearAccountSignatureKey()
        let accountEnc = (try? accountForReply.serializedData()) ?? Data()

        let reply = BinaryNode(
            tag: "iq",
            attrs: ["to": "s.whatsapp.net", "type": "result", "id": msgId],
            content: .children([
                BinaryNode(
                    tag: "pair-device-sign",
                    content: .children([
                        BinaryNode(
                            tag: "device-identity",
                            attrs: ["key-index": String(deviceIdentity.keyIndex)],
                            content: .bytes(accountEnc)
                        )
                    ])
                )
            ])
        )

        return PairingResult(
            reply: reply,
            me: WAContact(id: jid, name: bizName, lid: lid),
            account: account,
            signalIdentity: identity,
            platform: platformNode?.attrs["name"]
        )
    }
}

extension BinaryNode {
    /// First child with the given tag, matching Baileys'
    /// `getBinaryNodeChild` (`src/WABinary/generic-utils.ts`).
    func child(_ tag: String) -> BinaryNode? {
        guard case .children(let children)? = content else { return nil }
        return children.first { $0.tag == tag }
    }
}

extension BinaryNodeContent {
    var bytesValue: Data? {
        switch self {
        case .bytes(let data): return data
        case .string(let str): return Data(str.utf8)
        case .children: return nil
        }
    }
}
