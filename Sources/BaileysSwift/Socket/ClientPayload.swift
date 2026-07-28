import Foundation

/// Minimal stand-in for Baileys' `SocketConfig` — just the fields that
/// affect the `ClientPayload` sent inside the Noise handshake and the QR
/// pairing payload. Defaults match Baileys' `DEFAULT_CONNECTION_CONFIG`
/// (`src/Defaults/index.ts`) with `Browsers.macOS('Chrome')`.
public struct WAConnectionConfig {
    public var version: (UInt32, UInt32, UInt32)
    /// `(os, browser, browserVersion)`, e.g. `("Mac OS", "Chrome", "14.4.1")`.
    public var browser: (String, String, String)
    public var countryCode: String
    public var syncFullHistory: Bool

    public init(
        version: (UInt32, UInt32, UInt32) = (2, 3000, 1_035_194_821),
        browser: (String, String, String) = ("Mac OS", "Chrome", "14.4.1"),
        countryCode: String = "US",
        syncFullHistory: Bool = false
    ) {
        self.version = version
        self.browser = browser
        self.countryCode = countryCode
        self.syncFullHistory = syncFullHistory
    }
}

/// `encodeBigEndian` (`src/Utils/generics.ts`).
func encodeBigEndian(_ value: Int, byteCount: Int = 4) -> Data {
    var v = UInt32(truncatingIfNeeded: value)
    var bytes = [UInt8](repeating: 0, count: byteCount)
    for i in stride(from: byteCount - 1, through: 0, by: -1) {
        bytes[i] = UInt8(v & 0xFF)
        v >>= 8
    }
    return Data(bytes)
}

enum ClientPayloadBuilder {
    private static func userAgent(_ config: WAConnectionConfig) -> Proto_ClientPayload.UserAgent {
        var ua = Proto_ClientPayload.UserAgent()
        ua.appVersion.primary = config.version.0
        ua.appVersion.secondary = config.version.1
        ua.appVersion.tertiary = config.version.2
        ua.platform = config.browser.1.lowercased().contains("android") ? .android : .web
        ua.releaseChannel = .release
        ua.osVersion = "0.1"
        ua.device = "Desktop"
        ua.osBuildNumber = "0.1"
        ua.localeLanguageIso6391 = "en"
        ua.mnc = "000"
        ua.mcc = "000"
        ua.localeCountryIso31661Alpha2 = config.countryCode
        return ua
    }

    private static func webInfo(_ config: WAConnectionConfig) -> Proto_ClientPayload.WebInfo {
        var info = Proto_ClientPayload.WebInfo()
        info.webSubPlatform = .webBrowser
        return info
    }

    private static func basePayload(_ config: WAConnectionConfig) -> Proto_ClientPayload {
        var payload = Proto_ClientPayload()
        payload.connectType = .wifiUnknown
        payload.connectReason = .userActivated
        payload.userAgent = userAgent(config)
        if !config.browser.1.lowercased().contains("android") {
            payload.webInfo = webInfo(config)
        }
        return payload
    }

    /// `generateLoginNode` (`src/Utils/validate-connection.ts`) — used once
    /// `creds.me` is set (an already-paired device reconnecting).
    static func loginNode(userJid: String, config: WAConnectionConfig) -> Proto_ClientPayload {
        var payload = basePayload(config)
        let decoded = jidDecode(userJid)
        payload.passive = true
        payload.pull = true
        payload.username = UInt64(decoded?.user ?? "") ?? 0
        payload.device = UInt32(decoded?.device ?? 0)
        payload.lidDbMigrated = false
        return payload
    }

    /// `generateRegistrationNode` (`src/Utils/validate-connection.ts`) —
    /// used for first-time pairing (QR or pairing-code), before `creds.me`
    /// exists.
    static func registrationNode(creds: AuthenticationCreds, config: WAConnectionConfig) -> Proto_ClientPayload {
        var payload = basePayload(config)
        payload.passive = false
        payload.pull = false

        let versionString = "\(config.version.0).\(config.version.1).\(config.version.2)"
        let buildHash = WACrypto.md5(Data(versionString.utf8))

        var companion = Proto_DeviceProps()
        companion.os = config.browser.0
        companion.platformType = .chrome
        companion.requireFullSync = config.syncFullHistory
        companion.historySyncConfig.storageQuotaMb = 10240
        companion.historySyncConfig.inlineInitialPayloadInE2EeMsg = true
        companion.historySyncConfig.supportCallLogHistory = false
        companion.historySyncConfig.supportBotUserAgentChatHistory = true
        companion.historySyncConfig.supportCagReactionsAndPolls = true
        companion.historySyncConfig.supportBizHostedMsg = true
        companion.historySyncConfig.supportRecentSyncChunkMessageCountTuning = true
        companion.historySyncConfig.supportHostedGroupMsg = true
        companion.historySyncConfig.supportFbidBotChatHistory = true
        companion.historySyncConfig.supportMessageAssociation = true
        companion.historySyncConfig.supportGroupHistory = false
        companion.version.primary = 10
        companion.version.secondary = 15
        companion.version.tertiary = 7

        var pairingData = Proto_ClientPayload.DevicePairingRegistrationData()
        pairingData.buildHash = buildHash
        pairingData.deviceProps = (try? companion.serializedData()) ?? Data()
        pairingData.eRegid = encodeBigEndian(creds.registrationId)
        pairingData.eKeytype = Data([WAAuth.keyBundleType])
        pairingData.eIdent = creds.signedIdentityKey.publicKey
        pairingData.eSkeyID = encodeBigEndian(creds.signedPreKey.keyId, byteCount: 3)
        pairingData.eSkeyVal = creds.signedPreKey.keyPair.publicKey
        pairingData.eSkeySig = creds.signedPreKey.signature

        payload.devicePairingData = pairingData
        return payload
    }
}
