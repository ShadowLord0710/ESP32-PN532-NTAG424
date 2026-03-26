/*
 * ESP32 + PN532 + NTAG424 DNA SDM Provisioning Tool
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 ShadowLord0710
 * 
 * This project uses:
 * - Adafruit PN532 NTAG424 Library
 * - Arduino Core libraries
 * - References NXP NTAG424 DNA specifications
 * 
 * See LICENSES.md for full attribution details
 */

#include <Arduino.h>
#include <SPI.h>
#include <Wire.h>
#include <esp_system.h>
#include <Adafruit_PN532_NTAG424.h>
#include <string.h>

// ============================================================================
// CONFIG
// ============================================================================
static const bool RUN_CHANGE_KEY = false;
static const bool RUN_WRITE_DYNAMIC_URL = true;
static const bool RUN_ENABLE_SDM = true;
static const bool DUMP_FILE_SETTINGS = true;
static const bool AUTO_DETECT_AUTH_KEY = true;
static const bool NDEF_WRITE_REQUIRES_AUTH = true;
static const bool DEBUG_TRY_BASELINE_VARIANT = false;
static const char *FW_DEBUG_TAG = "SDM-1BAR-DIAG-v2";

// Dynamic URL template with placeholders. NTAG424 SDM will mirror over these.
static const char *DYNAMIC_URL_TEMPLATE =
    "https://example.com/scan?uid=00000000000000&ctr=000000&cmac=0000000000000000";

// URI identifier 0x00 means no prefix compression.
static const uint8_t URI_IDENTIFIER = 0x00;

// File number 2 is the default NDEF file on NTAG424.
static const uint8_t NDEF_FILE_NO = 0x02;

// --------------------------------------------------------------------------
// POLICY MAPPING (adjust these to your real tag policy)
// --------------------------------------------------------------------------
// FACTORY-FRESH profile (new from manufacturer):
// - All AES keys are 00..00
// - Start with key0 for admin/config operations
// - Keep key change OFF until read/write/SDM flow works
// Authentication key used to change keys.
static const uint8_t POLICY_ADMIN_KEYNO = 0;

// Authentication key used to update NDEF payload.
static const uint8_t POLICY_NDEF_WRITE_KEYNO = 0;

// Authentication key used to change file settings / SDM config.
// According to your tag permissions: Change = 0x0, so use key0.
static const uint8_t POLICY_FILE_SETTINGS_KEYNO = 0;

// Nibble-based access rights for file settings:
// byte1 = (RW << 4) | CAR, byte2 = (R << 4) | W
static const uint8_t POLICY_AR_RW = 0xE;
static const uint8_t POLICY_AR_CAR = 0x0;
static const uint8_t POLICY_AR_R = 0xE;
static const uint8_t POLICY_AR_W = 0xE;

// SDM access-right bytes are policy dependent. Keep as explicit bytes.
// Configure SDM MAC-related access to use key1.
static const uint8_t POLICY_SDM_AR_B1 = 0xF1;
static const uint8_t POLICY_SDM_AR_B2 = 0xE1;

// SDM options: 0xC1 enables ASCII UID mirror + Read Counter mirror.
static const uint8_t POLICY_SDM_OPTIONS = 0xC1;

// ============================================================================
// PIN CONFIG
// ============================================================================
#define PN532_SCK 18
#define PN532_MOSI 23
#define PN532_SS 5
#define PN532_MISO 19


static Adafruit_PN532 nfc(PN532_SCK, PN532_MISO, PN532_MOSI, PN532_SS);

// ============================================================================
// KEYS
// ============================================================================
// OLD = current key on tag
static const uint8_t KEY0_OLD[16] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

static const uint8_t KEY1_OLD[16] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

static const uint8_t KEY2_OLD[16] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

static const uint8_t KEY3_OLD[16] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

// NEW = target key
static const uint8_t KEY0_NEW[16] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

static const uint8_t KEY1_NEW[16] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

static const uint8_t KEY2_NEW[16] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

static const uint8_t KEY3_NEW[16] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

struct AuthContext {
    bool valid;
    uint8_t keyNo;
    uint8_t cmd;
};

static const uint8_t *getKeyByNo(uint8_t keyNo, bool useNewKeys) {
    if (useNewKeys) {
        if (keyNo == 0) {
            return KEY0_NEW;
        }
        if (keyNo == 1) {
            return KEY1_NEW;
        }
        if (keyNo == 2) {
            return KEY2_NEW;
        }
        if (keyNo == 3) {
            return KEY3_NEW;
        }
        return nullptr;
    }

    if (keyNo == 0) {
        return KEY0_OLD;
    }
    if (keyNo == 1) {
        return KEY1_OLD;
    }
    if (keyNo == 2) {
        return KEY2_OLD;
    }
    if (keyNo == 3) {
        return KEY3_OLD;
    }
    return nullptr;
}

static void printHexLine(const char *label, const uint8_t *buf, size_t len) {
    Serial.print(label);
    for (size_t i = 0; i < len; ++i) {
        if (buf[i] < 0x10) {
            Serial.print('0');
        }
        Serial.print(buf[i], HEX);
        if (i + 1 < len) {
            Serial.print(' ');
        }
    }
    Serial.println();
}

static bool locateTag(uint8_t *uid, uint8_t *uidLength) {
    if (!nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, uidLength)) {
        return false;
    }

    if (!((*uidLength == 4) || (*uidLength == 7))) {
        Serial.println("UID length unsupported for this flow.");
        return false;
    }

    if (!nfc.ntag424_isNTAG424()) {
        Serial.println("Tag is not NTAG424.");
        return false;
    }

    return true;
}

static bool authenticateForPolicyKey(uint8_t keyNo, bool useNewKeys,
                                                                         const char *reason) {
    const uint8_t *key = getKeyByNo(keyNo, useNewKeys);
    if (!key) {
        Serial.println("Invalid keyNo in policy mapping.");
        return false;
    }

    Serial.print("Authenticate key");
    Serial.print(keyNo);
    Serial.print(" for ");
    Serial.println(reason);

    const uint8_t authCmdList[2] = {0x71, 0x77};
    for (size_t i = 0; i < 2; ++i) {
        if (nfc.ntag424_Authenticate((uint8_t *)key, keyNo, authCmdList[i]) == 1) {
            Serial.print("Authenticate OK with cmd 0x");
            Serial.println(authCmdList[i], HEX);
            return true;
        }
    }

    Serial.println("Authenticate failed.");
    return false;
}

static AuthContext detectAuthContext(bool useNewKeys) {
    AuthContext ctx = {false, 0, 0};
    const uint8_t authCmdList[2] = {0x71, 0x77};

    for (uint8_t keyNo = 0; keyNo < 4; ++keyNo) {
        const uint8_t *key = getKeyByNo(keyNo, useNewKeys);
        if (!key) {
            continue;
        }
        for (size_t i = 0; i < 2; ++i) {
            if (nfc.ntag424_Authenticate((uint8_t *)key, keyNo, authCmdList[i]) == 1) {
                ctx.valid = true;
                ctx.keyNo = keyNo;
                ctx.cmd = authCmdList[i];
                Serial.print("Detected auth key");
                Serial.print(ctx.keyNo);
                Serial.print(" cmd=0x");
                Serial.println(ctx.cmd, HEX);
                return ctx;
            }
        }
    }

    Serial.println("Auto-detect auth key failed (key0..3, cmd 0x71/0x77).");
    return ctx;
}

static bool authenticateForPolicyOrFallback(uint8_t policyKeyNo, bool useNewKeys,
                                                                                        const char *reason, const AuthContext &fallback) {
    if (authenticateForPolicyKey(policyKeyNo, useNewKeys, reason)) {
        return true;
    }

    if (!fallback.valid || fallback.keyNo == policyKeyNo) {
        Serial.println("Authenticate failed.");
        return false;
    }

    Serial.print("Fallback authenticate key");
    Serial.print(fallback.keyNo);
    Serial.print(" for ");
    Serial.println(reason);

    const uint8_t *fallbackKey = getKeyByNo(fallback.keyNo, useNewKeys);
    if (!fallbackKey) {
        return false;
    }

    if (nfc.ntag424_Authenticate((uint8_t *)fallbackKey, fallback.keyNo, fallback.cmd) == 1) {
        Serial.println("Fallback authenticate OK.");
        return true;
    }

    Serial.println("Fallback authenticate failed.");
    return false;
}

static bool runChangeKeys() {
    Serial.println("Changing keys (test flow 00..00 -> 00..00)...");
    bool ok = true;

    ok &= nfc.ntag424_ChangeKey((uint8_t *)KEY1_OLD, (uint8_t *)KEY1_NEW, 1);
    ok &= nfc.ntag424_ChangeKey((uint8_t *)KEY2_OLD, (uint8_t *)KEY2_NEW, 2);
    ok &= nfc.ntag424_ChangeKey((uint8_t *)KEY3_OLD, (uint8_t *)KEY3_NEW, 3);
    ok &= nfc.ntag424_ChangeKey((uint8_t *)KEY0_OLD, (uint8_t *)KEY0_NEW, 0);

    Serial.println(ok ? "ChangeKey sequence OK." : "ChangeKey sequence failed.");
    return ok;
}

static size_t buildNdefUriRecord(const char *url, uint8_t uriIdentifier,
                                                                 uint8_t *out, size_t outMax) {
    // Type 4 NDEF file: [NLEN(2 bytes)] [NDEF message]
    const size_t urlLen = strlen(url);
    const size_t payloadLen = 1 + urlLen; // 1 byte URI prefix + URL string
    const size_t ndefMsgLen = 5 + urlLen; // SR URI record header + payload
    const size_t totalLen = 2 + ndefMsgLen;

    if (totalLen > outMax || ndefMsgLen > 0xFF) {
        return 0;
    }

    out[0] = (uint8_t)((ndefMsgLen >> 8) & 0xFF);
    out[1] = (uint8_t)(ndefMsgLen & 0xFF);

    out[2] = 0xD1; // MB=1, ME=1, SR=1, TNF=Well Known
    out[3] = 0x01; // Type Length = 1
    out[4] = (uint8_t)payloadLen;
    out[5] = 0x55; // 'U' URI RTD
    out[6] = uriIdentifier;
    memcpy(out + 7, url, urlLen);

    return totalLen;
}

static uint32_t ndefUriPayloadOffset() {
    // NDEF layout built by buildNdefUriRecord:
    // [NLEN0][NLEN1][0xD1][TYPELEN][PAYLOADLEN][0x55][URI_ID][URL...]
    // URL text starts at offset 7.
    return 7;
}

static int findSubstrOffset(const char *haystack, const char *needle) {
    const char *p = strstr(haystack, needle);
    if (!p) {
        return -1;
    }
    return (int)(p - haystack);
}

static void put24le(uint8_t *dst, uint32_t value) {
    dst[0] = (uint8_t)(value & 0xFF);
    dst[1] = (uint8_t)((value >> 8) & 0xFF);
    dst[2] = (uint8_t)((value >> 16) & 0xFF);
}

static bool isApduStatusSuccess(const uint8_t *buf, size_t len) {
    if (len < 2) {
        return false;
    }
    // NTAG424 native response status word is typically 91 00 when successful.
    return (buf[len - 2] == 0x91 && buf[len - 1] == 0x00) ||
           (buf[len - 2] == 0x90 && buf[len - 1] == 0x00);
}

static uint8_t makeAccessByte(uint8_t highNibble, uint8_t lowNibble) {
    return (uint8_t)(((highNibble & 0x0F) << 4) | (lowNibble & 0x0F));
}

struct ParsedFileSettings {
    bool valid;
    bool statusOk;
    uint8_t fileType;
    uint8_t fileOption;
    uint8_t ar1;
    uint8_t ar2;
};

static ParsedFileSettings parseFileSettingsBasic(const uint8_t *fs, size_t fsLen) {
    ParsedFileSettings p = {false, false, 0, 0, 0, 0};
    if (!fs || fsLen < 6) {
        return p;
    }

    p.statusOk = isApduStatusSuccess(fs, fsLen);
    p.fileType = fs[0];
    p.fileOption = fs[1];
    p.ar1 = fs[2];
    p.ar2 = fs[3];
    p.valid = true;
    return p;
}

static void printParsedFileSettings(const ParsedFileSettings &p, const char *tag) {
    Serial.print(tag);
    Serial.print(" fileType=0x");
    Serial.print(p.fileType, HEX);
    Serial.print(" fileOption=0x");
    Serial.print(p.fileOption, HEX);
    Serial.print(" ar1=0x");
    Serial.print(p.ar1, HEX);
    Serial.print(" ar2=0x");
    Serial.print(p.ar2, HEX);
    Serial.print(" SDM=");
    Serial.println((p.fileOption & 0x40) ? "ON" : "OFF");
}

static void dumpFileSettingsRaw(const char *title) {
    uint8_t fs[64] = {0};
    const uint8_t fsLen = nfc.ntag424_GetFileSettings(
            NDEF_FILE_NO, fs, NTAG424_COMM_MODE_MAC);
    Serial.print(title);
    Serial.print(" len=");
    Serial.println(fsLen);
    if (fsLen > 0) {
        printHexLine("GetFileSettings: ", fs, fsLen);
        if (!isApduStatusSuccess(fs, fsLen)) {
            Serial.println("GetFileSettings status is NOT success.");
        }
        ParsedFileSettings parsed = parseFileSettingsBasic(fs, fsLen);
        if (parsed.valid) {
            printParsedFileSettings(parsed, "Parsed");
        }
    }
}

static size_t buildSdmFileSettingsForUrl(const char *url, uint8_t *out,
                                                                                 size_t outMax) {
    // Expected placeholders inside URL:
    // uid=00000000000000 (14 hex), ctr=000000 (6 hex), cmac=0000000000000000 (16 hex)
    const int uidPos = findSubstrOffset(url, "uid=");
    const int ctrPos = findSubstrOffset(url, "ctr=");
    const int cmacPos = findSubstrOffset(url, "cmac=");
    if (uidPos < 0 || ctrPos < 0 || cmacPos < 0) {
        return 0;
    }

    const uint32_t base = ndefUriPayloadOffset();
    const uint32_t uidOffset = base + (uint32_t)(uidPos + 4);
    const uint32_t ctrOffset = base + (uint32_t)(ctrPos + 4);
    const uint32_t cmacOffset = base + (uint32_t)(cmacPos + 5);
    const uint32_t cmacInputOffset = uidOffset;

    // This layout targets ASCII SDM with UID + ReadCounter mirroring + CMAC output.
    // Byte meaning follows NTAG424 ChangeFileSettings SDM layout.
    if (outMax < 18) {
        return 0;
    }

    size_t i = 0;
    out[i++] = 0x40; // FileOption: SDM enabled, plain communication
    out[i++] = makeAccessByte(POLICY_AR_RW, POLICY_AR_CAR);
    out[i++] = makeAccessByte(POLICY_AR_R, POLICY_AR_W);

    out[i++] = POLICY_SDM_OPTIONS;
    out[i++] = POLICY_SDM_AR_B1;
    out[i++] = POLICY_SDM_AR_B2;

    put24le(&out[i], uidOffset);
    i += 3;

    put24le(&out[i], ctrOffset);
    i += 3;

    put24le(&out[i], cmacInputOffset);
    i += 3;

    put24le(&out[i], cmacOffset);
    i += 3;

    return i;
}

static bool writeDynamicUrlNdef(const char *url) {
    uint8_t ndef[320] = {0};
    const size_t ndefLen = buildNdefUriRecord(url, URI_IDENTIFIER, ndef, sizeof(ndef));
    if (ndefLen == 0) {
        Serial.println("Failed to build NDEF payload.");
        return false;
    }

    Serial.print("Writing NDEF bytes: ");
    Serial.println((int)ndefLen);
    return nfc.ntag424_ISOUpdateBinary(ndef, (uint8_t)ndefLen);
}

static bool verifySdmBitAfterChange(uint8_t verifyKeyNo, bool useNewKeys,
                                                                        const AuthContext &fallback) {
    // After ChangeFileSettings the session may be invalid; always re-auth.
    if (!authenticateForPolicyOrFallback(verifyKeyNo, useNewKeys,
                                                                             "verify GetFileSettings", fallback)) {
        Serial.println("Re-auth before verify failed.");
        return false;
    }

    // GetFileSettings typically returns at least 9 bytes in this flow.
    uint8_t respProbe[64] = {0};
    const uint8_t verifyLen = nfc.ntag424_GetFileSettings(
            NDEF_FILE_NO, respProbe, NTAG424_COMM_MODE_MAC);
    Serial.print("Verify GetFileSettings len: ");
    Serial.println(verifyLen);
    if (verifyLen > 0) {
        printHexLine("Verify GetFileSettings: ", respProbe, verifyLen);
    }

    const ParsedFileSettings afterParsed = parseFileSettingsBasic(respProbe, verifyLen);
    const bool statusOk = isApduStatusSuccess(respProbe, verifyLen);
    if (afterParsed.valid) {
        printParsedFileSettings(afterParsed, "Parsed verify");
    }

    if (!statusOk) {
        Serial.println("ChangeFileSettings verify failed (status != 91 00).");
        return false;
    }

    if (!afterParsed.valid || ((afterParsed.fileOption & 0x40) == 0)) {
        Serial.println("SDM bit verify failed: FileOption bit6 is OFF (URL will stay static 0000).");
        return false;
    }

    return true;
}

static bool enableSdmForDynamicUrl(const char *url,
                                                                     uint8_t verifyKeyNo,
                                                                     bool useNewKeys,
                                                                     const AuthContext &fallback) {
    uint8_t currentFs[64] = {0};
    const uint8_t currentFsLen = nfc.ntag424_GetFileSettings(
            NDEF_FILE_NO, currentFs, NTAG424_COMM_MODE_MAC);

    uint8_t currentFileOption = 0x00;
    uint8_t currentAr1 = makeAccessByte(POLICY_AR_RW, POLICY_AR_CAR);
    uint8_t currentAr2 = makeAccessByte(POLICY_AR_R, POLICY_AR_W);

    // Typical decoded layout from GetFileSettings:
    // [FileType][FileOption][AR1][AR2][FileSize(3)] ... [SW1][SW2]
    ParsedFileSettings beforeParsed = parseFileSettingsBasic(currentFs, currentFsLen);
    if (beforeParsed.valid && beforeParsed.statusOk) {
        currentFileOption = beforeParsed.fileOption;
        currentAr1 = beforeParsed.ar1;
        currentAr2 = beforeParsed.ar2;
    }

    uint8_t fileSettings[24] = {0};
    const size_t fsLen = buildSdmFileSettingsForUrl(url, fileSettings, sizeof(fileSettings));
    if (fsLen == 0) {
        Serial.println("Failed to build SDM file settings (check URL placeholders).");
        return false;
    }

    // Keep comm mode bits and only force SDM bit. Reserved bits are kept clear.
    fileSettings[0] = (uint8_t)((currentFileOption & 0x03) | 0x40);
    fileSettings[1] = currentAr1;
    fileSettings[2] = currentAr2;

    if (DUMP_FILE_SETTINGS) {
        dumpFileSettingsRaw("Before ChangeFileSettings");
    }

    struct Candidate {
        uint8_t payload[24];
        uint8_t payloadLen;
        uint8_t commMode;
        const char *name;
    };

    uint8_t baselineNoSdm[3] = {currentFileOption, currentAr1, currentAr2};

    // Proven working payload from AN12196 / NT4H2421Gx mapping.
    // SDMOptions=C1, SDMAccessRights=F1E1, UIDOffset, CtrOffset,
    // SDMMACInputOffset=SDMMACOffset.
    uint8_t spec2B_F1E1_InputEqMac[18] = {
            (uint8_t)(0x40 | (currentFileOption & 0x03)), currentAr1, currentAr2,
            POLICY_SDM_OPTIONS, POLICY_SDM_AR_B1, POLICY_SDM_AR_B2,
            fileSettings[6], fileSettings[7], fileSettings[8],
            fileSettings[9], fileSettings[10], fileSettings[11],
            fileSettings[15], fileSettings[16], fileSettings[17],
            fileSettings[15], fileSettings[16], fileSettings[17]};

        Candidate runtimeCandidates[2] = {
            {{0}, 0, NTAG424_COMM_MODE_FULL, nullptr},
            {{0}, 0, NTAG424_COMM_MODE_FULL, nullptr}};
        size_t runtimeCandidateCount = 0;

        if (DEBUG_TRY_BASELINE_VARIANT) {
        memcpy(runtimeCandidates[runtimeCandidateCount].payload, baselineNoSdm, sizeof(baselineNoSdm));
        runtimeCandidates[runtimeCandidateCount].payloadLen = (uint8_t)sizeof(baselineNoSdm);
        runtimeCandidates[runtimeCandidateCount].commMode = NTAG424_COMM_MODE_FULL;
        runtimeCandidates[runtimeCandidateCount].name = "baseline no-SDM (diagnostic) + FULL";
        ++runtimeCandidateCount;
        }

        memcpy(runtimeCandidates[runtimeCandidateCount].payload, spec2B_F1E1_InputEqMac,
           sizeof(spec2B_F1E1_InputEqMac));
        runtimeCandidates[runtimeCandidateCount].payloadLen =
            (uint8_t)sizeof(spec2B_F1E1_InputEqMac);
        runtimeCandidates[runtimeCandidateCount].commMode = NTAG424_COMM_MODE_FULL;
        runtimeCandidates[runtimeCandidateCount].name =
            "spec 2B F1E1 UID+CTR+CMAC (MACInput=MACOffset) + FULL";
        ++runtimeCandidateCount;

    bool ok = false;
    for (size_t c = 0; c < runtimeCandidateCount; ++c) {

        Serial.print("Trying ChangeFileSettings variant: ");
        Serial.println(runtimeCandidates[c].name);
        printHexLine("FileSettings SDM: ", runtimeCandidates[c].payload,
                                 runtimeCandidates[c].payloadLen);

        const uint8_t respLen = nfc.ntag424_ChangeFileSettings(
                NDEF_FILE_NO,
                runtimeCandidates[c].payload,
                runtimeCandidates[c].payloadLen,
                runtimeCandidates[c].commMode);

        Serial.print("ChangeFileSettings response len: ");
        Serial.println(respLen);

        if (verifySdmBitAfterChange(verifyKeyNo, useNewKeys, fallback)) {
            ok = true;
            break;
        }
    }

    if (!ok) {
        Serial.println("All ChangeFileSettings variants failed to enable SDM.");
        if (DUMP_FILE_SETTINGS) {
            dumpFileSettingsRaw("After ChangeFileSettings");
        }
        return false;
    }

    if (DUMP_FILE_SETTINGS) {
        dumpFileSettingsRaw("After ChangeFileSettings");
    }

    return true;
}

void setup() {
    Serial.begin(115200);
    while (!Serial) {
        delay(10);
    }

    Serial.println();
    Serial.println("=== ESP32 PN532 NTAG424 Provisioning ===");
    Serial.print("Firmware tag: ");
    Serial.println(FW_DEBUG_TAG);

    nfc.begin();
    uint32_t versiondata = nfc.getFirmwareVersion();
    if (!versiondata) {
        Serial.println("PN532 not found.");
        while (true) {
            delay(1000);
        }
    }

    Serial.print("PN5");
    Serial.println((versiondata >> 24) & 0xFF, HEX);
    Serial.print("Firmware: ");
    Serial.print((versiondata >> 16) & 0xFF, DEC);
    Serial.print('.');
    Serial.println((versiondata >> 8) & 0xFF, DEC);

    nfc.SAMConfig();
    Serial.println("Tap NTAG424 to start...");
}

void loop() {
    uint8_t uid[7] = {0};
    uint8_t uidLength = 0;

    if (!locateTag(uid, &uidLength)) {
        delay(300);
        return;
    }

    printHexLine("Card UID: ", uid, uidLength);
    bool usingNewKeys = false;
    AuthContext detectedAuth = {false, 0, 0};

    if (AUTO_DETECT_AUTH_KEY) {
        detectedAuth = detectAuthContext(usingNewKeys);
    }

    if (RUN_CHANGE_KEY) {
        if (!authenticateForPolicyOrFallback(POLICY_ADMIN_KEYNO, false, "key change", detectedAuth)) {
            delay(1500);
            return;
        }
        if (!runChangeKeys()) {
            Serial.println("Stop due to key change error.");
            delay(2000);
            return;
        }
        usingNewKeys = true;
    }

    if (RUN_WRITE_DYNAMIC_URL) {
        if (NDEF_WRITE_REQUIRES_AUTH &&
            !authenticateForPolicyOrFallback(POLICY_NDEF_WRITE_KEYNO, usingNewKeys,
                                                                                             "NDEF update", detectedAuth)) {
            delay(1500);
            return;
        }
        if (!writeDynamicUrlNdef(DYNAMIC_URL_TEMPLATE)) {
            Serial.println("Write dynamic URL failed.");
            delay(2000);
            return;
        }
        Serial.println("Write dynamic URL OK.");
    }

    if (RUN_ENABLE_SDM) {
        if (!authenticateForPolicyOrFallback(POLICY_FILE_SETTINGS_KEYNO, usingNewKeys,
                                                                                         "ChangeFileSettings", detectedAuth)) {
            delay(1500);
            return;
        }
        if (!enableSdmForDynamicUrl(DYNAMIC_URL_TEMPLATE,
                                                                POLICY_FILE_SETTINGS_KEYNO,
                                                                usingNewKeys,
                                                                detectedAuth)) {
            Serial.println("Enable SDM failed.");
            delay(2000);
            return;
        }
        Serial.println("Enable SDM OK.");
    }

    Serial.println("Provision flow done. Remove and tap again for a new run.");
    delay(3000);
}

