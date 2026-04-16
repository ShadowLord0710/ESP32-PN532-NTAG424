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
static const bool NDEF_WRITE_REQUIRES_AUTH = true;
static const bool NDEF_WRITE_ALLOW_NO_AUTH_FALLBACK = true;
static const bool NDEF_AUTH_TRY_ALL_KEYNOS = false;
static const char *FW_DEBUG_TAG = "SDM-1BAR-DIAG-v5";
static const uint8_t AUTH_CMD_LIST[2] = {0x71, 0x77};
static const uint8_t OP_MAX_RETRY = 3;
static const uint8_t SDM_ENABLE_MAX_RETRY = 1;
static const uint16_t OP_RETRY_DELAY_MS = 80;
static const uint32_t AUTH_FATAL_COOLDOWN_MS = 8000;

enum ErrorCode {
    E_NONE = 0,
    E100_BUILD_NDEF = 100,
    E110_AUTH = 110,
    E120_WRITE_NDEF = 120,
    E210_SDM_VERIFY = 210,
    E300_KEY_CHANGE = 300
};

// Dynamic URL template.
// Supported forms:
// 1) Encrypted PICC: e=...&c=...
// 2) ASCII SDM: uid=...&ctr=...&cmac=...
static const char *DYNAMIC_URL_TEMPLATE =
    "https://example.com/scan?e=00000000000000000000000000000000&c=0000000000000000";

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
// B1: RFU(4) + SDMCtrRet key(4) = 0xF1 (counter retention on key1)
// B2: SDMMetaRead key(4, high nibble) + SDMFileRead key(4, low nibble)
//     Format: 0x(MetaReadKey)(FileReadKey)
//     0x00 = key0+key0, 0x11 = key1+key1, 0x21 = key2 decrypt+key1 verify, etc.
static const uint8_t POLICY_SDM_AR_B1_ASCII = 0xF1;
static const uint8_t POLICY_SDM_AR_B1_ENC_PICC = 0xFF;
static const uint8_t POLICY_SDM_AR_B2_ASCII = 0xE1;      // MetaRead=free (E), FileRead=key1 (1)
// For e/c mode we only need MetaRead (for EncPICCData) + MAC.
// Disable SDM file data read (low nibble F) to avoid requiring ENC file offsets.
static const uint8_t POLICY_SDM_AR_B2_ENC_PICC = 0x0F;   // MetaRead=key0, FileRead=none
static const uint8_t POLICY_SDM_AR_B2_ENC_PICC_FREE_META = 0xEF; // MetaRead=free, FileRead=none
static const uint8_t POLICY_SDM_AR_B2_ENC_PICC_SPEC = 0xE1; // Spec-like fallback profile

static const uint8_t POLICY_SDM_OPTIONS_ASCII = 0xC1;     // ASCII UID + counter mirror
static const uint8_t POLICY_SDM_OPTIONS_ENC_PICC = 0xC5;  // Encrypted PICC + ASCII encoding
static const uint8_t POLICY_SDM_OPTIONS_ENC_PICC_ALT1 = 0xC3; // Alternate bit layout used by some NTAG424 variants
static const uint8_t POLICY_SDM_OPTIONS_ENC_PICC_ALT2 = 0xC7; // Alternate bit layout used by some NTAG424 variants

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

static uint16_t keyFingerprint16(const uint8_t key[16]) {
    uint16_t acc = 0xA5A5;
    for (uint8_t i = 0; i < 16; ++i) {
        acc ^= (uint16_t)(key[i] << (i & 0x07));
        acc = (uint16_t)((acc << 1) | (acc >> 15));
    }
    return acc;
}

static const uint8_t *getKeyByNo(uint8_t keyNo, bool useNewKeys) {
    if (keyNo > 3) {
        return nullptr;
    }

    static const uint8_t *const OLD_KEYS[4] = {
            KEY0_OLD, KEY1_OLD, KEY2_OLD, KEY3_OLD};
    static const uint8_t *const NEW_KEYS[4] = {
            KEY0_NEW, KEY1_NEW, KEY2_NEW, KEY3_NEW};

    return useNewKeys ? NEW_KEYS[keyNo] : OLD_KEYS[keyNo];
}

static void printStepLog(const uint8_t *uid, uint8_t uidLength,
                         const char *step, uint8_t attempt,
                         uint8_t maxAttempt, bool ok,
                         ErrorCode code) {
    Serial.print("[TAG uid=");
    for (uint8_t i = 0; i < uidLength; ++i) {
        if (uid[i] < 0x10) {
            Serial.print('0');
        }
        Serial.print(uid[i], HEX);
    }
    Serial.print("] [STEP ");
    Serial.print(step);
    Serial.print("] [TRY ");
    Serial.print(attempt);
    Serial.print('/');
    Serial.print(maxAttempt);
    Serial.print("] [RESULT ");
    Serial.print(ok ? "OK" : "FAIL");
    if (!ok) {
        Serial.print(":E");
        Serial.print((int)code);
    }
    Serial.println(']');
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

    // Some reads right after anti-collision can transiently fail type detect;
    // retry briefly before concluding this is not an NTAG424 tag.
    bool isNtag424 = false;
    for (uint8_t i = 0; i < 3; ++i) {
        if (nfc.ntag424_isNTAG424()) {
            isNtag424 = true;
            break;
        }
        delay(20);
    }

    if (!isNtag424) {
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

    for (uint8_t cmd : AUTH_CMD_LIST) {
        const int authResult = nfc.ntag424_Authenticate((uint8_t *)key, keyNo, cmd);
        if (authResult == 1) {
            Serial.print("Authenticate OK with cmd 0x");
            Serial.println(cmd, HEX);
            return true;
        }
        Serial.print("Authenticate cmd 0x");
        Serial.print(cmd, HEX);
        Serial.println(" failed.");
    }

    Serial.println("Authenticate failed.");
    return false;
}

static bool authenticateForPolicyKeyRetry(const uint8_t *uid,
                                          uint8_t uidLength,
                                          const char *step,
                                          uint8_t keyNo,
                                          bool useNewKeys) {
    for (uint8_t attempt = 1; attempt <= OP_MAX_RETRY; ++attempt) {
        const bool ok = authenticateForPolicyKey(keyNo, useNewKeys, step);
        printStepLog(uid, uidLength, step, attempt, OP_MAX_RETRY, ok, E110_AUTH);
        if (ok) {
            return true;
        }
        delay(OP_RETRY_DELAY_MS);
    }
    return false;
}

static bool authenticateForAnyKeyNo(bool useNewKeys,
                                    const char *reason,
                                    uint8_t preferredKeyNo,
                                    uint8_t &selectedKeyNo) {
    // Try preferred key first, then scan remaining key numbers 0..3.
    for (uint8_t phase = 0; phase < 2; ++phase) {
        for (uint8_t keyNo = 0; keyNo <= 3; ++keyNo) {
            if ((phase == 0 && keyNo != preferredKeyNo) ||
                (phase == 1 && keyNo == preferredKeyNo)) {
                continue;
            }

            if (authenticateForPolicyKey(keyNo, useNewKeys, reason)) {
                selectedKeyNo = keyNo;
                return true;
            }
        }
    }
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

    if (totalLen > outMax || ndefMsgLen > 0xFF || totalLen > 0xFF) {
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

// Locate placeholder values after '=' for ASCII SDM URL fields.
static int findPlaceholderStart(const char *haystack, const char *key) {
    const char *p = strstr(haystack, key);
    if (!p) return -1;
    return (int)(p - haystack) + (int)strlen(key);
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

static bool buildSdmOffsetsFromUrl(const char *url,
                                   bool &encryptedPiccMode,
                                   uint32_t &uidOrEncPiccOffset,
                                   uint32_t &ctrOffset,
                                   uint32_t &cmacInputOffset,
                                   uint32_t &cmacOffset) {
    const int ePos = findPlaceholderStart(url, "e=");
    const int cPos = findPlaceholderStart(url, "c=");
    if (ePos >= 0 && cPos >= 0) {
        const uint32_t base = ndefUriPayloadOffset();
        encryptedPiccMode = true;
        uidOrEncPiccOffset = base + (uint32_t)ePos;
        ctrOffset = 0;
        cmacInputOffset = uidOrEncPiccOffset;
        cmacOffset = base + (uint32_t)cPos;
        return true;
    }

    const int uidPos = findPlaceholderStart(url, "uid=");
    const int ctrPos = findPlaceholderStart(url, "ctr=");
    const int cmacPos = findPlaceholderStart(url, "cmac=");
    if (uidPos < 0 || ctrPos < 0 || cmacPos < 0) {
        return false;
    }

    const uint32_t base = ndefUriPayloadOffset();
    encryptedPiccMode = false;
    uidOrEncPiccOffset = base + (uint32_t)uidPos;
    ctrOffset = base + (uint32_t)ctrPos;
    cmacOffset = base + (uint32_t)cmacPos;
    cmacInputOffset = uidOrEncPiccOffset;
    return true;
}

static bool writeDynamicUrlNdefWithRetry(const uint8_t *uid,
                                         uint8_t uidLength,
                                         const char *url,
                                         uint8_t maxAttempt) {
    uint8_t ndef[320] = {0};
    const size_t ndefLen = buildNdefUriRecord(url, URI_IDENTIFIER, ndef, sizeof(ndef));
    if (ndefLen == 0) {
        printStepLog(uid, uidLength, "NDEF_BUILD", 1, 1, false, E100_BUILD_NDEF);
        return false;
    }
    printStepLog(uid, uidLength, "NDEF_BUILD", 1, 1, true, E_NONE);

    for (uint8_t attempt = 1; attempt <= maxAttempt; ++attempt) {
        const bool writeOk = nfc.ntag424_ISOUpdateBinary(ndef, (uint8_t)ndefLen);
        printStepLog(uid, uidLength, "NDEF_WRITE", attempt, maxAttempt, writeOk, E120_WRITE_NDEF);
        if (writeOk) {
            return true;
        }
        delay(OP_RETRY_DELAY_MS);
    }
    return false;
}

static bool verifySdmBitAfterChange(uint8_t verifyKeyNo, bool useNewKeys) {
    // After ChangeFileSettings the session may be invalid; always re-auth.
    if (!authenticateForPolicyKey(verifyKeyNo, useNewKeys,
                                  "verify GetFileSettings")) {
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
                                                                     bool useNewKeys) {
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

    bool encryptedPiccMode = false;
    uint32_t uidOrEncPiccOffset = 0, ctrOffset = 0, cmacInputOffset = 0, cmacOffset = 0;
    if (!buildSdmOffsetsFromUrl(url,
                                encryptedPiccMode,
                                uidOrEncPiccOffset,
                                ctrOffset,
                                cmacInputOffset,
                                cmacOffset)) {
        Serial.println("Failed to build SDM offsets (check URL placeholders e/c or uid/ctr/cmac).");
        return false;
    }

    dumpFileSettingsRaw("Before ChangeFileSettings");

    // Diagnostic probe: verify ChangeFileSettings permission/session with a no-op
    // payload before trying SDM-specific encodings.
    {
        uint8_t noOpPayload[3] = {currentFileOption, currentAr1, currentAr2};
        Serial.println("Probe ChangeFileSettings: no-op payload (FileOption/AR unchanged)");
        printHexLine("FileSettings probe: ", noOpPayload, sizeof(noOpPayload));

        const uint8_t probeLen = nfc.ntag424_ChangeFileSettings(
                NDEF_FILE_NO,
                noOpPayload,
                (uint8_t)sizeof(noOpPayload),
                NTAG424_COMM_MODE_FULL);
        Serial.print("Probe ChangeFileSettings response len: ");
        Serial.println(probeLen);
        if (probeLen == 0) {
            Serial.println("Probe transport failure (len=0). Aborting this SDM attempt.");
            return false;
        }

        // Re-auth immediately so subsequent reads/writes start a fresh session.
        if (!authenticateForPolicyKey(verifyKeyNo, useNewKeys,
                                      "post-probe re-auth")) {
            Serial.println("Post-probe re-auth failed.");
            return false;
        }
    }

    if (encryptedPiccMode) {
        // Some NTAG424 variants reject one specific SDM layout with 91 9E.
        // Try a small set of known-compatible C5 payload encodings and stop
        // at the first one that verifies FileOption bit6 as ON.
        uint8_t payloadA[18] = {0}; // includes MAC input offset
        payloadA[0] = (uint8_t)(0x40 | (currentFileOption & 0x03));
        payloadA[1] = currentAr1;
        payloadA[2] = currentAr2;
        payloadA[3] = POLICY_SDM_OPTIONS_ENC_PICC;
        payloadA[4] = POLICY_SDM_AR_B1_ENC_PICC;
        payloadA[5] = POLICY_SDM_AR_B2_ENC_PICC;
        put24le(&payloadA[6], uidOrEncPiccOffset);
        put24le(&payloadA[9], cmacInputOffset);
        put24le(&payloadA[12], cmacOffset);

        uint8_t payloadB[15] = {0}; // compact layout without explicit MAC input offset
        payloadB[0] = (uint8_t)(0x40 | (currentFileOption & 0x03));
        payloadB[1] = currentAr1;
        payloadB[2] = currentAr2;
        payloadB[3] = POLICY_SDM_OPTIONS_ENC_PICC;
        payloadB[4] = POLICY_SDM_AR_B1_ENC_PICC;
        payloadB[5] = POLICY_SDM_AR_B2_ENC_PICC;
        put24le(&payloadB[6], uidOrEncPiccOffset);
        put24le(&payloadB[9], cmacOffset);

        uint8_t payloadC[18] = {0}; // fallback for tags that require retained ctr key nibble
        memcpy(payloadC, payloadA, sizeof(payloadA));
        payloadC[4] = POLICY_SDM_AR_B1_ASCII;

        uint8_t payloadD[18] = {0}; // fallback with free MetaRead
        memcpy(payloadD, payloadA, sizeof(payloadA));
        payloadD[5] = POLICY_SDM_AR_B2_ENC_PICC_FREE_META;

        uint8_t payloadE[18] = {0}; // free MetaRead + retained ctr key nibble
        memcpy(payloadE, payloadC, sizeof(payloadC));
        payloadE[5] = POLICY_SDM_AR_B2_ENC_PICC_FREE_META;

        uint8_t payloadF[18] = {0}; // alt SDMOptions profile with same offsets
        memcpy(payloadF, payloadA, sizeof(payloadA));
        payloadF[3] = POLICY_SDM_OPTIONS_ENC_PICC_ALT1;

        uint8_t payloadG[18] = {0}; // second alt SDMOptions profile
        memcpy(payloadG, payloadA, sizeof(payloadA));
        payloadG[3] = POLICY_SDM_OPTIONS_ENC_PICC_ALT2;

        // Spec-like 4-offset layouts for encrypted mode.
        uint8_t payloadH[18] = {0};
        payloadH[0] = (uint8_t)(0x40 | (currentFileOption & 0x03));
        payloadH[1] = currentAr1;
        payloadH[2] = currentAr2;
        payloadH[3] = POLICY_SDM_OPTIONS_ENC_PICC;
        payloadH[4] = POLICY_SDM_AR_B1_ASCII;
        payloadH[5] = POLICY_SDM_AR_B2_ENC_PICC_SPEC;
        put24le(&payloadH[6], 0);                  // slot#1
        put24le(&payloadH[9], uidOrEncPiccOffset); // slot#2
        put24le(&payloadH[12], cmacOffset);        // slot#3
        put24le(&payloadH[15], cmacOffset);        // slot#4

        uint8_t payloadI[18] = {0};
        payloadI[0] = (uint8_t)(0x40 | (currentFileOption & 0x03));
        payloadI[1] = currentAr1;
        payloadI[2] = currentAr2;
        payloadI[3] = POLICY_SDM_OPTIONS_ENC_PICC;
        payloadI[4] = POLICY_SDM_AR_B1_ASCII;
        payloadI[5] = POLICY_SDM_AR_B2_ENC_PICC_SPEC;
        put24le(&payloadI[6], uidOrEncPiccOffset); // slot#1
        put24le(&payloadI[9], 0);                  // slot#2
        put24le(&payloadI[12], cmacOffset);        // slot#3
        put24le(&payloadI[15], cmacOffset);        // slot#4

        uint8_t payloadJ[18] = {0};
        memcpy(payloadJ, payloadH, sizeof(payloadH));
        payloadJ[3] = POLICY_SDM_OPTIONS_ENC_PICC_ALT1;

        uint8_t payloadK[18] = {0};
        memcpy(payloadK, payloadH, sizeof(payloadH));
        payloadK[3] = POLICY_SDM_OPTIONS_ENC_PICC_ALT2;
        payloadK[4] = POLICY_SDM_AR_B1_ENC_PICC;

        // Alternate offset basis for tags that interpret offsets from NDEF payload
        // start without the 2-byte NLEN prefix.
        const uint32_t uidOrEncPiccOffsetNoNlen =
                (uidOrEncPiccOffset >= 2) ? (uidOrEncPiccOffset - 2) : uidOrEncPiccOffset;
        const uint32_t cmacInputOffsetNoNlen =
                (cmacInputOffset >= 2) ? (cmacInputOffset - 2) : cmacInputOffset;
        const uint32_t cmacOffsetNoNlen =
                (cmacOffset >= 2) ? (cmacOffset - 2) : cmacOffset;

        uint8_t payloadL[18] = {0};
        memcpy(payloadL, payloadA, sizeof(payloadA));
        put24le(&payloadL[6], uidOrEncPiccOffsetNoNlen);
        put24le(&payloadL[9], cmacInputOffsetNoNlen);
        put24le(&payloadL[12], cmacOffsetNoNlen);

        uint8_t payloadM[15] = {0};
        memcpy(payloadM, payloadB, sizeof(payloadB));
        put24le(&payloadM[6], uidOrEncPiccOffsetNoNlen);
        put24le(&payloadM[9], cmacOffsetNoNlen);

        // Spec-based encrypted e/c profiles from NTAG424 docs:
        // - SDMOptions C1 profile
        // - SDMFileRead key must not be F for encrypted SDM flow
        // - Use PICCDataOffset + SDMMACOffset + SDMMACInputOffset
        uint8_t payloadN[15] = {0};
        payloadN[0] = (uint8_t)(0x40 | (currentFileOption & 0x03));
        payloadN[1] = currentAr1;
        payloadN[2] = currentAr2;
        payloadN[3] = 0xC1; // spec-style SDM options profile
        payloadN[4] = 0xF1;
        payloadN[5] = 0x01; // MetaRead=key0, FileRead=key1
        put24le(&payloadN[6], uidOrEncPiccOffset); // ENC PICC data offset
        put24le(&payloadN[9], cmacOffset);         // SDMMAC offset
        put24le(&payloadN[12], cmacOffset);        // empty MAC input region

        uint8_t payloadO[15] = {0};
        memcpy(payloadO, payloadN, sizeof(payloadN));
        payloadO[5] = 0x11; // MetaRead=key1, FileRead=key1

        uint8_t payloadP[15] = {0};
        memcpy(payloadP, payloadN, sizeof(payloadN));
        payloadP[5] = 0x21; // MetaRead=key2, FileRead=key1 (AN12196 style)

        uint8_t payloadQ[15] = {0};
        memcpy(payloadQ, payloadN, sizeof(payloadN));
        put24le(&payloadQ[12], uidOrEncPiccOffset); // MAC input starts at ENC PICC data

        uint8_t payloadR[15] = {0};
        memcpy(payloadR, payloadN, sizeof(payloadN));
        put24le(&payloadR[6], uidOrEncPiccOffsetNoNlen);
        put24le(&payloadR[9], cmacOffsetNoNlen);
        put24le(&payloadR[12], cmacOffsetNoNlen);

        uint8_t payloadS[15] = {0};
        memcpy(payloadS, payloadQ, sizeof(payloadQ));
        put24le(&payloadS[6], uidOrEncPiccOffsetNoNlen);
        put24le(&payloadS[9], cmacOffsetNoNlen);
        put24le(&payloadS[12], uidOrEncPiccOffsetNoNlen);

        const uint8_t *candidatePayloads[19] = {
            payloadN, payloadO, payloadP, payloadQ, payloadR, payloadS,
            payloadA, payloadB, payloadC, payloadD, payloadE,
            payloadF, payloadG, payloadH, payloadI, payloadJ, payloadK,
            payloadL, payloadM
        };
        const uint8_t candidateLens[19] = {
            sizeof(payloadN), sizeof(payloadO), sizeof(payloadP), sizeof(payloadQ), sizeof(payloadR), sizeof(payloadS),
            sizeof(payloadA), sizeof(payloadB), sizeof(payloadC), sizeof(payloadD), sizeof(payloadE),
            sizeof(payloadF), sizeof(payloadG), sizeof(payloadH), sizeof(payloadI), sizeof(payloadJ), sizeof(payloadK),
            sizeof(payloadL), sizeof(payloadM)
        };
        const char *candidateNames[19] = {
            "SPEC variant N (15B, Opt=C1, B1=F1, B2=01, slots=E,C,C)",
            "SPEC variant O (15B, Opt=C1, B1=F1, B2=11, slots=E,C,C)",
            "SPEC variant P (15B, Opt=C1, B1=F1, B2=21, slots=E,C,C)",
            "SPEC variant Q (15B, Opt=C1, B1=F1, B2=01, slots=E,C,E)",
            "SPEC variant R (15B, Opt=C1, B1=F1, B2=01, no-NLEN, slots=E,C,C)",
            "SPEC variant S (15B, Opt=C1, B1=F1, B2=01, no-NLEN, slots=E,C,E)",
            "C5 variant A (18B, B1=FF, B2=0F, with MAC input)",
            "C5 variant B (15B, B1=FF, B2=0F, compact)",
            "C5 variant C (18B, B1=F1, B2=0F, with MAC input)",
            "C5 variant D (18B, B1=FF, B2=EF, with MAC input)",
            "C5 variant E (18B, B1=F1, B2=EF, with MAC input)",
            "ALT variant F (18B, Opt=C3, B1=FF, B2=0F)",
            "ALT variant G (18B, Opt=C7, B1=FF, B2=0F)",
            "SPEC variant H (18B, Opt=C5, B1=F1, B2=E1, slots=0,E,C,C)",
            "SPEC variant I (18B, Opt=C5, B1=F1, B2=E1, slots=E,0,C,C)",
            "SPEC variant J (18B, Opt=C3, B1=F1, B2=E1, slots=0,E,C,C)",
            "SPEC variant K (18B, Opt=C7, B1=FF, B2=E1, slots=0,E,C,C)",
            "C5 variant L (18B, A-style offsets without NLEN)",
            "C5 variant M (15B, B-style offsets without NLEN)"
        };

        for (uint8_t i = 0; i < 19; ++i) {
            Serial.print("Requesting ChangeFileSettings: ");
            Serial.println(candidateNames[i]);
            printHexLine("FileSettings SDM: ", candidatePayloads[i], candidateLens[i]);

            const uint8_t respLen = nfc.ntag424_ChangeFileSettings(
                    NDEF_FILE_NO,
                    (uint8_t *)candidatePayloads[i],
                    candidateLens[i],
                    NTAG424_COMM_MODE_FULL);

            Serial.print("ChangeFileSettings response len: ");
            Serial.println(respLen);

            // PN532/transport failure (e.g. D5 41 0B): abort this attempt and
            // require a fresh tap to avoid cascading auth/session errors.
            if (respLen == 0) {
                Serial.println("ChangeFileSettings transport failure (len=0). Aborting this SDM attempt.");
                return false;
            }

            const bool ok = verifySdmBitAfterChange(verifyKeyNo, useNewKeys);
            if (ok) {
                dumpFileSettingsRaw("After ChangeFileSettings (success)");
                return true;
            }

            Serial.println("ChangeFileSettings verification failed.");
            dumpFileSettingsRaw("After ChangeFileSettings (failed)");
        }

        return false;
    } else {
        uint8_t sdmPayload[18] = {0};
        sdmPayload[0] = (uint8_t)(0x40 | (currentFileOption & 0x03));
        sdmPayload[1] = currentAr1;
        sdmPayload[2] = currentAr2;

        // ASCII payload (18 bytes):
        // [FileOption|AR1|AR2|SDMOptions|SDMCtrRet|Meta+FileRead|UIDOff(3)|CtrOff(3)|MacInputOff(3)|MacOff(3)]
        sdmPayload[3] = POLICY_SDM_OPTIONS_ASCII;
        sdmPayload[4] = POLICY_SDM_AR_B1_ASCII;
        sdmPayload[5] = POLICY_SDM_AR_B2_ASCII;
        put24le(&sdmPayload[6], uidOrEncPiccOffset);
        put24le(&sdmPayload[9], ctrOffset);
        put24le(&sdmPayload[12], cmacInputOffset);
        put24le(&sdmPayload[15], cmacOffset);
        Serial.println("Requesting ChangeFileSettings: ASCII SDM (C1) + F1E1 profile");
        printHexLine("FileSettings SDM: ", sdmPayload,
                     sizeof(sdmPayload));

        const uint8_t respLen = nfc.ntag424_ChangeFileSettings(
                NDEF_FILE_NO,
                sdmPayload,
                (uint8_t)sizeof(sdmPayload),
                NTAG424_COMM_MODE_FULL);

        Serial.print("ChangeFileSettings response len: ");
        Serial.println(respLen);

        const bool ok = verifySdmBitAfterChange(verifyKeyNo, useNewKeys);
        if (!ok) {
            Serial.println("ChangeFileSettings verification failed.");
            dumpFileSettingsRaw("After ChangeFileSettings (failed)");
            return false;
        }

        dumpFileSettingsRaw("After ChangeFileSettings (success)");
        return true;
    }
}

void setup() {
    Serial.begin(115200);
    while (!Serial) {
        delay(10);
    }

    Serial.print("KEY0_OLD fingerprint16=0x");
    Serial.println(keyFingerprint16(KEY0_OLD), HEX);

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
    static uint8_t lastBlockedUid[7] = {0};
    static uint8_t lastBlockedUidLen = 0;
    static uint32_t lastBlockedAtMs = 0;

    uint8_t uid[7] = {0};
    uint8_t uidLength = 0;

    if (!locateTag(uid, &uidLength)) {
        delay(300);
        return;
    }

    printHexLine("Card UID: ", uid, uidLength);

    if (lastBlockedUidLen == uidLength &&
        uidLength > 0 &&
        memcmp(lastBlockedUid, uid, uidLength) == 0) {
        const uint32_t elapsed = millis() - lastBlockedAtMs;
        if (elapsed < AUTH_FATAL_COOLDOWN_MS) {
            Serial.print("Skip same UID during cooldown (ms left=");
            Serial.print((uint32_t)(AUTH_FATAL_COOLDOWN_MS - elapsed));
            Serial.println(").");
            delay(300);
            return;
        }
    }

    bool usingNewKeys = false;

    if (RUN_CHANGE_KEY) {
        if (!authenticateForPolicyKeyRetry(uid, uidLength,
                                           "KEY_CHANGE_AUTH",
                                           POLICY_ADMIN_KEYNO,
                                           false)) {
            delay(1500);
            return;
        }
        bool keyChangeOk = false;
        for (uint8_t attempt = 1; attempt <= OP_MAX_RETRY; ++attempt) {
            keyChangeOk = runChangeKeys();
            printStepLog(uid, uidLength, "KEY_CHANGE", attempt, OP_MAX_RETRY,
                         keyChangeOk, E300_KEY_CHANGE);
            if (keyChangeOk) {
                break;
            }
            delay(OP_RETRY_DELAY_MS);
        }
        if (!keyChangeOk) {
            Serial.println("Stop due to key change error.");
            delay(2000);
            return;
        }
        usingNewKeys = true;
    }

    if (RUN_WRITE_DYNAMIC_URL) {
        uint8_t ndefWriteKeyNo = POLICY_NDEF_WRITE_KEYNO;
        bool ndefAuthOk = true;
        if (NDEF_WRITE_REQUIRES_AUTH) {
            if (NDEF_AUTH_TRY_ALL_KEYNOS) {
                for (uint8_t attempt = 1; attempt <= OP_MAX_RETRY; ++attempt) {
                    ndefAuthOk = authenticateForAnyKeyNo(usingNewKeys,
                                                         "NDEF_AUTH",
                                                         POLICY_NDEF_WRITE_KEYNO,
                                                         ndefWriteKeyNo);
                    printStepLog(uid, uidLength, "NDEF_AUTH", attempt, OP_MAX_RETRY,
                                 ndefAuthOk, E110_AUTH);
                    if (ndefAuthOk) {
                        if (ndefWriteKeyNo != POLICY_NDEF_WRITE_KEYNO) {
                            Serial.print("NDEF auth auto-selected key");
                            Serial.println(ndefWriteKeyNo);
                        }
                        break;
                    }
                    delay(OP_RETRY_DELAY_MS);
                }
            } else {
                ndefAuthOk = authenticateForPolicyKeyRetry(uid, uidLength,
                                                           "NDEF_AUTH",
                                                           POLICY_NDEF_WRITE_KEYNO,
                                                           usingNewKeys);
            }
            if (!ndefAuthOk) {
                if (!NDEF_WRITE_ALLOW_NO_AUTH_FALLBACK) {
                    Serial.println("Stop provisioning for this tag: NDEF auth failed on all configured keys.");
                    Serial.println("Set correct AES keys (KEY*_OLD_HEX) before retrying.");
                    memcpy(lastBlockedUid, uid, uidLength);
                    lastBlockedUidLen = uidLength;
                    lastBlockedAtMs = millis();
                    delay(1500);
                    return;
                }
                Serial.println("All key0..key3 auth attempts failed for NDEF_AUTH.");
                Serial.println("Likely cause: tag keys are no longer default 00..00 or wrong key set is configured.");
                Serial.println("NDEF_AUTH failed; trying NDEF write without auth fallback.");
            }
        }

        bool ndefWriteOk = false;
        const uint8_t ndefWriteAttemptMax = ndefAuthOk ? OP_MAX_RETRY : 1;
        for (uint8_t attempt = 1; attempt <= ndefWriteAttemptMax; ++attempt) {
            if (NDEF_WRITE_REQUIRES_AUTH && ndefAuthOk) {
                const bool writeAuthOk = authenticateForPolicyKey(
                        ndefWriteKeyNo,
                        usingNewKeys,
                        "NDEF_WRITE_AUTH");
                printStepLog(uid, uidLength, "NDEF_WRITE_AUTH", attempt,
                             ndefWriteAttemptMax, writeAuthOk, E110_AUTH);
                if (!writeAuthOk) {
                    delay(OP_RETRY_DELAY_MS);
                    continue;
                }
            }

            ndefWriteOk = writeDynamicUrlNdefWithRetry(uid, uidLength,
                                                       DYNAMIC_URL_TEMPLATE,
                                                       1);
            if (ndefWriteOk) {
                break;
            }
            delay(OP_RETRY_DELAY_MS);
        }

        if (!ndefWriteOk && NDEF_WRITE_ALLOW_NO_AUTH_FALLBACK) {
            Serial.println("NDEF write still failing after auth attempts; trying plain write fallback.");
            ndefWriteOk = writeDynamicUrlNdefWithRetry(uid, uidLength,
                                                       DYNAMIC_URL_TEMPLATE,
                                                       1);
        }

        if (!ndefWriteOk) {
            Serial.println("Write dynamic URL failed.");
            delay(2000);
            return;
        }
        Serial.println("Write dynamic URL OK.");
    }

    if (RUN_ENABLE_SDM) {
        if (!authenticateForPolicyKeyRetry(uid, uidLength,
                                           "SDM_AUTH",
                                           POLICY_FILE_SETTINGS_KEYNO,
                                           usingNewKeys)) {
            delay(1500);
            return;
        }

        bool sdmOk = false;
        for (uint8_t attempt = 1; attempt <= SDM_ENABLE_MAX_RETRY; ++attempt) {
            sdmOk = enableSdmForDynamicUrl(DYNAMIC_URL_TEMPLATE,
                                           POLICY_FILE_SETTINGS_KEYNO,
                                           usingNewKeys);
            printStepLog(uid, uidLength, "SDM_ENABLE", attempt, SDM_ENABLE_MAX_RETRY,
                         sdmOk, E210_SDM_VERIFY);
            if (sdmOk) break;
            delay(OP_RETRY_DELAY_MS);
        }

        if (!sdmOk) {
            Serial.println("Enable SDM failed.");
            delay(2000);
            return;
        }
    }

    Serial.println("Provision flow done. Remove and tap again for a new run.");
    delay(3000);
}

