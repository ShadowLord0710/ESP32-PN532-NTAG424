# ESP32 + PN532 (SPI) + NTAG424 DNA Provisioning

Provisioning template for NTAG424 DNA using ESP32 + PN532 (SPI) with PlatformIO.

This project focuses on:
- Writing a dynamic URL into NDEF File 02.
- Enabling SDM (Secure Dynamic Messaging): UID mirror, counter mirror, CMAC.
- Running policy-based authentication/key mapping safely for factory tags.

## Contents
- [What This Project Does](#what-this-project-does)
- [Hardware Requirements](#hardware-requirements)
- [Wiring (SPI)](#wiring-spi)
- [Software Requirements](#software-requirements)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Verified SDM Profile](#verified-sdm-profile)
- [Recommended Test Flow](#recommended-test-flow)
- [Troubleshooting](#troubleshooting)
- [Safety Notes](#safety-notes)
- [References & License](#references--license)

## What This Project Does
- Detects NTAG424 DNA tag.
- Authenticates with AES-128 keys.
- Writes URI NDEF record to File 02.
- Applies `ChangeFileSettings` to enable SDM on File 02.
- Verifies SDM bit by reading file settings after update.

Implementation file:
- `src/main.cpp`

## Hardware Requirements
- ESP32 DevKit (Arduino framework)
- PN532 module in SPI mode
- NTAG424 DNA tag
- Stable 3.3V supply and common GND

## Wiring (SPI)
Default pin mapping in code:

| PN532 | ESP32 |
|---|---|
| SCK | GPIO18 |
| MOSI | GPIO23 |
| MISO | GPIO19 |
| SS | GPIO5 |
| VCC | 3V3 |
| GND | GND |

To change pins, update in `src/main.cpp`:
- `PN532_SCK`
- `PN532_MOSI`
- `PN532_MISO`
- `PN532_SS`

## Software Requirements
- VS Code + PlatformIO extension (recommended)
- or PlatformIO CLI

## Project Structure
```text
.
|- platformio.ini
|- README.md
|- README_PLATFORMIO_ESP32_SPI.md
\- src/
   \- main.cpp
```

## Quick Start
Build:

```powershell
pio run
```

Upload:

```powershell
pio run -t upload --upload-port COM3
```

Open monitor:

```powershell
pio device monitor --port COM3 -b 115200
```

If PlatformIO is installed via VS Code extension only, run commands from PlatformIO terminal.

## Configuration
Main runtime flags in `src/main.cpp`:
- `RUN_CHANGE_KEY`
- `RUN_WRITE_DYNAMIC_URL`
- `RUN_ENABLE_SDM`
- `DUMP_FILE_SETTINGS`

Main policy settings:
- `POLICY_ADMIN_KEYNO`
- `POLICY_NDEF_WRITE_KEYNO`
- `POLICY_FILE_SETTINGS_KEYNO`
- `POLICY_AR_RW`, `POLICY_AR_CAR`, `POLICY_AR_R`, `POLICY_AR_W`

URL template:
- `DYNAMIC_URL_TEMPLATE`

Keys:
- `KEY0_OLD..KEY3_OLD`
- `KEY0_NEW..KEY3_NEW`

## Verified SDM Profile
This repo now includes a known-good SDM payload that has been validated in device logs.

Working profile summary:
- Communication mode: `FULL`
- `FileOption`: `0x40` (SDM enabled, plain comm bits preserved)
- `AccessRights`: `0xE0EE` (current file policy)
- `SDMOptions`: `0xC1` (UID mirror + SDMReadCtr mirror + ASCII)
- `SDMAccessRights`: `0xF1E1` (2-byte format per NTAG424 spec)
- `SDMMACInputOffset = SDMMACOffset`

Successful verify example shape:
- `GetFileSettings ... 00 40 E0 EE 00 01 00 C1 F1 E1 ... 91 00`
- parsed result: `SDM=ON`

## Recommended Test Flow
1. Keep `RUN_CHANGE_KEY = false` while validating SDM.
2. Upload firmware and open monitor.
3. Tap a tag.
4. Confirm logs show:
   - `Write dynamic URL OK.`
   - `Enable SDM OK.`
   - `Parsed ... fileOption=0x40 ... SDM=ON`
5. Remove and re-tap.
6. Scan with phone and verify URL placeholders are replaced dynamically.

## Troubleshooting
### `pio` command not found
Use one of these options:

```powershell
pio run
```

- Open VS Code command palette and run PlatformIO: New Terminal.
- Or install PlatformIO CLI globally and ensure pio is in PATH.

### Upload fails / COM busy
- Close Serial Monitor before upload.
- Re-check COM port.
- Keep upload speed conservative (115200 works well in this setup).

### PN532 not detected
- Ensure module is in SPI mode.
- Re-check SPI wiring and common GND.

### Authenticate fails
- Keys on tag are not default anymore.
- Policy key number does not match file access rights.

### `ChangeFileSettings` returns `91 7E` / `91 9E`
- SDM payload format/rights do not match tag policy.
- Verify you are using the spec-based `F1E1` SDM access rights profile.
- Read `GetFileSettings` before and after change.

## Safety Notes
- Wrong key/policy can lock write/config access.
- Do not enable key change on production batches before full test pass.
- Keep a per-batch record of key map and file policy.

## References & License

**License**: This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

**Third-Party Dependencies**: See [LICENSES.md](LICENSES.md) for comprehensive attribution and license information for all libraries and documentation used.

**Key References**:
- PN532 NTAG424 library fork:
  - https://github.com/bitcoin-ring/Adafruit-PN532-NTAG424
- PlatformIO:
  - https://platformio.org/
- NXP AN12196 (NTAG 424 DNA features and hints)
  - Used for SDM specification details
- NXP NT4H2421Gx datasheet (NTAG 424 DNA Type 2 Tag)
  - Used for protocol and memory layout reference

**Building on This Project**: When using or forking this code, ensure you:
1. Retain the MIT LICENSE file
2. Keep or reference LICENSES.md
3. Maintain attribution to original authors
4. Document any modifications or derivative works
