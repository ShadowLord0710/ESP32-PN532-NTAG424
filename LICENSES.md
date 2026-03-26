# Third-Party Licenses and Attribution

This project uses the following open-source libraries and resources.

## Software Dependencies

### Adafruit PN532 NTAG424 Library
- **Repository**: https://github.com/bitcoin-ring/Adafruit-PN532-NTAG424
- **License**: Likely BSD or MIT (based on Adafruit standards)
- **Attribution**: Required per library license
- **Usage**: Core NFC PN532 and NTAG424 communication

### Adafruit BusIO Library
- **Version**: ^1.17.0
- **Source**: https://github.com/adafruit/Adafruit_BusIO
- **License**: MIT
- **Attribution**: Required

### Arduino CRC32 Library
- **Version**: ^1.0.0
- **Source**: https://github.com/arduino-libraries/Arduino_CRC32
- **License**: LGPL v2.1
- **Attribution**: Required

### PlatformIO
- **License**: Apache License 2.0
- **URL**: https://platformio.org/

## Hardware & Documentation

### NXP NTAG424 DNA Documentation
- **AN12196**: NTAG 424 DNA features and hints (NXP Semiconductors)
  - Used for SDM (Secure Dynamic Messaging) feature specification
  - Publicly available from NXP
  
- **NT4H2421Gx Datasheet**: NTAG 424 DNA NFC Type 2 Tag (NXP Semiconductors)
  - Used for command protocol and memory layout reference
  - Publicly available from NXP

### ESP32 Platform
- **Framework**: Arduino Core for ESP32
- **License**: LGPL v2.1 + Apache 2.0
- **Maintainer**: Espressif Systems

## This Project

- **License**: MIT License (2026)
- **Copyright**: ShadowLord0710
- **Source**: https://github.com/ShadowLord0710/ESP32-PN532-NTAG424

---

## Legal Compliance Notes

1. **Fair Use of Manufacturer Documentation**
   - This project lawfully references publicly available NXP datasheets
   - Implementation is custom and not derived from NXP code
   - All documentation is properly attributed

2. **Attribution in Use**
   - When forking or modifying, retain all license headers
   - Include notice of modifications
   - Maintain this LICENSES.md file

3. **No Proprietary Code**
   - No NXP proprietary code is included
   - No closed-source dependencies
   - All cryptographic functions use standard AES-128

---

## How to Comply When Using This Project

If you use this code in your project:

1. **Keep the MIT LICENSE file** in your distribution
2. **Keep this LICENSES.md file** or create your own covering these dependencies
3. **Include notice** of any modifications you make
4. **List in your README** the same attributions shown here

Example README addition:
```markdown
## License & Attribution

This project uses code from:
- Adafruit PN532 NTAG424 Library (license per library)
- Arduino ecosystem libraries (LGPL/Apache)
- References NXP NTAG424 DNA documentation for protocol compliance

Full details: see [LICENSES.md](LICENSES.md)
```

---

## Questions?

For licensing questions:
- Adafruit libraries: Check individual repository
- NXP resources: Visit nxp.com
- This project: Open an issue or contact ShadowLord0710
