# ESP32-S3 USB HID Accessibility Fuzzer

Lab firmware for ESP32-S3 boards with native USB-OTG. It enumerates as a single HID interface with three report IDs:

- Report ID 1: Generic Desktop / Assistive Control style switch + optional relative pointer report.
- Report ID 2: Braille Display page report surface with router/button-like input and feature/output handling.
- Report ID 3: Vendor-defined 63-byte chaos report for boundary-pattern delivery.

The firmware is designed for defensive fuzzing of USB/HID/accessibility parsing in isolated lab machines or VMs. It intentionally does not enumerate as a keyboard and it does not send keystrokes.

## Build

```bash
. $IDF_PATH/export.sh
idf.py set-target esp32s3
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

Use your board's flashing port. On many ESP32-S3 dev boards, the port labeled `USB` is the native USB-OTG port used by this device firmware; the `UART`/`COM` port can be used for logging and flashing.

## Runtime

The device prints the fuzz seed at boot. Rebuild with a fixed `FUZZ_SEED` for repro:

```bash
idf.py build -DFUZZ_SEED=0x12345678
```

By default, relative pointer deltas are disabled. To include tiny cursor movements in the Assistive Control report, build with:

```bash
idf.py build -DSEND_POINTER_DELTAS=1
```

## Suggested lab loop

- Test on a sacrificial host, VM with USB passthrough, or a host connected through a USB power/data switch.
- Capture enumeration with `dmesg -w`, macOS `log stream`, Windows Event Viewer / SetupAPI logs, or USBPcap/Wireshark.
- Save the printed seed plus host crash/log artifacts.
- Start with 20-50 ms intervals; lower only when the host survives basic enumeration.
