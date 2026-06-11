# ESP32-S3 USB MIDI and HID Fuzzing Labs

Small ESP32-S3 firmware projects for experimenting with USB device emulation,
host-side parser behavior, and descriptor/report robustness. The repository
contains lab-oriented USB devices that can be flashed on ESP32-S3 boards and
attached to sacrificial Windows, macOS, Linux, router, or embedded hosts.

The current focus is on two USB surfaces that are commonly auto-bound by modern
operating systems:

- **USB MIDI**: class-compliant MIDI-style devices, including unusual strings,
  Unicode device names, endpoint combinations, and packet patterns.
- **USB HID**: Human Interface Device experiments, including accessibility-style
  reports, Braille-display-like reports, vendor-defined reports, and controlled
  report mutation.

The goal is not to build malicious USB gadgets. The goal is to exercise host USB
stacks, class drivers, descriptor parsers, and control-transfer handling in a
repeatable lab environment.

## Why ESP32-S3?

The ESP32-S3 exposes a native USB device peripheral, making it a convenient and
cheap target for building class-compliant or intentionally unusual USB devices.
It is easy to reflash, portable, and useful when testing how different hosts
react to USB descriptors, string descriptors, interfaces, endpoints, and class
requests.

This makes it useful for:

- USB descriptor robustness testing
- Host parser fuzzing
- HID report descriptor experiments
- MIDI endpoint and packet behavior testing
- Unicode string descriptor testing
- Regression tests across macOS, Windows, Linux, routers, and embedded hosts
- Reproducing crashes or driver warnings with fixed seeds

## Projects

### USB MIDI Fuzzer

The MIDI firmware simulates a class-compliant USB MIDI device while allowing
controlled variation of descriptors, strings, endpoint behavior, and packet
contents.

Interesting areas include:

- long and short USB string descriptors
- Unicode-heavy product/manufacturer/serial names
- unusual but valid MIDI packet streams
- malformed or boundary-value MIDI event packets
- repeated connect/disconnect testing
- host behavior when the device exposes strange names or endpoint layouts

This is useful for testing host-side MIDI stacks, audio/MIDI enumeration paths,
class-driver assumptions, and logging behavior.

### USB HID Accessibility Fuzzer

The HID firmware simulates non-keyboard HID devices, especially accessibility
or assistive-control-style devices. The default design avoids keyboard injection
and does not send keycodes.

Interesting areas include:

- HID report descriptor parsing
- accessibility-style input reports
- Braille-display-like usage pages
- vendor-defined reports
- `GET_REPORT` and `SET_REPORT` control paths
- boundary-sized feature/input/output reports
- host behavior across HID class drivers

This is useful because HID devices are widely supported and often auto-bound by
operating systems without custom drivers.

## Safety Model

These projects are intended for controlled research environments.

Recommended setup:

- use sacrificial test machines or virtual machines with USB passthrough
- keep logs enabled while testing
- avoid testing on production machines
- avoid using the HID project as a keyboard-emulation or keystroke-injection
  device
- prefer fixed seeds when reproducing crashes
- document the exact firmware build, host operating system, and USB logs

The HID project is intentionally designed around non-keyboard reports by default.
Pointer movement, keyboard-style reports, or aggressive mutation should only be
enabled deliberately in a lab.

## Repository Layout

A suggested layout is:

```text
.
├── LICENSE
├── README.md
├── hid-accessibility-fuzzer/
│   ├── CMakeLists.txt
│   ├── sdkconfig.defaults
│   ├── main/
│   │   ├── CMakeLists.txt
│   │   ├── idf_component.yml
│   │   └── main.c
│   ├── docs/
│   │   └── descriptor_notes.md
│   └── tools/
│       ├── linux_watch.sh
│       └── macos_watch.sh
└── midi-fuzzer/
    ├── CMakeLists.txt
    ├── sdkconfig.defaults
    ├── main/
    │   ├── CMakeLists.txt
    │   ├── idf_component.yml
    │   └── main.c
    ├── docs/
    │   └── descriptor_notes.md
    └── tools/
        ├── linux_watch.sh
        └── macos_watch.sh
```

The exact project names may differ, but keeping MIDI and HID as separate
firmware projects makes testing and reproduction easier.

## Requirements

- ESP32-S3 development board with native USB support
- ESP-IDF installed and exported in the shell
- USB cable that supports data, not charge-only
- sacrificial host or VM for testing

## Board Compatibility

The best boards for this repository are ESP32-S3 boards that expose the native
USB data lines separately from the debug UART. This lets you connect one cable to
the fuzz target host while keeping another cable connected to your development
machine for flashing, logs, and crash triage.

Important distinction: most ESP32-S3 "dual USB" boards do not provide two fully
independent native USB device controllers. Usually they provide:

- **Native USB / USB-OTG port** connected to the ESP32-S3 USB D+/D- pins. Use
  this as the fuzzing port.
- **USB-to-UART port** connected through a bridge chip such as CP210x, CH34x, or
  similar. Use this for flashing and serial logs.

Espressif documents the ESP32-S3 USB device pins as GPIO20 for D+ and GPIO19 for
D-. On two-port ESP32-S3 development boards, the port labeled `USB` is normally
connected to these native USB pins.

### Recommended dual-port style boards

| Board | Why it is useful | Notes |
| --- | --- | --- |
| **Espressif ESP32-S3-DevKitC-1** | Good default board. It exposes a `USB` native USB-OTG port and a separate `USB-to-UART` port. | Use `USB` toward the fuzz target host. Use `USB-to-UART` for flashing and monitoring. Variants such as `N8R8`, `N16R8`, and `N32R16V` should be fine as long as they are ESP32-S3 DevKitC-style boards. |
| **Espressif ESP32-S3-USB-OTG** | Best board when you also want to experiment with host mode, OTG switching, VBUS behavior, or device/host role changes. | It has USB host/device hardware, a USB device interface, and a separate USB-to-UART debug interface. More expensive and more complex than DevKitC, but very useful for USB research. |
| **Waveshare ESP32-S3-GEEK** | Convenient dongle-like board with an onboard USB-A male connector and a separate UART port. | Useful when you want a compact plug-in test device. Confirm the UART header/cable before relying on it for logs. |
| **Generic ESP32-S3 DevKitC-compatible boards with two USB-C ports** | Many clones expose one port as `COM`, `UART`, or `USB-to-UART`, and the other as `USB`, `OTG`, or `Native USB`. | They can work well, but check the schematic. For this repo, the fuzzing port must reach GPIO19/GPIO20, not only a USB-to-UART bridge. |

### Single-port boards that can still work

Single-port native USB boards can run the firmware, but they are less convenient
for fuzzing because the same port is used for programming, logging, and device
emulation. If the firmware wedges the USB stack, you may lose logs until reset.

Examples that should be usable with extra care:

| Board | Notes |
| --- | --- |
| **Adafruit ESP32-S3 Feather** | Native USB board. Good ecosystem, but only one onboard USB-C path, so use an external UART adapter if you want independent logs. |
| **Seeed Studio XIAO ESP32S3 / XIAO ESP32S3 Sense** | Small and cheap native USB board. Good for disposable tests, less comfortable for serial triage unless you add an external UART adapter. |
| **Arduino Nano ESP32** | ESP32-S3-based board with native USB support. Convenient if you already use the Nano form factor. Check ESP-IDF board support and pin defaults before using it as the main lab board. |
| **Unexpected Maker FeatherS3 / ProS3** | Native USB ESP32-S3 boards with good power design. Use an external UART adapter for independent logging. |
| **LilyGO T-Dongle-S3 / Waveshare ESP32-S3-GEEK-like dongles** | Dongle format is attractive for host fuzzing. Prefer models with a separate UART header if you need logs. |

### Boards to treat carefully

Boards that route USB through an onboard hub, USB switch, or combined UART/native
USB circuit can still be useful, but they may pollute the target host view with
extra devices. For clean USB fuzzing, prefer a board where the target host sees
only the experimental MIDI or HID device.

When buying a board, check for these labels and schematic details:

- `USB`, `OTG`, `Native USB`, `USB_DEV`, or D+/D- connected to GPIO20/GPIO19
- separate `UART`, `COM`, or `USB-to-UART` port for logs
- data-capable cable support
- easy access to `BOOT` and `RESET`
- enough PSRAM/flash if you plan to add large descriptor corpora or logging

For this repository, the practical ideal is: flash/log over the UART port, fuzz
the host through the native USB port.

## Build

From one of the firmware project directories:

```bash
. "$IDF_PATH/export.sh"
idf.py set-target esp32s3
idf.py build
```

Flash and monitor:

```bash
idf.py -p /dev/ttyACM0 flash monitor
```

On macOS, the serial port may look like:

```bash
idf.py -p /dev/cu.usbmodemXXXX flash monitor
```

## Reproducible Seeds

When a firmware supports seeded mutation, build with a fixed seed:

```bash
idf.py -DFUZZ_SEED=0x12345678 build flash monitor
```

Record the seed together with:

- firmware commit hash
- ESP-IDF version
- host operating system version
- USB logs
- crash logs or kernel messages
- exact board model

## Linux Host Logging

Useful commands while attaching the device:

```bash
sudo dmesg -w
journalctl -kf
lsusb
lsusb -v -d VID:PID
```

For HID descriptor inspection:

```bash
sudo usbhid-dump -e descriptor
sudo usbhid-dump -e stream
```

For MIDI testing:

```bash
aconnect -l
amidi -l
aseqdump -l
```

## macOS Host Logging

Useful commands while attaching the device:

```bash
system_profiler SPUSBDataType
ioreg -p IOUSB -l -w 0
```

General USB/HID logging:

```bash
log stream --style compact --predicate 'process == "kernel" OR eventMessage CONTAINS[c] "USB" OR eventMessage CONTAINS[c] "HID"'
```

MIDI-related inspection:

```bash
system_profiler SPAudioDataType
```

For GUI inspection, use **Audio MIDI Setup** on macOS.

## Windows Host Logging

Useful tools:

- Device Manager
- Event Viewer
- USBView from the Windows SDK
- PowerShell `Get-PnpDevice`

Example PowerShell snippets:

```powershell
Get-PnpDevice -PresentOnly | ? { $_.InstanceId -match 'USB' }
Get-PnpDeviceProperty -InstanceId '<INSTANCE_ID>'
```

## Testing Strategy

A practical test loop:

1. Flash a known seed.
2. Start host-side logs.
3. Attach the ESP32-S3 native USB port.
4. Wait for enumeration.
5. Exercise the class path:
   - open MIDI device from a DAW or MIDI monitor
   - read HID reports with host tools
   - trigger `GET_REPORT` / `SET_REPORT` where applicable
6. Save logs.
7. Change one variable at a time.

Good variables to mutate:

- string descriptor length
- Unicode string contents
- report descriptor size
- report count and report size
- endpoint packet size
- interface subclass/protocol
- number of reports
- feature report length
- MIDI event packet values
- timing between reports

## Unicode Descriptor Ideas

Useful test strings include mixed scripts and boundary cases:

```text
FuzzSociety MIDI 測試 устройство جهاز 🎛️
Assistive HID Δοκιμή кнопка 点字 ⠃⠗⠇
MIDI-Ω-漢字-кириллица-العربية
HID Accessibility 🧪 Braille ⠋⠥⠵⠵
```

Keep notes on which hosts display, truncate, reject, or sanitize the names.

## Responsible Use

Do not attach experimental USB firmware to systems you do not own or do not have
permission to test. Do not use the HID project to send unsolicited keyboard
input. Do not use these projects for persistence, evasion, credential capture,
or unauthorized access.

The intended output of this repository is research data: logs, crashes,
descriptor behavior, parser bugs, and reproducible test cases.


## Hardware References

- Espressif ESP32-S3 USB Device Stack: documents native USB D+/D- routing to
  GPIO20/GPIO19 and notes that two-port development boards usually label the
  native port as `USB`.
- Espressif ESP32-S3-DevKitC-1 user guide: documents the separate
  `USB-to-UART Port` and `USB Port`.
- Espressif ESP32-S3-USB-OTG user guide: documents the USB host/device-focused
  board, USB device interface, USB host interface, USB switch, and USB-to-UART
  debug interface.
- Adafruit ESP32-S3 Feather overview: documents native USB support.
- Waveshare ESP32-S3-GEEK documentation: documents the onboard USB-A port and
  UART port.

## License


MIT 

Copyright 2026 FuzzSociety / Antonio Nappa

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
## Author


FuzzSociety / Antonio Nappa


