# RP2040 USB Multi-Peripheral Fuzzer

Lab firmware for **Raspberry Pi Pico / RP2040** boards with native USB. A single
firmware image runs a deterministic campaign that rotates through several USB
**peripheral types**, exposing one fuzzed device per case, then reboots into the
next case.

This is the RP2040 sibling of the ESP32-S3 HID and Audio/MIDI labs in this
repository. It combines both ideas:

- the **behavioural HID fuzzing** of the HID lab (accessibility / Braille /
  vendor reports, `GET_REPORT` / `SET_REPORT`), and
- the **deterministic descriptor campaign + Unicode string fuzzing** of the
  MIDI lab (case N → reboot → case N+1, replayable crash windows),

generalised across **HID, MIDI, CDC, Vendor, a CDC+HID composite, and
descriptor-only MSC and Audio** profiles.

Like the rest of the repository, the goal is research data — host logs, parser
behaviour, crashes, reproducible cases — not a malicious gadget. It does **not**
enumerate as a keyboard and does not inject keystrokes.

## Why RP2040?

The RP2040 exposes a native full-speed USB device controller, is cheap and easy
to reflash (drag-and-drop UF2), and TinyUSB is first-class in the Pico SDK. The
firmware uses **raw TinyUSB descriptor callbacks**, so each case can return
arbitrary device / configuration / string descriptor bytes — exactly what
descriptor-parser fuzzing needs.

## Peripheral profiles

Per case, `profile = case_id % 7`:

| Profile | Kind | What it exercises |
| --- | --- | --- |
| `HID-accessibility` | real | Assistive Control + Braille Display + vendor reports; `GET_REPORT`/`SET_REPORT` paths |
| `MIDI` | real | AudioControl + MIDIStreaming interfaces, MIDI jacks, USB-MIDI event packets |
| `CDC-ACM` | real | CDC serial enumeration + line coding + bulk data |
| `Vendor-bulk` | real | vendor-specific class, bulk IN/OUT |
| `Composite-CDC+HID` | real | IAD-based composite enumeration and multi-interface binding |
| `MSC-desc-only` | descriptor-only | host configuration-descriptor parsing of a Mass Storage (BOT/SCSI) interface |
| `Audio-desc-only` | descriptor-only | host parsing of UAC AudioControl/AudioStreaming descriptors |

**Real** profiles start from a valid baseline (built with TinyUSB's
`TUD_*_DESCRIPTOR` macros), so the device fully enumerates and the host binds the
matching class driver before traffic starts.

**Descriptor-only** profiles emit hand-assembled interface bytes. The host still
parses them during `GET_DESCRIPTOR(configuration)` — which is the surface under
test — even though the device has no compiled driver to fully configure them, so
`SET_CONFIGURATION` may stall. That is expected and is logged over UART.

The device PID encodes the active profile (`0xF000 + profile`) so it is easy to
tell which class a given enumeration was in host logs.

## Campaign model

```
boot
  └─ (reset pin low?) → erase campaign, reboot
  └─ previous case marked active but not clean? → log SUSPECT
case_id = next_case
  ├─ seed     = 0xA11D0000 ^ case*0x9E3779B9 ^ "RP24"
  ├─ profile  = case_id % 7
  ├─ variant  = VALID on the first pass over all profiles, then a bounded
  │             deterministic mutation
  └─ unicode  = case_id % <#string profiles>
mark active in flash, bump next_case
enumerate → dwell (CASE_DWELL_MS) driving light fuzzed class traffic
mark clean in flash
watchdog reboot → next case
```

State lives in the **last flash sector** (CRC-checked). A case that is marked
active but never marked clean (because the host crash cut our power, the device
hung, or a watchdog reset fired mid-case) is reported as a **SUSPECT** on the
next boot — the replayable signal you care about.

### Descriptor variants (mutation cases)

After the first clean pass over all profiles, later cases corrupt one field in a
bounded, deterministic way:

```
bad-total-lengths    bad-blengths        bad-class-bytes
bad-string-index     bad-endpoints       random-cs-trailers
truncate-extend
```

## Build

Requires the Raspberry Pi Pico SDK and the ARM toolchain.

```bash
export PICO_SDK_PATH=/path/to/pico-sdk
cd rp2040
mkdir build && cd build
cmake .. -DPICO_BOARD=pico        # or pico_w, etc.
make -j
```

Output: `build/rp2040_usb_fuzz.uf2`.

Flash by holding **BOOTSEL** while plugging the Pico in, then copy the `.uf2`
onto the `RPI-RP2` mass-storage volume. (Or use `picotool load -f`.)

### Logs over UART, fuzz over USB

The native USB port is the **device-under-test** surface presented to the target
host, so logs go out over **UART0** instead:

| Pico pin | Signal |
| --- | --- |
| GP0 | UART0 TX → your serial adapter RX |
| GP1 | UART0 RX |
| GND | GND |

```bash
# 115200 8N1, e.g.
screen /dev/tty.usbserial-XXXX 115200       # macOS
minicom -D /dev/ttyUSB0 -b 115200            # Linux
```

A typical lab setup: USB cable from the Pico to the **sacrificial target host**,
and a separate USB-UART adapter on GP0/GP1/GND to your **development machine**
for logs and crash triage.

## Runtime controls (compile-time)

Edit `src/fuzz.h` (or pass `-D...` to CMake) then rebuild:

| Macro | Default | Meaning |
| --- | --- | --- |
| `CASE_DWELL_MS` | `30000` | time per case before advancing |
| `AUTO_ADVANCE_CASE` | `1` | set `0` to replay one case |
| `CASE_OVERRIDE` | `0` | case id to replay when not auto-advancing |
| `REPLAY_DWELL_MS` | `90000` | dwell while replaying |
| `CAMPAIGN_RESET_PIN` | `15` | jumper this GPIO to GND at boot to wipe state |
| `SEND_POINTER_DELTAS` | `0` | include tiny HID cursor deltas (off by default) |

### Reset the campaign

Jumper **GP15 → GND** during reset/power-on. The firmware erases the campaign
state and restarts from case 0.

### Replay a suspect window

A crash at a known time maps to a case range (`elapsed / CASE_DWELL_MS`). To
reproduce:

```c
/* src/fuzz.h */
#define AUTO_ADVANCE_CASE 0
#define CASE_OVERRIDE     1234u
#define REPLAY_DWELL_MS   90000u
```

Rebuild, reflash, and sweep `CASE_OVERRIDE` around the suspected case.

## Host monitoring

Same playbook as the ESP32-S3 labs — watch for the Raspberry Pi VID `2E8A` and
PID `F0xx`.

**Linux**

```bash
sudo dmesg -w
journalctl -kf
lsusb -v -d 2e8a:
sudo usbhid-dump -e descriptor      # HID cases
```

**macOS**

```bash
log stream --style compact --predicate 'process == "kernel" AND (composedMessage CONTAINS[c] "AppleUSB" OR composedMessage CONTAINS[c] "2E8A" OR composedMessage CONTAINS[c] "panic")'
system_profiler SPUSBDataType | grep -iA8 '2e8a\|FuzzSociety'
```

**Windows (PowerShell, Administrator)**

```powershell
while ($true) { Get-PnpDevice -PresentOnly:$false | ? { $_.InstanceId -match 'VID_2E8A' } | Format-List Status,Class,FriendlyName,InstanceId; Start-Sleep 2 }
Get-Content "$env:windir\inf\setupapi.dev.log" -Wait -Tail 200 | Select-String 'VID_2E8A|Problem|failed|descriptor'
```

## Flash wear note

The campaign rewrites the last flash sector twice per case (active, then clean).
That is fine for typical smoke / first-signal runs, but very long overnight
campaigns accumulate erase cycles on a single sector. For multi-day soak
testing, increase `CASE_DWELL_MS`, or use a sacrificial board.

## Layout

```text
rp2040/
├── CMakeLists.txt
├── pico_sdk_import.cmake
├── include/
│   └── tusb_config.h        # HID/MIDI/CDC/Vendor on; MSC/Audio off (desc-only)
└── src/
    ├── main.c               # boot, suspect detect, case run, dwell, reboot
    ├── fuzz.c / fuzz.h       # PRNG, flash campaign state, case selection
    ├── usb_descriptors.c     # device/config/string/HID-report cbs, builders, mutations
    ├── usb_descriptors.h
    └── usb_callbacks.c       # HID get/set report + per-class fuzzed traffic
```

## Safety

Attach this only to systems you own or are explicitly authorized to test.
Descriptor and class fuzzing can hang USB stacks, crash class-driver services,
bugcheck Windows, or panic macOS/Linux. Prefer a sacrificial host or a VM with
USB passthrough, keep host logs running, and record the printed case id / seed
with every crash.
