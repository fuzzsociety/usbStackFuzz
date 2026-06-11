# ESP32-S3 USB Audio/MIDI Unicode Descriptor Fuzzer

**FuzzSociety USB host-surface test firmware for Windows and macOS.**

This project turns an ESP32-S3 board into a deterministic USB device that repeatedly exposes fuzzed **USB AudioControl** and **USB MIDIStreaming** descriptor layouts, while also rotating through Unicode-heavy USB string descriptors such as manufacturer, product, serial, and interface/function names.

The goal is to exercise host-side USB parsing and binding paths in Windows and macOS, especially around:

- USB device/configuration/interface/endpoint descriptors
- AudioControl descriptors
- MIDIStreaming descriptors
- MIDI jack topology descriptors
- class-specific endpoint companion descriptors
- Unicode USB string descriptor handling
- attach/detach and class-driver teardown behavior

This firmware is intended for controlled vulnerability research on machines you own or are authorized to test.

## Why this exists

HID report descriptor fuzzing is useful, but Audio/MIDI gives a different and richer surface. Hosts typically parse several layers before a device becomes visible to CoreAudio, MIDI services, Windows PnP, or class drivers.

This firmware targets that path with a simple campaign model:

```text
boot
case N
select Unicode string profile
build deterministic Audio/MIDI descriptor variant
expose USB device
wait
mark case clean
reboot to N+1
```

If the host crashes, freezes, panics, or reboots, the iteration sequence is deterministic, so you can replay around the suspected case range.

## Hardware

Tested target style:

- ESP32-S3 board with native USB device support
- Freenove ESP32-S3 WROOM-style boards
- USB-C data cable connected to the ESP32-S3 native USB port

The default PlatformIO environments support both 2MB and 8MB flash reports:

```text
esp32s3_2mb
esp32s3_8mb
```

If esptool reports `Expected 8MB, found 2MB`, use the 2MB environment.

## Repository layout

```text
.
├── platformio.ini
├── sdkconfig.defaults
├── partitions_2MB.csv
├── partitions_8MB.csv
└── src
    ├── idf_component.yml
    └── main.cpp
```

The project uses **ESP-IDF through PlatformIO** and pulls `esp_tinyusb` as an ESP-IDF managed component.

Do not build this as an Arduino project and do not add `lib_deps = tinyusb`.

## Build and flash

Install PlatformIO, then from the repository root:

```bash
pio run -e esp32s3_2mb
pio run -e esp32s3_2mb -t upload
```

For an 8MB board:

```bash
pio run -e esp32s3_8mb
pio run -e esp32s3_8mb -t upload
```

If PlatformIO keeps stale state after config edits:

```bash
rm -rf .pio managed_components sdkconfig sdkconfig.old dependencies.lock
pio run -e esp32s3_2mb
```

## Runtime modes

### Normal fuzzing mode

Power/reset the board normally.

The firmware will:

1. load the next case from NVS,
2. select a Unicode string profile,
3. generate a fuzzed Audio/MIDI configuration descriptor,
4. expose the USB device,
5. dwell for the configured time,
6. mark the case clean,
7. reboot into the next case.

Default dwell time:

```cpp
#define CASE_DWELL_MS 30000u
```

That is approximately one case every 30 seconds plus USB enumeration/reboot overhead.

### BOOT/GPIO0 held during reset

Holding BOOT while resetting clears the NVS campaign state and reboots.

Use this to reset the campaign counter.

## Deterministic cases

Cases are deterministic. Given the same `case_id`, the firmware chooses the same:

- seed
- descriptor variant
- mutation values
- Unicode string profile
- configuration descriptor bytes

Unicode profile selection is:

```text
profile = case_id % number_of_profiles
```

Early cases cover fixed descriptor variants. Later cases use deterministic pseudo-random mutation from the case seed.

## Unicode string profiles

The firmware rotates manufacturer, product, serial, and function/interface strings through profiles covering:

- ASCII baseline
- Chinese simplified and traditional
- Japanese
- Korean
- Cyrillic
- Greek
- Hebrew
- Arabic and right-to-left text
- Devanagari
- Thai
- Khmer
- accented Latin
- combining marks
- Zalgo-style combining text
- fullwidth Latin
- mathematical Unicode
- enclosed characters
- symbols
- emoji and supplementary-plane characters
- bidi control markers
- zero-width markers
- long mixed Unicode strings
- mixed-script names

This is useful because host operating systems touch USB string descriptors early, before or during class-driver binding.

## Descriptor variants

The current corpus includes variants such as:

```text
VAR_VALID_MIDI
VAR_DUP_JACK_IDS
VAR_ZERO_JACK_IDS
VAR_BAD_TOTAL_LENGTHS
VAR_BAD_ENDPOINT_COMPANION
VAR_BAD_INTERFACE_COUNTS
VAR_MIDI_WITH_AUDIO_STREAM
VAR_RANDOM_CS_TRAILERS
VAR_AUDIO_ONLY_ODD_STREAM
```

The intent is to stress host parsers without requiring high-bandwidth audio streaming. The firmware is descriptor-focused.

## Host campaign workflow

Use sacrificial or non-critical hosts. A real kernel panic on macOS or a bugcheck on Windows can reboot or freeze the whole machine.

Recommended campaign lengths:

```text
15–30 min   smoke run
1–3 h       first signal run
overnight   only on a sacrificial host
```

Keep notes with:

```text
campaign start time
CASE_DWELL_MS
host OS build/version
approximate crash time
observed host behavior
```

Because iterations are deterministic, a crash at a known time gives you an approximate case range. Replay around that range with `CASE_OVERRIDE`.

## Replaying a case

Edit `src/main.cpp`:

```cpp
#define AUTO_ADVANCE_CASE 0
#define CASE_OVERRIDE 1234u
#define REPLAY_DWELL_MS 90000u
```

Then rebuild and flash:

```bash
pio run -e esp32s3_2mb -t upload
```

For a fuzzy crash window, replay around the suspected range:

```text
suspect - 10
suspect - 9
...
suspect
...
suspect + 10
```

## macOS monitoring

Avoid broad predicates like `parse`, `USB`, `Audio`, or `MIDI` alone. They are too noisy and can match unrelated kernel logs such as Wi-Fi PHY parsing.

Quiet error-focused stream:

```bash
log stream --style compact --level default \
  --predicate '
    process == "kernel" AND
    NOT composedMessage CONTAINS[c] "wlan0" AND
    NOT composedMessage CONTAINS[c] "parsePHYEcounter" AND
    (
      composedMessage CONTAINS[c] "AppleUSB" OR
      composedMessage CONTAINS[c] "AppleUSBAudio" OR
      composedMessage CONTAINS[c] "AppleMIDI" OR
      composedMessage CONTAINS[c] "303A" OR
      composedMessage CONTAINS[c] "1001" OR
      composedMessage CONTAINS[c] "panic" OR
      composedMessage CONTAINS[c] "watchdog" OR
      composedMessage CONTAINS[c] "kernel trap"
    ) AND (
      composedMessage CONTAINS[c] "failed" OR
      composedMessage CONTAINS[c] "invalid" OR
      composedMessage CONTAINS[c] "malformed" OR
      composedMessage CONTAINS[c] "timeout" OR
      composedMessage CONTAINS[c] "panic" OR
      composedMessage CONTAINS[c] "watchdog" OR
      composedMessage CONTAINS[c] "kernel trap" OR
      composedMessage CONTAINS[c] "303A" OR
      composedMessage CONTAINS[c] "1001"
    )
  ' | tee audio_midi_fuzz_mac_errors_only.log
```

Low-noise USB presence sampler:

```bash
while true; do
  echo "===== $(date -Is) ====="
  system_profiler SPUSBDataType 2>/dev/null | \
    egrep -i 'Espressif|Freenove|TinyUSB|Audio|MIDI|Product ID|Vendor ID|Serial Number|Location ID' || true
  sleep 10
done | tee usb_audio_midi_presence.log
```

After a reboot, freeze, or panic:

```bash
ls -lt /Library/Logs/DiagnosticReports/*panic* 2>/dev/null | head
```

And extract recent USB/audio/MIDI context:

```bash
log show --last 30m --style compact \
  --predicate '
    composedMessage CONTAINS[c] "panic" OR
    composedMessage CONTAINS[c] "watchdog" OR
    composedMessage CONTAINS[c] "kernel trap" OR
    composedMessage CONTAINS[c] "AppleUSB" OR
    composedMessage CONTAINS[c] "AppleUSBAudio" OR
    composedMessage CONTAINS[c] "AppleMIDI" OR
    composedMessage CONTAINS[c] "303A" OR
    composedMessage CONTAINS[c] "1001"
  ' > postmortem_audio_midi_$(date +%Y%m%d_%H%M%S).log
```

## Windows monitoring

Run PowerShell as Administrator.

Live PnP status:

```powershell
$VIDPID = "VID_303A"

while ($true) {
    Clear-Host
    "===== $(Get-Date -Format o) ====="

    $devs = Get-PnpDevice -PresentOnly:$false |
        Where-Object { $_.InstanceId -match $VIDPID }

    foreach ($d in $devs) {
        "`n==== $($d.InstanceId) ===="
        $d | Format-List Status,Class,FriendlyName,InstanceId

        Get-PnpDeviceProperty -InstanceId $d.InstanceId -ErrorAction SilentlyContinue |
            Where-Object {
                $_.KeyName -match 'DeviceDesc|Service|Class|HardwareIds|Problem|DriverProblemDesc|Location|ContainerId|Parent'
            } |
            Sort-Object KeyName |
            Format-Table KeyName,Data -AutoSize
    }

    Start-Sleep 2
}
```

Tail SetupAPI:

```powershell
Get-Content "$env:windir\inf\setupapi.dev.log" -Wait -Tail 300 |
    Select-String -Pattern "VID_303A|303A|Audio|MIDI|USB|Problem|failed|descriptor|validation"
```

Check crash artifacts:

```powershell
Get-ChildItem C:\Windows\LiveKernelReports -Recurse -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 30 FullName,LastWriteTime,Length
```

Bugcheck and unexpected reboot events:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='System'
    Id=41,1001,6008
    StartTime=(Get-Date).AddHours(-4)
} -ErrorAction SilentlyContinue |
Format-List TimeCreated,ProviderName,Id,LevelDisplayName,Message
```

## Interesting result buckets

Expected / low priority:

```text
USB device rejected cleanly
Audio/MIDI class driver refuses descriptor
invalid descriptor log
failed to start class driver
```

Medium priority:

```text
USB stack reset loop
Audio/MIDI service hangs
device remains stuck until unplug
host input/audio subsystem degrades
high CPU in kernel or driver service
```

High priority:

```text
macOS kernel panic
Windows bugcheck
watchdog timeout
spontaneous reboot
machine freeze requiring power-cycle
USB subsystem dead until reboot
```

## Safety notes

This firmware intentionally sends unusual USB descriptors to host operating systems. Use it only against systems you own or have explicit authorization to test.

Do not run long campaigns on your daily workstation unless you are comfortable with:

- kernel panics or bugchecks
- spontaneous reboots
- loss of unsaved work
- USB subsystem instability
- audio/MIDI services becoming unstable

Prefer a sacrificial Mac mini, spare Windows laptop, or lab host.

## Development notes

This project intentionally avoids MSC dump mode in the Audio/MIDI firmware. Some `esp_tinyusb` versions provide strong default callback symbols for MSC and lifecycle events; defining duplicate `tud_*` callbacks can cause linker conflicts.

For that reason, this build keeps the host-facing fuzz surface small:

```text
USB Audio/MIDI descriptors
Unicode USB strings
optional MIDI traffic
NVS case state
```

If you need firmware-side log extraction later, add it as a separate firmware mode or a separate log-dumper project rather than mixing MSC into this Audio/MIDI fuzzer.

## License

Add the repository license here. For FuzzSociety internal/research tooling, keep this section explicit before publishing.
