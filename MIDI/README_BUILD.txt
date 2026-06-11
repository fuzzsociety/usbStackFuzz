ESP32-S3 Audio/MIDI Unicode-name descriptor fuzzer
===================================================

This is a compact PlatformIO + ESP-IDF + esp_tinyusb project.

Normal boot:
  case N -> choose Unicode manufacturer/product/serial/function strings
         -> build fuzzed AudioControl/MIDIStreaming config descriptor
         -> expose USB device for CASE_DWELL_MS
         -> mark clean and reboot to N+1

BOOT/GPIO0 held during reset:
  clear NVS campaign state and reboot.

Build:
  pio run -e esp32s3_2mb
  pio run -e esp32s3_2mb -t upload

If your board reports 8MB flash:
  pio run -e esp32s3_8mb -t upload

Notes:
  - No MSC dump mode: avoids esp_tinyusb callback collisions.
  - Unicode profiles are selected deterministically: profile = case_id % profile_count.
  - Descriptor variants are also deterministic from case_id/seed.
