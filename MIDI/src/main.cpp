// ============================================================
// ESP32-S3 USB Audio/MIDI descriptor fuzzer
//
// Normal boot:
//   boot -> case N -> expose fuzzed AudioControl/MIDIStreaming device
//   -> dwell -> mark clean -> reboot -> case N+1
//
// BOOT/GPIO0 held during reset:
//   reset journal/case counter and reboot.
//
// The firmware journals clean/suspect cases in NVS. This minimal build avoids
// MSC dump mode to prevent esp_tinyusb callback symbol collisions.
// The host-facing fuzz mode targets descriptor parsing/binding of:
//   - USB AudioControl interface descriptors
//   - USB MIDIStreaming interface descriptors
//   - class-specific jack descriptors
//   - class-specific endpoint companions
//   - optional malformed AudioStreaming-ish descriptors
//
// Build style: ESP-IDF + esp_tinyusb, because Arduino's high-level USBMIDI
// wrapper gives mostly fixed descriptors and Arduino USB Audio support has been
// incomplete/version-dependent.
// ============================================================

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"

#include "tinyusb.h"
#include "tinyusb_default_config.h"
#include "tusb.h"

// ----------------------- Tunables ---------------------------

#define BOOT_BUTTON_PIN             GPIO_NUM_0
#define AUTO_ADVANCE_CASE           1
#define CASE_OVERRIDE               0u
#define RESET_ALL_STATE             0

#define CASE_DWELL_MS               30000u   // Audio/MIDI enumeration can be slower than HID
#define REPLAY_DWELL_MS             90000u
#define SEND_MIDI_TRAFFIC           1        // Send valid-ish + odd USB-MIDI event packets after enumeration
#define MIDI_TRAFFIC_PERIOD_MS      250u

// Weak detector. Disabled by default because hosts naturally stop polling MIDI
// after enumeration. Enable only when replaying a suspect.
#define ENABLE_IDLE_SUSPECT         0
#define IDLE_SUSPECT_MS             120000u

#define JOURNAL_MAX                 96
#define CFG_MAX_LEN                 384


// Endpoint choices. ESP32-S3 full-speed endpoint budget is limited; keep simple.
#define EP_MIDI_OUT                 0x01
#define EP_MIDI_IN                  0x81
#define EP_AUDIO_OUT                0x03

// ----------------------- USB constants ----------------------

#define USB_CLASS_AUDIO             0x01
#define AUDIO_SUBCLASS_CONTROL      0x01
#define AUDIO_SUBCLASS_STREAMING    0x02
#define AUDIO_SUBCLASS_MIDISTREAM   0x03
#define AUDIO_PROTO_UNDEFINED       0x00

#define CS_INTERFACE                0x24
#define CS_ENDPOINT                 0x25

#define AC_HEADER                   0x01
#define MS_HEADER                   0x01
#define MIDI_IN_JACK                0x02
#define MIDI_OUT_JACK               0x03
#define EP_GENERAL                  0x01

#define JACK_EMBEDDED               0x01
#define JACK_EXTERNAL               0x02

// ----------------------- Status codes -----------------------

enum Status : uint32_t {
  STATUS_COMPLETED_CLEAN        = 1,
  STATUS_POWERLOSS_SUSPECT      = 2,
  STATUS_USB_UMOUNTED           = 3,
  STATUS_IDLE_TIMEOUT_SUSPECT   = 4,
  STATUS_REPLAY_MARKER          = 5,
};

enum Variant : uint32_t {
  VAR_VALID_MIDI                = 0,
  VAR_DUP_JACK_IDS              = 1,
  VAR_ZERO_JACK_IDS             = 2,
  VAR_BAD_TOTAL_LENGTHS         = 3,
  VAR_BAD_ENDPOINT_COMPANION    = 4,
  VAR_BAD_INTERFACE_COUNTS      = 5,
  VAR_MIDI_WITH_AUDIO_STREAM    = 6,
  VAR_RANDOM_CS_TRAILERS        = 7,
  VAR_AUDIO_ONLY_ODD_STREAM     = 8,
};

struct JournalEntry {
  uint32_t magic;
  uint32_t version;
  uint32_t case_id;
  uint32_t seed;
  uint32_t status;
  uint32_t reset_reason;
  uint32_t variant;
  uint32_t mutation_id;
  uint32_t cfg_len;
  uint32_t cfg_crc32;
  uint32_t mount_count;
  uint32_t umount_count;
  uint32_t suspend_count;
  uint32_t resume_count;
  uint32_t midi_rx_packets;
  uint32_t midi_tx_packets;
  uint32_t control_unknown;
  uint32_t uptime_ms;
  uint32_t checksum;
};

static const uint32_t JOURNAL_MAGIC = 0x414D4655u; // AMFU: Audio MIDI FUzzer
static const uint32_t JOURNAL_VERSION = 1u;

// ----------------------- Runtime state ----------------------

static const char *TAG = "amfuzz";
static bool g_dump_mode = false;

static uint8_t g_cfg[CFG_MAX_LEN];
static uint16_t g_cfg_len = 0;

static uint32_t g_case_id = 0;
static uint32_t g_seed = 0;
static uint32_t g_variant = 0;
static uint32_t g_mutation_id = 0;
static uint32_t g_boot_ms = 0;
static uint32_t g_last_usb_activity_ms = 0;
static bool g_saw_usb_activity = false;
static bool g_recorded_idle_suspect = false;

static volatile uint32_t g_mount_count = 0;
static volatile uint32_t g_umount_count = 0;
static volatile uint32_t g_suspend_count = 0;
static volatile uint32_t g_resume_count = 0;
static volatile uint32_t g_midi_rx_packets = 0;
static volatile uint32_t g_midi_tx_packets = 0;
static volatile uint32_t g_control_unknown = 0;


// ----------------------- Device descriptor ------------------

static const tusb_desc_device_t g_device_desc = {
  .bLength            = sizeof(tusb_desc_device_t),
  .bDescriptorType    = TUSB_DESC_DEVICE,
  .bcdUSB             = 0x0200,
  .bDeviceClass       = 0x00,
  .bDeviceSubClass    = 0x00,
  .bDeviceProtocol    = 0x00,
  .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,
  .idVendor           = 0x303A, // Espressif VID used by many ESP32-Sx dev boards
  .idProduct          = 0x1003, // Deliberately different from your HID PID
  .bcdDevice          = 0x0100,
  .iManufacturer      = 0x01,
  .iProduct           = 0x02,
  .iSerialNumber      = 0x03,
  .bNumConfigurations = 0x01,
};

// esp_tinyusb accepts UTF-8 C strings here and emits USB string descriptors.
// Index 0 is the language ID pseudo-string. The remaining strings are selected
// deterministically per case to fuzz host-side Unicode/string descriptor paths.
//
// Fields used by the device descriptor:
//   iManufacturer = 1
//   iProduct      = 2
//   iSerialNumber = 3
// Extra string index 4 is kept for interface/function naming.
static const char *g_lang_id = (const char[]){0x09, 0x04}; // en-US
static const char *g_string_desc[5] = {
  nullptr,
  "FuzzSociety",
  "ESP32-S3 Audio/MIDI Fuzzer",
  "AMFUZ-0001",
  "AudioMIDI",
};

struct UnicodeStringProfile {
  const char *manufacturer;
  const char *product;
  const char *serial;
  const char *function_name;
};

static const UnicodeStringProfile g_unicode_profiles[] = {
  // 0: ASCII baseline
  {"FuzzSociety", "ESP32-S3 Audio/MIDI Fuzzer", "AMFUZ-ASCII-0001", "AudioMIDI"},

  // CJK families
  {"模糊社", "ESP32-S3 音频/MIDI 描述符模糊器", "序列-零一二三", "音频MIDI"},
  {"模糊社測試", "高速音訊介面 測試裝置", "序號-甲乙丙丁", "音訊MIDI串流"},
  {"ファズ協会", "ESP32-S3 オーディオ/MIDI ファザー", "シリアル-アイウエオ", "音声MIDI"},
  {"퍼즈소사이어티", "ESP32-S3 오디오/MIDI 퍼저", "일련번호-가나다라", "오디오MIDI"},

  // Cyrillic / Greek / Hebrew / Arabic
  {"ФаззСообщество", "ESP32-S3 Аудио/MIDI фаззер", "СЕРИЙНЫЙ-АБВГД", "АудиоMIDI"},
  {"ΚοινότηταFuzz", "ESP32-S3 Δοκιμή Ήχου/MIDI", "ΣΕΙΡΑ-ΑΒΓΔ", "ΉχοςMIDI"},
  {"חברת־פאז", "ESP32-S3 בדיקת שמע/MIDI", "מספר-אבגד", "שמעMIDI"},
  {"مجتمع فز", "ESP32-S3 فاحص صوت/MIDI", "تسلسل-ابتث", "صوتMIDI"},

  // Indic / Southeast Asian scripts
  {"फ़ज़समाज", "ESP32-S3 ऑडियो/MIDI फ़ज़र", "क्रमांक-कखग", "ऑडियोMIDI"},
  {"ฟัซโซไซตี้", "ESP32-S3 ตัวทดสอบเสียง/MIDI", "ลำดับ-กขค", "เสียงMIDI"},
  {"សង្គមហ្វាស់", "ESP32-S3 អូឌីយ៉ូ/MIDI", "ស៊េរី-កខគ", "អូឌីយ៉ូMIDI"},

  // Accents / normalization-ish / combining marks
  {"FúzzSociété", "ESP32-S3 Áudio/MIDI Fuzzér", "SÉRIE-ÀÉÎÕÜ", "ÁudioMIDI"},
  {"Cafe\u0301 Fuzz", "A\u030Angstro\u0308m Audio MIDI", "N\u0303-Combining-Serial", "Combining\u0301MIDI"},
  {"Zalgo Fuzz", "A̴u̷d̸i̶o̵ M̷I̶D̵I̸", "Z̵A̶L̸G̴O̷-001", "Z̶a̸l̴g̵o̷"},

  // Fullwidth / mathematical / enclosed / symbols
  {"ＦｕｚｚＳｏｃｉｅｔｙ", "ＥＳＰ３２－Ｓ３　Ａｕｄｉｏ／ＭＩＤＩ", "ＳＮ－１２３４５", "ＡｕｄｉｏＭＩＤＩ"},
  {"𝔉𝔲𝔷𝔷𝔖𝔬𝔠𝔦𝔢𝔱𝔶", "𝔈𝔖𝔓32-S3 𝔄𝔲𝔡𝔦𝔬/MIDI", "𝔖𝔑-𝟘𝟙𝟚𝟛", "𝔐𝔦𝔡𝔦"},
  {"ⓕⓤⓩⓩ", "Ⓐⓤⓓⓘⓞ ⓂⒾⒹⒾ", "ⓈⓃ-①②③", "ⓂⒾⒹⒾ"},
  {"Fuzz ⚙ Society", "ESP32-S3 ♫ Audio/MIDI ♬", "SN-♠♥♦♣", "♫MIDI♫"},

  // Emoji / supplementary planes
  {"🐈‍⬛ FuzzSociety", "ESP32-S3 🎧🎹 Audio/MIDI", "SN-😀😈💣🧪", "🎹MIDI"},
  {"🧬🔬⚡", "🧪 USB Audio MIDI Fuzzer 🧪", "🧯🧯🧯", "🎛️🎚️🎙️"},

  // Bidi/control-ish strings. These include Unicode bidi controls inside UTF-8.
  {"Fuzz\u202EyticoS", "Audio\u202EMIDI\u202C ESP32", "SN\u202E12345", "MIDI\u202EAudio"},
  {"Fuzz\u200FSociety", "ESP32\u200F Audio\u200E MIDI", "SN\u200FRTL\u200E", "RTL\u200FMIDI"},
  {"Fuzz\u2066Society\u2069", "\u2067MIDI Audio\u2069 ESP32", "SN\u2066ISO\u2069", "ISO-MIDI"},

  // Long but still reasonable strings; long enough to exercise truncation/alloc paths.
  {"FuzzSociety-长长长长长长长长长长长长长长长长长长长长", "ESP32-S3-Audio-MIDI-设备-描述符-模糊测试-长产品名称-ABCDEFGHIJKLMNOPQRSTUVWXYZ", "SN-LONG-000000000000000000000000000000000000", "LongAudioMIDI"},
  {"Производитель-очень-длинная-строка-для-теста", "Устройство-USB-Audio-MIDI-с-очень-длинным-именем", "СЕРИЯ-ДЛИННАЯ-0000000000000000", "ДлинныйMIDI"},

  // Mixed scripts and odd separators
  {"Fuzz/模糊/Фазз/فز", "Audio🎧MIDI🎹音频ミディمدي", "SN-混合-MIX-مزيج", "MixMIDI"},
  {"ASCII Symbols !@#$%^&*()[]{}<>?/|~`+-=", "Quoted \"Audio\" MIDI Device", "SN-QUOTE-BACKSLASH", "QuoteMIDI"},
  {"Zero Width Fuzz", "ESP32\u200BAudio\u200BMIDI\u200BFuzzer", "SN\u200BZERO\u200BWIDTH", "Zero\u200BWidth"},
};

static void select_unicode_strings() {
  size_t count = sizeof(g_unicode_profiles) / sizeof(g_unicode_profiles[0]);
  size_t idx = (size_t)(g_case_id % count);
  g_string_desc[0] = g_lang_id;
  g_string_desc[1] = g_unicode_profiles[idx].manufacturer;
  g_string_desc[2] = g_unicode_profiles[idx].product;
  g_string_desc[3] = g_unicode_profiles[idx].serial;
  g_string_desc[4] = g_unicode_profiles[idx].function_name;
}

// ----------------------- Helpers ----------------------------

static uint32_t now_ms() {
  return (uint32_t)(esp_timer_get_time() / 1000ULL);
}

static uint32_t xorshift32(uint32_t &s) {
  if (s == 0) s = 0x12345678u;
  s ^= s << 13;
  s ^= s >> 17;
  s ^= s << 5;
  return s;
}

static uint8_t rnd8(uint32_t &s) {
  return (uint8_t)(xorshift32(s) & 0xffu);
}

static uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t len) {
  crc = ~crc;
  for (size_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (int k = 0; k < 8; k++) {
      crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
  }
  return ~crc;
}

static uint32_t cfg_crc32() {
  return crc32_update(0, g_cfg, g_cfg_len);
}

static void mark_activity() {
  g_saw_usb_activity = true;
  g_last_usb_activity_ms = now_ms();
}

static uint32_t checksum_entry(const JournalEntry &e) {
  const uint32_t *p = (const uint32_t *)&e;
  uint32_t n = (sizeof(JournalEntry) / sizeof(uint32_t)) - 1;
  uint32_t c = 0x5AA55AA5u;
  for (uint32_t i = 0; i < n; i++) {
    c ^= p[i] + 0x9E3779B9u + (c << 6) + (c >> 2);
  }
  return c;
}

static bool valid_entry(const JournalEntry &e) {
  return e.magic == JOURNAL_MAGIC &&
         e.version == JOURNAL_VERSION &&
         e.checksum == checksum_entry(e);
}

static void key_for_record(uint32_t idx, char out[8]) {
  snprintf(out, 8, "j%03lu", (unsigned long)idx);
}

static void reset_stats() {
  g_mount_count = 0;
  g_umount_count = 0;
  g_suspend_count = 0;
  g_resume_count = 0;
  g_midi_rx_packets = 0;
  g_midi_tx_packets = 0;
  g_control_unknown = 0;
}

static void append_journal(uint32_t status, uint32_t reset_reason) {
  JournalEntry e{};
  e.magic = JOURNAL_MAGIC;
  e.version = JOURNAL_VERSION;
  e.case_id = g_case_id;
  e.seed = g_seed;
  e.status = status;
  e.reset_reason = reset_reason;
  e.variant = g_variant;
  e.mutation_id = g_mutation_id;
  e.cfg_len = g_cfg_len;
  e.cfg_crc32 = cfg_crc32();
  e.mount_count = g_mount_count;
  e.umount_count = g_umount_count;
  e.suspend_count = g_suspend_count;
  e.resume_count = g_resume_count;
  e.midi_rx_packets = g_midi_rx_packets;
  e.midi_tx_packets = g_midi_tx_packets;
  e.control_unknown = g_control_unknown;
  e.uptime_ms = now_ms() - g_boot_ms;
  e.checksum = checksum_entry(e);

  nvs_handle_t nvs;
  if (nvs_open("amfuzz", NVS_READWRITE, &nvs) != ESP_OK) return;

  uint32_t head = 0, count = 0;
  nvs_get_u32(nvs, "head", &head);
  nvs_get_u32(nvs, "count", &count);

  char key[8];
  key_for_record(head, key);
  nvs_set_blob(nvs, key, &e, sizeof(e));

  head = (head + 1u) % JOURNAL_MAX;
  if (count < JOURNAL_MAX) count++;
  nvs_set_u32(nvs, "head", head);
  nvs_set_u32(nvs, "count", count);
  nvs_commit(nvs);
  nvs_close(nvs);
}

static void set_active_case() {
  nvs_handle_t nvs;
  if (nvs_open("amfuzz", NVS_READWRITE, &nvs) != ESP_OK) return;
  nvs_set_u32(nvs, "active", 1);
  nvs_set_u32(nvs, "acase", g_case_id);
  nvs_set_u32(nvs, "aseed", g_seed);
  nvs_set_u32(nvs, "avar", g_variant);
  nvs_set_u32(nvs, "amut", g_mutation_id);
  nvs_commit(nvs);
  nvs_close(nvs);
}

static void clear_active_case() {
  nvs_handle_t nvs;
  if (nvs_open("amfuzz", NVS_READWRITE, &nvs) != ESP_OK) return;
  nvs_set_u32(nvs, "active", 0);
  nvs_commit(nvs);
  nvs_close(nvs);
}

static void process_previous_active_case() {
  nvs_handle_t nvs;
  if (nvs_open("amfuzz", NVS_READWRITE, &nvs) != ESP_OK) return;

  uint32_t active = 0;
  nvs_get_u32(nvs, "active", &active);
  if (active == 1) {
    nvs_get_u32(nvs, "acase", &g_case_id);
    nvs_get_u32(nvs, "aseed", &g_seed);
    nvs_get_u32(nvs, "avar", &g_variant);
    nvs_get_u32(nvs, "amut", &g_mutation_id);
    nvs_close(nvs);

    append_journal(STATUS_POWERLOSS_SUSPECT, (uint32_t)esp_reset_reason());

    if (nvs_open("amfuzz", NVS_READWRITE, &nvs) == ESP_OK) {
      nvs_set_u32(nvs, "active", 0);
      nvs_commit(nvs);
      nvs_close(nvs);
    }
    return;
  }

  nvs_close(nvs);
}

static void choose_case() {
#if AUTO_ADVANCE_CASE
  nvs_handle_t nvs;
  if (nvs_open("amfuzz", NVS_READWRITE, &nvs) != ESP_OK) {
    g_case_id = 0;
  } else {
    nvs_get_u32(nvs, "next", &g_case_id);
    nvs_set_u32(nvs, "next", g_case_id + 1u);
    nvs_commit(nvs);
    nvs_close(nvs);
  }
#else
  g_case_id = CASE_OVERRIDE;
#endif

  g_seed = 0xA11D0000u ^ (g_case_id * 0x9E3779B9u) ^ 0x4D494449u;
  uint32_t s = g_seed;
  g_variant = (g_case_id < 9) ? g_case_id : (xorshift32(s) % 9u);
  g_mutation_id = xorshift32(s);
}

// ----------------------- Descriptor builder -----------------

static void d_reset() {
  g_cfg_len = 0;
  memset(g_cfg, 0, sizeof(g_cfg));
}

static void d8(uint8_t v) {
  if (g_cfg_len < CFG_MAX_LEN) g_cfg[g_cfg_len++] = v;
}

static void d16(uint16_t v) {
  d8((uint8_t)(v & 0xffu));
  d8((uint8_t)(v >> 8));
}

static uint16_t d_pos() { return g_cfg_len; }

static void patch16(uint16_t pos, uint16_t v) {
  if (pos + 1 < CFG_MAX_LEN) {
    g_cfg[pos] = (uint8_t)(v & 0xffu);
    g_cfg[pos + 1] = (uint8_t)(v >> 8);
  }
}

static void desc_config_start(uint8_t n_interfaces) {
  d8(9); d8(TUSB_DESC_CONFIGURATION);
  d16(0);                         // patched total length
  d8(n_interfaces);
  d8(1);                          // bConfigurationValue
  d8(0);                          // iConfiguration
  d8(0x80);                       // bus powered
  d8(50);                         // 100 mA
}

static void desc_interface(uint8_t num, uint8_t alt, uint8_t eps,
                           uint8_t cls, uint8_t subcls, uint8_t proto) {
  d8(9); d8(TUSB_DESC_INTERFACE);
  d8(num); d8(alt); d8(eps);
  d8(cls); d8(subcls); d8(proto);
  d8(0);
}

static void desc_ep(uint8_t ep, uint8_t attr, uint16_t mps, uint8_t interval) {
  d8(7); d8(TUSB_DESC_ENDPOINT);
  d8(ep); d8(attr); d16(mps); d8(interval);
}

static void desc_ac_header(uint16_t total_len, uint8_t in_collection, uint8_t iface_nr) {
  d8(9); d8(CS_INTERFACE); d8(AC_HEADER);
  d16(0x0100);                    // UAC 1.0
  d16(total_len);
  d8(in_collection);
  d8(iface_nr);
}

static uint16_t desc_ms_header_placeholder() {
  d8(7); d8(CS_INTERFACE); d8(MS_HEADER);
  d16(0x0100);
  uint16_t p = d_pos();
  d16(0);                         // patched MS total length
  return p;
}

static void desc_midi_in_jack(uint8_t jack_type, uint8_t jack_id, uint8_t str_idx = 0) {
  d8(6); d8(CS_INTERFACE); d8(MIDI_IN_JACK);
  d8(jack_type); d8(jack_id); d8(str_idx);
}

static void desc_midi_out_jack(uint8_t jack_type, uint8_t jack_id,
                               uint8_t n_pins, uint8_t src_id, uint8_t src_pin,
                               uint8_t str_idx = 0) {
  // 7 + 2 * n_pins in USB-MIDI 1.0
  d8((uint8_t)(7 + 2 * n_pins)); d8(CS_INTERFACE); d8(MIDI_OUT_JACK);
  d8(jack_type); d8(jack_id); d8(n_pins);
  for (uint8_t i = 0; i < n_pins; i++) {
    d8(src_id); d8(src_pin);
  }
  d8(str_idx);
}

static void desc_ms_ep_companion(uint8_t declared_len, uint8_t n_jacks,
                                 uint8_t jack_a, uint8_t jack_b = 0) {
  d8(declared_len); d8(CS_ENDPOINT); d8(EP_GENERAL);
  d8(n_jacks);
  if (declared_len > 4) d8(jack_a);
  if (declared_len > 5) d8(jack_b);
  // pad malformed oversized companion descriptors deterministically
  for (uint8_t i = 6; i < declared_len; i++) d8((uint8_t)(0x80u + i));
}

static void add_random_cs_trailers(uint32_t &s) {
  uint8_t n = 1 + (xorshift32(s) % 8);
  for (uint8_t i = 0; i < n && g_cfg_len < CFG_MAX_LEN - 16; i++) {
    uint8_t len = 3 + (xorshift32(s) % 12);
    d8(len);
    d8((xorshift32(s) & 1) ? CS_INTERFACE : CS_ENDPOINT);
    d8(rnd8(s));
    for (uint8_t j = 3; j < len; j++) d8(rnd8(s));
  }
}

static void build_midi_descriptor(uint32_t variant) {
  d_reset();
  uint32_t s = g_seed;

  uint8_t iface_count = 2;
  if (variant == VAR_BAD_INTERFACE_COUNTS) iface_count = (uint8_t)(1 + (xorshift32(s) % 5));
  if (variant == VAR_MIDI_WITH_AUDIO_STREAM) iface_count = 4;

  desc_config_start(iface_count);

  // Interface 0: AudioControl.
  desc_interface(0, 0, 0, USB_CLASS_AUDIO, AUDIO_SUBCLASS_CONTROL, AUDIO_PROTO_UNDEFINED);

  uint16_t ac_total = 9;
  uint8_t ac_collection = 1;
  uint8_t ac_iface_ref = 1;

  if (variant == VAR_BAD_TOTAL_LENGTHS) {
    ac_total = (uint16_t)(xorshift32(s) & 0xffffu);
    ac_collection = (uint8_t)(xorshift32(s) & 0xffu);
    ac_iface_ref = (uint8_t)(xorshift32(s) & 0xffu);
  }
  desc_ac_header(ac_total, ac_collection, ac_iface_ref);

  // Interface 1: MIDIStreaming with two bulk endpoints.
  uint8_t midi_eps = 2;
  if (variant == VAR_BAD_INTERFACE_COUNTS) midi_eps = (uint8_t)(xorshift32(s) % 5);
  desc_interface(1, 0, midi_eps, USB_CLASS_AUDIO, AUDIO_SUBCLASS_MIDISTREAM, AUDIO_PROTO_UNDEFINED);

  uint16_t ms_start = d_pos();
  uint16_t ms_total_patch = desc_ms_header_placeholder();

  uint8_t in_emb = 1, in_ext = 2, out_emb = 3, out_ext = 4;
  if (variant == VAR_DUP_JACK_IDS) {
    in_emb = in_ext = out_emb = out_ext = (uint8_t)(1 + (xorshift32(s) % 7));
  } else if (variant == VAR_ZERO_JACK_IDS) {
    in_emb = 0; in_ext = 0; out_emb = 0; out_ext = 0;
  } else if (g_case_id >= 9) {
    // Mild randomization after fixed corpus.
    if ((xorshift32(s) % 7) == 0) in_emb = (uint8_t)(xorshift32(s) & 0xffu);
    if ((xorshift32(s) % 7) == 0) out_emb = (uint8_t)(xorshift32(s) & 0xffu);
  }

  desc_midi_in_jack(JACK_EMBEDDED, in_emb);
  desc_midi_in_jack(JACK_EXTERNAL, in_ext);
  desc_midi_out_jack(JACK_EMBEDDED, out_emb, 1, in_ext, 1);
  desc_midi_out_jack(JACK_EXTERNAL, out_ext, 1, in_emb, 1);

  // OUT endpoint + companion: host to device.
  desc_ep(EP_MIDI_OUT, TUSB_XFER_BULK, 64, 0);
  if (variant == VAR_BAD_ENDPOINT_COMPANION) {
    uint8_t len = (uint8_t)(3 + (xorshift32(s) % 16));
    uint8_t n_jacks = (uint8_t)(xorshift32(s) & 0xffu);
    desc_ms_ep_companion(len, n_jacks, in_emb, in_ext);
  } else {
    desc_ms_ep_companion(5, 1, in_emb);
  }

  // IN endpoint + companion: device to host.
  desc_ep(EP_MIDI_IN, TUSB_XFER_BULK, 64, 0);
  if (variant == VAR_BAD_ENDPOINT_COMPANION) {
    uint8_t len = (uint8_t)(3 + (xorshift32(s) % 16));
    uint8_t n_jacks = (uint8_t)(xorshift32(s) & 0xffu);
    desc_ms_ep_companion(len, n_jacks, out_emb, out_ext);
  } else {
    desc_ms_ep_companion(5, 1, out_emb);
  }

  uint16_t ms_total = d_pos() - ms_start;
  if (variant == VAR_BAD_TOTAL_LENGTHS) {
    uint16_t choices[] = {0, 1, 7, 9, 0xFFFF, (uint16_t)(ms_total - 1), (uint16_t)(ms_total + 32)};
    ms_total = choices[xorshift32(s) % (sizeof(choices) / sizeof(choices[0]))];
  }
  patch16(ms_total_patch, ms_total);

  if (variant == VAR_RANDOM_CS_TRAILERS || (g_case_id >= 9 && (xorshift32(s) % 4) == 0)) {
    add_random_cs_trailers(s);
  }

  if (variant == VAR_MIDI_WITH_AUDIO_STREAM) {
    // Add AudioStreaming-ish interfaces after the MIDIStreaming interface.
    // These are descriptor-level fuzzing bait; no real audio data is produced.
    desc_interface(2, 0, 0, USB_CLASS_AUDIO, AUDIO_SUBCLASS_STREAMING, AUDIO_PROTO_UNDEFINED);
    desc_interface(2, 1, 1, USB_CLASS_AUDIO, AUDIO_SUBCLASS_STREAMING, AUDIO_PROTO_UNDEFINED);
    // A few class-specific AS descriptors, intentionally minimal/odd.
    d8(7); d8(CS_INTERFACE); d8(0x01); d8(1); d8(1); d16(0x0001); // AS_GENERAL-ish
    d8(11); d8(CS_INTERFACE); d8(0x02); d8(1); d8(1); d8(2); d8(16); d16(16000); d16(0); // FORMAT_TYPE-ish/truncated-ish
    desc_ep(EP_AUDIO_OUT, TUSB_XFER_ISOCHRONOUS, 64, 1);
    d8(7); d8(CS_ENDPOINT); d8(0x01); d8(0); d8(0); d16(0); // Audio EP general-ish
  }

  // Patch configuration total length. Sometimes deliberately wrong.
  uint16_t total = g_cfg_len;
  if (variant == VAR_BAD_TOTAL_LENGTHS && (xorshift32(s) & 1)) {
    uint16_t bad[] = {9, 32, 0x00FF, 0xFFFF, (uint16_t)(total + 64), (uint16_t)(total - 1)};
    total = bad[xorshift32(s) % (sizeof(bad) / sizeof(bad[0]))];
  }
  patch16(2, total);
}

static void build_audio_only_descriptor(uint32_t variant) {
  d_reset();
  uint32_t s = g_seed;

  uint8_t ifaces = (variant == VAR_BAD_INTERFACE_COUNTS) ? (uint8_t)(1 + (xorshift32(s) % 5)) : 2;
  desc_config_start(ifaces);

  desc_interface(0, 0, 0, USB_CLASS_AUDIO, AUDIO_SUBCLASS_CONTROL, AUDIO_PROTO_UNDEFINED);
  // Minimal UAC AC header referring to interface 1.
  uint16_t ac_total = (variant == VAR_BAD_TOTAL_LENGTHS) ? (uint16_t)(xorshift32(s) & 0xffffu) : 9;
  desc_ac_header(ac_total, 1, 1);

  // AudioStreaming alt 0 and alt 1. This is intentionally descriptor-focused.
  desc_interface(1, 0, 0, USB_CLASS_AUDIO, AUDIO_SUBCLASS_STREAMING, AUDIO_PROTO_UNDEFINED);
  desc_interface(1, 1, 1, USB_CLASS_AUDIO, AUDIO_SUBCLASS_STREAMING, AUDIO_PROTO_UNDEFINED);

  // AS_GENERAL-ish and FORMAT_TYPE-ish. Some cases mutate lengths/values.
  uint8_t as_len = (variant == VAR_RANDOM_CS_TRAILERS) ? (uint8_t)(3 + (xorshift32(s) % 12)) : 7;
  d8(as_len); d8(CS_INTERFACE); d8(0x01);
  for (uint8_t i = 3; i < as_len; i++) d8(rnd8(s));

  uint8_t fmt_len = (variant == VAR_BAD_TOTAL_LENGTHS) ? (uint8_t)(3 + (xorshift32(s) % 20)) : 11;
  d8(fmt_len); d8(CS_INTERFACE); d8(0x02);
  for (uint8_t i = 3; i < fmt_len; i++) d8(rnd8(s));

  uint16_t mps_choices[] = {0, 1, 8, 32, 64, 128, 255, 512, 1023};
  uint16_t mps = mps_choices[xorshift32(s) % (sizeof(mps_choices) / sizeof(mps_choices[0]))];
  desc_ep(EP_AUDIO_OUT, TUSB_XFER_ISOCHRONOUS, mps, (uint8_t)(xorshift32(s) & 0xffu));

  if ((xorshift32(s) & 1) || variant == VAR_RANDOM_CS_TRAILERS) {
    add_random_cs_trailers(s);
  }

  patch16(2, g_cfg_len);
}

static void build_fuzz_descriptor() {
  if (g_variant == VAR_AUDIO_ONLY_ODD_STREAM) {
    build_audio_only_descriptor(g_variant);
  } else {
    build_midi_descriptor(g_variant);
  }
}

// ----------------------- TinyUSB callbacks ------------------
// esp_tinyusb v2.x provides lifecycle callbacks internally. Defining tud_mount_cb,
// tud_umount_cb, or MSC callbacks here causes multiple-definition linker errors.
// This minimal fuzzer deliberately avoids user TinyUSB callbacks and relies on
// active-case journaling to detect power-loss/reboot suspects.

// ----------------------- MIDI traffic task ------------------

static void midi_traffic_task(void *arg) {
  (void)arg;
#if SEND_MIDI_TRAFFIC && CFG_TUD_MIDI
  uint32_t s = g_seed ^ 0x54455854u;
  uint32_t last = 0;
  while (!g_dump_mode) {
    uint32_t n = now_ms();
    if (n - last >= MIDI_TRAFFIC_PERIOD_MS && tud_mounted()) {
      last = n;
      mark_activity();

      uint8_t pkt[4];
      uint32_t r = xorshift32(s) % 8;
      switch (r) {
        case 0: // Note on
          pkt[0] = 0x09; pkt[1] = 0x90; pkt[2] = (uint8_t)(xorshift32(s) & 0x7f); pkt[3] = 0x40; break;
        case 1: // Note off
          pkt[0] = 0x08; pkt[1] = 0x80; pkt[2] = (uint8_t)(xorshift32(s) & 0x7f); pkt[3] = 0x00; break;
        case 2: // CC
          pkt[0] = 0x0B; pkt[1] = 0xB0; pkt[2] = (uint8_t)(xorshift32(s) & 0x7f); pkt[3] = (uint8_t)(xorshift32(s) & 0x7f); break;
        case 3: // Program change, with odd 4th byte
          pkt[0] = 0x0C; pkt[1] = 0xC0; pkt[2] = (uint8_t)(xorshift32(s) & 0x7f); pkt[3] = rnd8(s); break;
        case 4: // SysEx start/continue
          pkt[0] = 0x04; pkt[1] = 0xF0; pkt[2] = rnd8(s); pkt[3] = rnd8(s); break;
        case 5: // SysEx end 3 bytes
          pkt[0] = 0x07; pkt[1] = rnd8(s); pkt[2] = rnd8(s); pkt[3] = 0xF7; break;
        case 6: // Malformed-ish CIN/status mismatch
          pkt[0] = (uint8_t)(xorshift32(s) & 0x0f); pkt[1] = rnd8(s); pkt[2] = rnd8(s); pkt[3] = rnd8(s); break;
        default: // cable number fuzz in header
          pkt[0] = (uint8_t)(((xorshift32(s) & 0x0f) << 4) | (xorshift32(s) & 0x0f));
          pkt[1] = rnd8(s); pkt[2] = rnd8(s); pkt[3] = rnd8(s); break;
      }

      if (tud_midi_packet_write(pkt)) {
        g_midi_tx_packets = g_midi_tx_packets + 1;
      }
    }
    vTaskDelay(pdMS_TO_TICKS(10));
  }
#else
  while (!g_dump_mode) {
    vTaskDelay(pdMS_TO_TICKS(250));
  }
#endif
  vTaskDelete(NULL);
}

// ----------------------- Driver init ------------------------

static void install_usb() {
  // esp_tinyusb v2.x uses nested descriptor fields.
  // The macro lives in tinyusb_default_config.h.
  tinyusb_config_t tusb_cfg = TINYUSB_DEFAULT_CONFIG();
  tusb_cfg.descriptor.device = &g_device_desc;
  tusb_cfg.descriptor.string = g_string_desc;
  tusb_cfg.descriptor.string_count = sizeof(g_string_desc) / sizeof(g_string_desc[0]);
  tusb_cfg.descriptor.full_speed_config = g_cfg;
#if (TUD_OPT_HIGH_SPEED)
  tusb_cfg.descriptor.high_speed_config = NULL;
  tusb_cfg.descriptor.qualifier = NULL;
#endif

  ESP_ERROR_CHECK(tinyusb_driver_install(&tusb_cfg));
}

// ----------------------- Main -------------------------------

extern "C" void app_main(void) {
  g_boot_ms = now_ms();
  g_last_usb_activity_ms = g_boot_ms;

  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ESP_ERROR_CHECK(nvs_flash_init());
  }

#if RESET_ALL_STATE
  nvs_flash_erase();
  nvs_flash_init();
#endif

  gpio_config_t io_conf{};
  io_conf.intr_type = GPIO_INTR_DISABLE;
  io_conf.mode = GPIO_MODE_INPUT;
  io_conf.pin_bit_mask = 1ULL << BOOT_BUTTON_PIN;
  io_conf.pull_up_en = GPIO_PULLUP_ENABLE;
  io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
  gpio_config(&io_conf);
  vTaskDelay(pdMS_TO_TICKS(50));
  g_dump_mode = (gpio_get_level(BOOT_BUTTON_PIN) == 0);

  process_previous_active_case();
  reset_stats();

  if (g_dump_mode) {
    // Minimal safe action: hold BOOT during reset to clear campaign state.
    nvs_handle_t nvs;
    if (nvs_open("amfuzz", NVS_READWRITE, &nvs) == ESP_OK) {
      nvs_erase_all(nvs);
      nvs_commit(nvs);
      nvs_close(nvs);
    }
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
  }

  choose_case();
  select_unicode_strings();
  build_fuzz_descriptor();
  set_active_case();
  install_usb();

  xTaskCreate(midi_traffic_task, "midi_traffic", 4096, NULL, 5, NULL);

#if !AUTO_ADVANCE_CASE
  append_journal(STATUS_REPLAY_MARKER, (uint32_t)esp_reset_reason());
#endif

  const uint32_t dwell = AUTO_ADVANCE_CASE ? CASE_DWELL_MS : REPLAY_DWELL_MS;
  uint32_t start = now_ms();

  while ((now_ms() - start) < dwell) {
#if ENABLE_IDLE_SUSPECT
    if (!g_recorded_idle_suspect && g_saw_usb_activity && (now_ms() - g_last_usb_activity_ms) > IDLE_SUSPECT_MS) {
      g_recorded_idle_suspect = true;
      append_journal(STATUS_IDLE_TIMEOUT_SUSPECT, (uint32_t)esp_reset_reason());
    }
#endif
    vTaskDelay(pdMS_TO_TICKS(100));
  }

  append_journal(STATUS_COMPLETED_CLEAN, (uint32_t)esp_reset_reason());
  clear_active_case();
  vTaskDelay(pdMS_TO_TICKS(200));
  esp_restart();
}
