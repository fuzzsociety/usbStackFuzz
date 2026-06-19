/*
 * Descriptor and string-descriptor fuzzing for the RP2040 USB fuzzer.
 *
 * This file owns every TinyUSB descriptor callback. For each campaign case it:
 *   - builds a device descriptor whose PID encodes the active class (handy in
 *     host logs),
 *   - selects a Unicode string profile for manufacturer/product/serial/iface,
 *   - assembles a configuration descriptor for the active peripheral profile,
 *   - applies a bounded, deterministic mutation when the case is past the first
 *     clean pass over all profiles.
 *
 * "Real" profiles (HID/MIDI/CDC/Vendor/composite) start from a valid baseline
 * built with TinyUSB's TUD_*_DESCRIPTOR macros so the device fully enumerates
 * and the host binds the matching class driver. "Descriptor-only" profiles
 * (MSC/Audio) are hand-assembled byte streams: the host still parses them
 * during GET_DESCRIPTOR(configuration), even though the device has no driver to
 * fully configure them — that GET_DESCRIPTOR parse is the surface under test.
 */

#include <string.h>
#include <stdio.h>

#include "tusb.h"
#include "fuzz.h"
#include "usb_descriptors.h"

/* ---------------------------------------------------------------------------
 * Endpoint / interface assignments. Only one profile is active per boot, so
 * low endpoint numbers can be reused freely between profiles.
 * ------------------------------------------------------------------------- */
#define EPNUM_HID         0x81

#define EPNUM_MIDI_OUT    0x01
#define EPNUM_MIDI_IN     0x81

#define EPNUM_VENDOR_OUT  0x01
#define EPNUM_VENDOR_IN   0x81

#define EPNUM_CDC_NOTIF   0x81
#define EPNUM_CDC_OUT     0x02
#define EPNUM_CDC_IN      0x82

/* Composite (CDC itf 0/1, HID itf 2) needs distinct endpoints. */
#define EPNUM_C_CDC_NOTIF 0x81
#define EPNUM_C_CDC_OUT   0x02
#define EPNUM_C_CDC_IN    0x82
#define EPNUM_C_HID       0x83

/* String indices. 1/2/3 are device mfr/product/serial; 4/5 name interfaces. */
#define STR_IFACE_A       4
#define STR_IFACE_B       5

/* ---------------------------------------------------------------------------
 * HID report descriptor: accessibility-adjacent, non-keyboard surface.
 * Mirrors the ESP32-S3 HID firmware (assistive control, Braille display,
 * vendor-defined chaos report). It never enumerates as a keyboard.
 * ------------------------------------------------------------------------- */
#define REPORT_ID_ASSISTIVE 1
#define REPORT_ID_BRAILLE   2
#define REPORT_ID_VENDOR    3

static const uint8_t g_hid_report_desc[] = {
    /* Report ID 1: Generic Desktop / Assistive Control */
    0x05, 0x01, 0x09, 0x10, 0xA1, 0x01, 0x85, REPORT_ID_ASSISTIVE,
      0x05, 0x09, 0x19, 0x01, 0x29, 0x08, 0x15, 0x00, 0x25, 0x01,
      0x75, 0x01, 0x95, 0x08, 0x81, 0x02,
      0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x15, 0x81, 0x25, 0x7F,
      0x75, 0x08, 0x95, 0x02, 0x81, 0x06,
    0xC0,
    /* Report ID 2: Braille Display page (0x41) */
    0x06, 0x41, 0x00, 0x09, 0x01, 0xA1, 0x01, 0x85, REPORT_ID_BRAILLE,
      0x09, 0xFA, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x10, 0x81, 0x00,
      0x09, 0x05, 0x15, 0x00, 0x25, 0x40, 0x75, 0x08, 0x95, 0x01, 0xB1, 0x02,
      0x09, 0x03, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x20, 0x91, 0x02,
    0xC0,
    /* Report ID 3: vendor-defined 63-byte chaos report */
    0x06, 0x00, 0xFF, 0x09, 0x01, 0xA1, 0x01, 0x85, REPORT_ID_VENDOR,
      0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x3F,
      0x09, 0x01, 0x81, 0x02, 0x09, 0x02, 0x91, 0x02, 0x09, 0x03, 0xB1, 0x02,
    0xC0
};
#define HID_REPORT_DESC_LEN ((uint16_t)sizeof(g_hid_report_desc))

/* ---------------------------------------------------------------------------
 * Baseline configuration descriptors (valid, enumerable) for "real" profiles.
 * ------------------------------------------------------------------------- */
static const uint8_t cfg_hid[] = {
    TUD_CONFIG_DESCRIPTOR(1, 1, 0, TUD_CONFIG_DESC_LEN + TUD_HID_DESC_LEN,
                          TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, 100),
    TUD_HID_DESCRIPTOR(0, STR_IFACE_A, HID_ITF_PROTOCOL_NONE,
                       HID_REPORT_DESC_LEN, EPNUM_HID, CFG_TUD_HID_EP_BUFSIZE, 5),
};

static const uint8_t cfg_midi[] = {
    TUD_CONFIG_DESCRIPTOR(1, 2, 0, TUD_CONFIG_DESC_LEN + TUD_MIDI_DESC_LEN,
                          TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, 100),
    TUD_MIDI_DESCRIPTOR(0, STR_IFACE_A, EPNUM_MIDI_OUT, EPNUM_MIDI_IN, 64),
};

static const uint8_t cfg_cdc[] = {
    TUD_CONFIG_DESCRIPTOR(1, 2, 0, TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN,
                          TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, 100),
    TUD_CDC_DESCRIPTOR(0, STR_IFACE_A, EPNUM_CDC_NOTIF, 8,
                       EPNUM_CDC_OUT, EPNUM_CDC_IN, 64),
};

static const uint8_t cfg_vendor[] = {
    TUD_CONFIG_DESCRIPTOR(1, 1, 0, TUD_CONFIG_DESC_LEN + TUD_VENDOR_DESC_LEN,
                          TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, 100),
    TUD_VENDOR_DESCRIPTOR(0, STR_IFACE_A, EPNUM_VENDOR_OUT, EPNUM_VENDOR_IN, 64),
};

static const uint8_t cfg_composite[] = {
    TUD_CONFIG_DESCRIPTOR(1, 3, 0,
                          TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN + TUD_HID_DESC_LEN,
                          TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, 100),
    TUD_CDC_DESCRIPTOR(0, STR_IFACE_A, EPNUM_C_CDC_NOTIF, 8,
                       EPNUM_C_CDC_OUT, EPNUM_C_CDC_IN, 64),
    TUD_HID_DESCRIPTOR(2, STR_IFACE_B, HID_ITF_PROTOCOL_NONE,
                       HID_REPORT_DESC_LEN, EPNUM_C_HID, CFG_TUD_HID_EP_BUFSIZE, 5),
};

/* ---------------------------------------------------------------------------
 * Working buffers / state
 * ------------------------------------------------------------------------- */
#define CFG_BUF_MAX 512

static uint8_t  g_cfg[CFG_BUF_MAX];
static uint16_t g_cfg_len;

static tusb_desc_device_t g_dev;
static fuzz_profile_t     g_active_profile = PROF_HID_ACCESS;

fuzz_profile_t usb_fuzz_active_profile(void) { return g_active_profile; }

/* ---------------------------------------------------------------------------
 * Byte emitters for hand-built (descriptor-only) profiles and mutations.
 * ------------------------------------------------------------------------- */
static void e_reset(void)       { g_cfg_len = 0; }
static void e8(uint8_t v)       { if (g_cfg_len < CFG_BUF_MAX) g_cfg[g_cfg_len++] = v; }
static void e16(uint16_t v)     { e8((uint8_t)(v & 0xff)); e8((uint8_t)(v >> 8)); }
static void patch16(uint16_t pos, uint16_t v) {
    if (pos + 1 < CFG_BUF_MAX) { g_cfg[pos] = (uint8_t)(v & 0xff); g_cfg[pos + 1] = (uint8_t)(v >> 8); }
}

static void build_msc_desc_only(void) {
    e_reset();
    e8(9); e8(TUSB_DESC_CONFIGURATION); e16(0); e8(1); e8(1); e8(0); e8(0x80); e8(50);
    /* MSC interface: class 0x08, subclass 0x06 (SCSI), protocol 0x50 (BOT) */
    e8(9); e8(TUSB_DESC_INTERFACE); e8(0); e8(0); e8(2); e8(0x08); e8(0x06); e8(0x50); e8(STR_IFACE_A);
    e8(7); e8(TUSB_DESC_ENDPOINT); e8(0x01); e8(0x02); e16(64); e8(0);   /* bulk OUT */
    e8(7); e8(TUSB_DESC_ENDPOINT); e8(0x81); e8(0x02); e16(64); e8(0);   /* bulk IN  */
    patch16(2, g_cfg_len);
}

static void build_audio_desc_only(void) {
    e_reset();
    e8(9); e8(TUSB_DESC_CONFIGURATION); e16(0); e8(2); e8(1); e8(0); e8(0x80); e8(50);
    /* AudioControl interface */
    e8(9); e8(TUSB_DESC_INTERFACE); e8(0); e8(0); e8(0); e8(0x01); e8(0x01); e8(0x00); e8(STR_IFACE_A);
    /* AC header: CS_INTERFACE(0x24)/HEADER(0x01), bcdADC 1.00, wTotalLength, 1 streaming iface */
    e8(9); e8(0x24); e8(0x01); e16(0x0100); e16(9); e8(1); e8(1);
    /* AudioStreaming alt 0 (no endpoints) and alt 1 (one iso endpoint) */
    e8(9); e8(TUSB_DESC_INTERFACE); e8(1); e8(0); e8(0); e8(0x01); e8(0x02); e8(0x00); e8(STR_IFACE_B);
    e8(9); e8(TUSB_DESC_INTERFACE); e8(1); e8(1); e8(1); e8(0x01); e8(0x02); e8(0x00); e8(STR_IFACE_B);
    /* AS_GENERAL */
    e8(7); e8(0x24); e8(0x01); e8(1); e8(1); e16(0x0001);
    /* FORMAT_TYPE_I: 1 channel, 2 bytes/subframe, 16 bits, 1 freq = 16000 Hz */
    e8(11); e8(0x24); e8(0x02); e8(1); e8(1); e8(2); e8(16); e8(1); e8(0x80); e8(0x3e); e8(0x00);
    /* Isochronous OUT endpoint (UAC1 9-byte audio endpoint) */
    e8(9); e8(TUSB_DESC_ENDPOINT); e8(0x03); e8(0x01); e16(64); e8(1); e8(0); e8(0);
    /* CS_ENDPOINT / EP_GENERAL */
    e8(7); e8(0x25); e8(0x01); e8(0); e8(0); e16(0);
    patch16(2, g_cfg_len);
}

/* ---------------------------------------------------------------------------
 * Mutation engine. Walks the assembled descriptor and corrupts one field in a
 * deterministic, bounded way driven by the case PRNG.
 * ------------------------------------------------------------------------- */
static int nth_desc_of_type(uint8_t type, int n) {
    uint16_t off = 0;
    int count = 0;
    while (off + 2 <= g_cfg_len) {
        uint8_t blen = g_cfg[off];
        if (blen < 2) break;
        if (g_cfg[off + 1] == type) {
            if (count == n) return (int)off;
            count++;
        }
        off += blen;
    }
    return -1;
}

static int count_desc_of_type(uint8_t type) {
    uint16_t off = 0;
    int count = 0;
    while (off + 2 <= g_cfg_len) {
        uint8_t blen = g_cfg[off];
        if (blen < 2) break;
        if (g_cfg[off + 1] == type) count++;
        off += blen;
    }
    return count;
}

static int random_desc_off(uint8_t type) {
    int n = count_desc_of_type(type);
    if (n <= 0) return -1;
    return nth_desc_of_type(type, (int)(fuzz_rand() % (uint32_t)n));
}

static void append_random_cs_trailers(void) {
    uint8_t n = (uint8_t)(1 + (fuzz_rand() % 6));
    for (uint8_t i = 0; i < n && g_cfg_len < CFG_BUF_MAX - 16; i++) {
        uint8_t len = (uint8_t)(3 + (fuzz_rand() % 12));
        e8(len);
        e8((fuzz_rand() & 1) ? 0x24 /* CS_INTERFACE */ : 0x25 /* CS_ENDPOINT */);
        for (uint8_t j = 2; j < len; j++) e8(fuzz_rand8());
    }
}

/* TinyUSB transmits exactly wTotalLength bytes from g_cfg for the configuration
 * descriptor, so an over-claim must stay within the (fully zero-padded) buffer
 * or the device itself reads out of bounds. Under-claims are always safe. */
static uint16_t cap_total(uint16_t v) {
    return (v > CFG_BUF_MAX) ? (uint16_t)CFG_BUF_MAX : v;
}

static void mutate_config(fuzz_variant_t variant) {
    switch (variant) {
    case VAR_BAD_TOTAL_LENGTHS: {
        uint16_t real = g_cfg_len;
        uint16_t choices[] = {9, 0x00FF, CFG_BUF_MAX, (uint16_t)(real + 64),
                              (uint16_t)(real - 1), 0};
        patch16(2, cap_total(choices[fuzz_rand() % (sizeof(choices) / sizeof(choices[0]))]));
        break;
    }
    case VAR_BAD_BLENGTHS: {
        int off = random_desc_off(TUSB_DESC_INTERFACE);
        if (off < 0) off = random_desc_off(TUSB_DESC_ENDPOINT);
        if (off >= 0) {
            uint8_t bad[] = {0, 1, 2, 0xff, (uint8_t)(g_cfg[off] + 8)};
            g_cfg[off] = bad[fuzz_rand() % (sizeof(bad) / sizeof(bad[0]))];
        }
        break;
    }
    case VAR_BAD_CLASS_BYTES: {
        int off = random_desc_off(TUSB_DESC_INTERFACE);
        if (off >= 0 && off + 7 < g_cfg_len) {
            g_cfg[off + 5] = fuzz_rand8();   /* bInterfaceClass    */
            g_cfg[off + 6] = fuzz_rand8();   /* bInterfaceSubClass */
            g_cfg[off + 7] = fuzz_rand8();   /* bInterfaceProtocol */
        }
        break;
    }
    case VAR_BAD_STRING_INDEX: {
        int off = random_desc_off(TUSB_DESC_INTERFACE);
        if (off >= 0 && off + 8 < g_cfg_len) {
            g_cfg[off + 8] = (uint8_t)(0x40 + (fuzz_rand() & 0x3f)); /* iInterface */
        }
        break;
    }
    case VAR_BAD_ENDPOINTS: {
        int off = random_desc_off(TUSB_DESC_ENDPOINT);
        if (off >= 0 && off + 6 <= g_cfg_len) {
            switch (fuzz_rand() % 3) {
            case 0: g_cfg[off + 2] = fuzz_rand8(); break;          /* bEndpointAddress */
            case 1: g_cfg[off + 3] = fuzz_rand8(); break;          /* bmAttributes     */
            default: patch16((uint16_t)(off + 4), (uint16_t)(fuzz_rand() & 0xffff)); /* wMaxPacketSize */
            }
        }
        break;
    }
    case VAR_RANDOM_CS_TRAILERS:
        append_random_cs_trailers();
        patch16(2, g_cfg_len);   /* advertise the junk so the host reads it */
        break;
    case VAR_TRUNCATE_EXTEND: {
        uint16_t real = g_cfg_len;
        uint16_t delta = (uint16_t)(1 + (fuzz_rand() % 64));
        patch16(2, (fuzz_rand() & 1) ? cap_total((uint16_t)(real + delta))
                                     : (uint16_t)(real - delta));
        break;
    }
    default:
        break;
    }
}

/* ---------------------------------------------------------------------------
 * Unicode string profiles (subset of the ESP32-S3 MIDI firmware corpus).
 * ------------------------------------------------------------------------- */
typedef struct {
    const char *manufacturer;
    const char *product;
    const char *serial;
    const char *iface;
} unicode_profile_t;

static const unicode_profile_t g_unicode_profiles[] = {
    {"FuzzSociety", "RP2040 USB Fuzzer", "RP24-ASCII-0001", "FuzzIface"},
    {"模糊社", "RP2040 USB 描述符模糊器", "序列-零一二三", "接口"},
    {"ファズ協会", "RP2040 USB ファザー", "シリアル-アイウエオ", "インターフェース"},
    {"퍼즈소사이어티", "RP2040 USB 퍼저", "일련번호-가나다라", "인터페이스"},
    {"ФаззСообщество", "RP2040 USB фаззер", "СЕРИЙНЫЙ-АБВГД", "Интерфейс"},
    {"ΚοινότηταFuzz", "RP2040 USB Δοκιμή", "ΣΕΙΡΑ-ΑΒΓΔ", "Διεπαφή"},
    {"חברת־פאז", "RP2040 USB בדיקה", "מספר-אבגד", "ממשק"},
    {"مجتمع فز", "RP2040 USB فاحص", "تسلسل-ابتث", "واجهة"},
    {"फ़ज़समाज", "RP2040 USB फ़ज़र", "क्रमांक-कखग", "इंटरफ़ेस"},
    {"ฟัซโซไซตี้", "RP2040 USB ตัวทดสอบ", "ลำดับ-กขค", "อินเทอร์เฟซ"},
    {"FúzzSociété", "RP2040 USB Fuzzér", "SÉRIE-ÀÉÎÕÜ", "Ínterface"},
    {"Café Fuzz", "Ångström RP2040", "Ñ-Combining", "Íface"},
    {"Zalgo Fuzz", "R̴P̷2̸0̶4̵0̷ F̶u̵z̸z", "Z̵A̶L̸G̴O̷-001", "Z̶a̸l̴g̵o̷"},
    {"ＦｕｚｚＳｏｃｉｅｔｙ", "ＲＰ２０４０　ＵＳＢ", "ＳＮ－１２３４５", "Ｉｆａｃｅ"},
    {"🐈‍⬛ FuzzSociety", "RP2040 🎧🎹 USB", "SN-😀😈💣🧪", "🎛️Iface"},
    {"Fuzz‮yticoS", "RP2040‮BSU‬", "SN‮12345", "I‮face"},
    {"Zero Width Fuzz", "RP2040​USB​Fuzzer", "SN​ZERO​WIDTH", "Zero​If"},
    {"FuzzSociety-长长长长长长长长长长长长长长长长长长长长",
     "RP2040-USB-设备-描述符-模糊测试-长产品名称-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
     "SN-LONG-000000000000000000000000000000", "LongIface"},
};
#define N_UNICODE_PROFILES (sizeof(g_unicode_profiles) / sizeof(g_unicode_profiles[0]))

static const char *g_str[6]; /* [0] unused, [1..5] used */

static void select_unicode(uint32_t case_id) {
    const unicode_profile_t *p =
        &g_unicode_profiles[case_id % N_UNICODE_PROFILES];
    g_str[1] = p->manufacturer;
    g_str[2] = p->product;
    g_str[3] = p->serial;
    g_str[4] = p->iface;
    g_str[5] = p->iface;
}

/* Decode well-formed UTF-8 into UTF-16LE (with surrogate pairs). */
static size_t utf8_to_utf16(const char *in, uint16_t *out, size_t maxout) {
    const uint8_t *p = (const uint8_t *)in;
    size_t o = 0;
    while (*p && o < maxout) {
        uint32_t cp;
        uint8_t c = *p;
        if (c < 0x80) {
            cp = c; p += 1;
        } else if ((c >> 5) == 0x6 && p[1]) {
            cp = ((uint32_t)(c & 0x1f) << 6) | (p[1] & 0x3f); p += 2;
        } else if ((c >> 4) == 0xE && p[1] && p[2]) {
            cp = ((uint32_t)(c & 0x0f) << 12) | ((uint32_t)(p[1] & 0x3f) << 6) | (p[2] & 0x3f); p += 3;
        } else if ((c >> 3) == 0x1E && p[1] && p[2] && p[3]) {
            cp = ((uint32_t)(c & 0x07) << 18) | ((uint32_t)(p[1] & 0x3f) << 12) |
                 ((uint32_t)(p[2] & 0x3f) << 6) | (p[3] & 0x3f); p += 4;
        } else {
            cp = 0xFFFD; p += 1;
        }
        if (cp < 0x10000) {
            out[o++] = (uint16_t)cp;
        } else {
            if (o + 2 > maxout) break;
            cp -= 0x10000;
            out[o++] = (uint16_t)(0xD800 | (cp >> 10));
            out[o++] = (uint16_t)(0xDC00 | (cp & 0x3FF));
        }
    }
    return o;
}

/* ---------------------------------------------------------------------------
 * Per-case preparation
 * ------------------------------------------------------------------------- */
static void build_device_desc(fuzz_profile_t p) {
    memset(&g_dev, 0, sizeof(g_dev));
    g_dev.bLength         = sizeof(tusb_desc_device_t);
    g_dev.bDescriptorType = TUSB_DESC_DEVICE;
    g_dev.bcdUSB          = 0x0200;
    if (p == PROF_CDC || p == PROF_COMPOSITE) {
        /* Misc / IAD device triple required for CDC + composite. */
        g_dev.bDeviceClass    = 0xEF;
        g_dev.bDeviceSubClass = 0x02;
        g_dev.bDeviceProtocol = 0x01;
    }
    g_dev.bMaxPacketSize0   = CFG_TUD_ENDPOINT0_SIZE;
    g_dev.idVendor          = 0x2E8A;                 /* Raspberry Pi */
    g_dev.idProduct         = (uint16_t)(0xF000 + (uint16_t)p); /* encodes class */
    g_dev.bcdDevice         = 0x0100;
    g_dev.iManufacturer     = 1;
    g_dev.iProduct          = 2;
    g_dev.iSerialNumber     = 3;
    g_dev.bNumConfigurations = 1;
}

static void build_config_for_profile(fuzz_profile_t p) {
    switch (p) {
    case PROF_HID_ACCESS:    memcpy(g_cfg, cfg_hid,       sizeof(cfg_hid));       g_cfg_len = sizeof(cfg_hid); break;
    case PROF_MIDI:          memcpy(g_cfg, cfg_midi,      sizeof(cfg_midi));      g_cfg_len = sizeof(cfg_midi); break;
    case PROF_CDC:           memcpy(g_cfg, cfg_cdc,       sizeof(cfg_cdc));       g_cfg_len = sizeof(cfg_cdc); break;
    case PROF_VENDOR:        memcpy(g_cfg, cfg_vendor,    sizeof(cfg_vendor));    g_cfg_len = sizeof(cfg_vendor); break;
    case PROF_COMPOSITE:     memcpy(g_cfg, cfg_composite, sizeof(cfg_composite)); g_cfg_len = sizeof(cfg_composite); break;
    case PROF_MSC_DESC_ONLY: build_msc_desc_only();   break;
    case PROF_AUDIO_DESC_ONLY: build_audio_desc_only(); break;
    default:                 memcpy(g_cfg, cfg_hid,       sizeof(cfg_hid));       g_cfg_len = sizeof(cfg_hid); break;
    }
}

void usb_fuzz_prepare(const fuzz_case_t *c) {
    g_active_profile = c->profile;

    /* Seed the shared PRNG so descriptor mutation AND later class traffic are
     * deterministic for this case. */
    fuzz_srand(c->seed);

    select_unicode(c->case_id);
    build_device_desc(c->profile);

    /* Zero the whole buffer first: a mutated wTotalLength may legitimately
     * point past the real descriptor, and we want those over-reads to land on
     * zero padding (still inside g_cfg) rather than out of bounds. */
    memset(g_cfg, 0, sizeof(g_cfg));
    build_config_for_profile(c->profile);

    if (c->mutate) {
        mutate_config(c->variant);
    }

    printf("[CASE %lu] profile=%s variant=%s seed=0x%08lx cfg_len=%u pid=0x%04x\n",
           (unsigned long)c->case_id, fuzz_profile_name(c->profile),
           fuzz_variant_name(c->variant), (unsigned long)c->seed,
           (unsigned)g_cfg_len, (unsigned)g_dev.idProduct);
}

/* ---------------------------------------------------------------------------
 * TinyUSB descriptor callbacks
 * ------------------------------------------------------------------------- */
uint8_t const *tud_descriptor_device_cb(void) {
    return (uint8_t const *)&g_dev;
}

uint8_t const *tud_descriptor_configuration_cb(uint8_t index) {
    (void)index;
    return g_cfg;
}

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance) {
    (void)instance;
    return g_hid_report_desc;
}

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void)langid;
    static uint16_t s[64];
    size_t chars;

    if (index == 0) {
        s[1] = 0x0409;     /* en-US */
        chars = 1;
    } else {
        const char *str = (index < 6) ? g_str[index] : NULL;
        if (str == NULL) return NULL;   /* unknown index -> STALL (part of the fuzz) */
        chars = utf8_to_utf16(str, &s[1], 62);
    }

    s[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * chars + 2));
    return s;
}
