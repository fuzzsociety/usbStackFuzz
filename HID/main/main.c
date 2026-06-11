/*
 * ESP32-S3 USB HID Accessibility Fuzzer
 *
 * Defensive lab firmware: enumerates as HID using accessibility-adjacent
 * usage pages. It does not enumerate as a keyboard and does not inject keys.
 *
 * Tested design target: ESP-IDF 5.x + espressif/esp_tinyusb component.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include "esp_log.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "tinyusb.h"
#include "tinyusb_default_config.h"
#include "class/hid/hid_device.h"
#include "driver/gpio.h"

#ifndef FUZZ_SEED
#define FUZZ_SEED 0u
#endif

#ifndef FUZZ_INTERVAL_MS
#define FUZZ_INTERVAL_MS 20u
#endif

#ifndef SEND_POINTER_DELTAS
#define SEND_POINTER_DELTAS 0
#endif

#define APP_BOOT_BUTTON       GPIO_NUM_0
#define HID_EP_IN             0x81
#define HID_EP_SIZE           64
#define HID_POLL_INTERVAL_MS  1

#define REPORT_ID_ASSISTIVE   1
#define REPORT_ID_BRAILLE     2
#define REPORT_ID_VENDOR      3

static const char *TAG = "hid_acc_fuzz";
static bool s_suspended;
static uint32_t s_rng;

/*
 * Report descriptor strategy:
 *
 * 1) Generic Desktop / Assistive Control (Usage 0x10):
 *    - 8 switch/button bits
 *    - optional relative X/Y bytes; disabled by default at runtime
 *
 * 2) Braille Display page (0x41):
 *    - exercises screen-reader / accessibility-adjacent HID parsing paths
 *    - accepts SET_REPORT/GET_REPORT and output-like report shapes
 *
 * 3) Vendor-defined page:
 *    - 63-byte report body for boundary patterns without pretending to be
 *      keyboard/mouse.
 */
static const uint8_t hid_report_descriptor[] = {
    /* Report ID 1: Generic Desktop / Assistive Control */
    0x05, 0x01,                    /* Usage Page (Generic Desktop) */
    0x09, 0x10,                    /* Usage (Assistive Control) */
    0xA1, 0x01,                    /* Collection (Application) */
      0x85, REPORT_ID_ASSISTIVE,   /*   Report ID */

      0x05, 0x09,                  /*   Usage Page (Button) */
      0x19, 0x01,                  /*   Usage Minimum (Button 1) */
      0x29, 0x08,                  /*   Usage Maximum (Button 8) */
      0x15, 0x00,                  /*   Logical Minimum (0) */
      0x25, 0x01,                  /*   Logical Maximum (1) */
      0x75, 0x01,                  /*   Report Size (1) */
      0x95, 0x08,                  /*   Report Count (8) */
      0x81, 0x02,                  /*   Input (Data,Var,Abs) */

      0x05, 0x01,                  /*   Usage Page (Generic Desktop) */
      0x09, 0x30,                  /*   Usage (X) */
      0x09, 0x31,                  /*   Usage (Y) */
      0x15, 0x81,                  /*   Logical Minimum (-127) */
      0x25, 0x7F,                  /*   Logical Maximum (127) */
      0x75, 0x08,                  /*   Report Size (8) */
      0x95, 0x02,                  /*   Report Count (2) */
      0x81, 0x06,                  /*   Input (Data,Var,Rel) */
    0xC0,                          /* End Collection */

    /* Report ID 2: Braille Display page */
    0x06, 0x41, 0x00,              /* Usage Page (Braille Display, 0x41) */
    0x09, 0x01,                    /* Usage (Braille Display) */
    0xA1, 0x01,                    /* Collection (Application) */
      0x85, REPORT_ID_BRAILLE,     /*   Report ID */

      0x09, 0xFA,                  /*   Usage (Router Set 1) */
      0x15, 0x00,                  /*   Logical Minimum (0) */
      0x26, 0xFF, 0x00,            /*   Logical Maximum (255) */
      0x75, 0x08,                  /*   Report Size (8) */
      0x95, 0x10,                  /*   Report Count (16) */
      0x81, 0x00,                  /*   Input (Data,Array,Abs) */

      0x09, 0x05,                  /*   Usage (Number of Braille Cells) */
      0x15, 0x00,                  /*   Logical Minimum (0) */
      0x25, 0x40,                  /*   Logical Maximum (64) */
      0x75, 0x08,                  /*   Report Size (8) */
      0x95, 0x01,                  /*   Report Count (1) */
      0xB1, 0x02,                  /*   Feature (Data,Var,Abs) */

      0x09, 0x03,                  /*   Usage (8 Dot Braille Cell) */
      0x15, 0x00,                  /*   Logical Minimum (0) */
      0x26, 0xFF, 0x00,            /*   Logical Maximum (255) */
      0x75, 0x08,                  /*   Report Size (8) */
      0x95, 0x20,                  /*   Report Count (32) */
      0x91, 0x02,                  /*   Output (Data,Var,Abs) */
    0xC0,                          /* End Collection */

    /* Report ID 3: vendor-defined 63-byte chaos report */
    0x06, 0x00, 0xFF,              /* Usage Page (Vendor Defined 0xFF00) */
    0x09, 0x01,                    /* Usage (Vendor 1) */
    0xA1, 0x01,                    /* Collection (Application) */
      0x85, REPORT_ID_VENDOR,      /*   Report ID */
      0x15, 0x00,                  /*   Logical Minimum (0) */
      0x26, 0xFF, 0x00,            /*   Logical Maximum (255) */
      0x75, 0x08,                  /*   Report Size (8) */
      0x95, 0x3F,                  /*   Report Count (63) */
      0x09, 0x01,                  /*   Usage (Vendor 1) */
      0x81, 0x02,                  /*   Input (Data,Var,Abs) */
      0x09, 0x02,                  /*   Usage (Vendor 2) */
      0x91, 0x02,                  /*   Output (Data,Var,Abs) */
      0x09, 0x03,                  /*   Usage (Vendor 3) */
      0xB1, 0x02,                  /*   Feature (Data,Var,Abs) */
    0xC0                           /* End Collection */
};

#define TUSB_DESC_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_HID_DESC_LEN)

static const tusb_desc_device_t device_descriptor = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,
    .bDeviceClass       = 0x00,
    .bDeviceSubClass    = 0x00,
    .bDeviceProtocol    = 0x00,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor           = 0xCAFE,  /* lab/test VID used by TinyUSB examples; replace for production */
    .idProduct          = 0xF001,
    .bcdDevice          = 0x0100,
    .iManufacturer      = 0x01,
    .iProduct           = 0x02,
    .iSerialNumber      = 0x03,
    .bNumConfigurations = 0x01,
};

static const char *string_descriptor[] = {
    (const char[]){0x09, 0x04},     /* 0: English */
    "FuzzSociety Lab",             /* 1: Manufacturer */
    "USB Accessibility HID Fuzzer",/* 2: Product */
    "S3-HID-FUZZ-0001",            /* 3: Serial */
    "Accessibility HID Surface",   /* 4: HID interface */
};

static const uint8_t configuration_descriptor[] = {
    TUD_CONFIG_DESCRIPTOR(1, 1, 0, TUSB_DESC_TOTAL_LEN,
                          TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, 100),
    TUD_HID_DESCRIPTOR(0, 4, false, sizeof(hid_report_descriptor),
                       HID_EP_IN, HID_EP_SIZE, HID_POLL_INTERVAL_MS),
};

static uint32_t xorshift32(void)
{
    uint32_t x = s_rng;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    s_rng = x ? x : 0xA5A5A5A5u;
    return s_rng;
}

static void fill_fuzz(uint8_t *buf, size_t len)
{
    static const uint8_t interesting[] = {
        0x00, 0x01, 0x02, 0x03, 0x07, 0x08, 0x0f, 0x10,
        0x1f, 0x20, 0x3f, 0x40, 0x7f, 0x80, 0xfe, 0xff
    };

    uint32_t mode = xorshift32() & 7u;
    for (size_t i = 0; i < len; i++) {
        switch (mode) {
        case 0:
            buf[i] = 0x00;
            break;
        case 1:
            buf[i] = 0xff;
            break;
        case 2:
            buf[i] = (uint8_t)i;
            break;
        case 3:
            buf[i] = (uint8_t)(len - i);
            break;
        case 4:
            buf[i] = interesting[xorshift32() % sizeof(interesting)];
            break;
        default:
            buf[i] = (uint8_t)xorshift32();
            break;
        }
    }
}

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance)
{
    (void) instance;
    return hid_report_descriptor;
}

uint16_t tud_hid_get_report_cb(uint8_t instance,
                               uint8_t report_id,
                               hid_report_type_t report_type,
                               uint8_t *buffer,
                               uint16_t reqlen)
{
    (void) instance;
    ESP_LOGI(TAG, "GET_REPORT id=%u type=%u reqlen=%u", report_id, report_type, reqlen);

    uint16_t n = reqlen;
    if (n > 63) {
        n = 63;
    }

    switch (report_id) {
    case REPORT_ID_ASSISTIVE:
        if (n > 3) n = 3;
        break;
    case REPORT_ID_BRAILLE:
        if (report_type == HID_REPORT_TYPE_FEATURE) {
            n = n > 1 ? 1 : n;
        } else if (n > 16) {
            n = 16;
        }
        break;
    case REPORT_ID_VENDOR:
        break;
    default:
        return 0; /* STALL unknown IDs */
    }

    fill_fuzz(buffer, n);
    if (report_id == REPORT_ID_ASSISTIVE && SEND_POINTER_DELTAS == 0) {
        /* Keep X/Y zero unless explicitly enabled at build time. */
        if (n > 1) buffer[1] = 0;
        if (n > 2) buffer[2] = 0;
    }
    return n;
}

void tud_hid_set_report_cb(uint8_t instance,
                           uint8_t report_id,
                           hid_report_type_t report_type,
                           uint8_t const *buffer,
                           uint16_t bufsize)
{
    (void) instance;
    uint8_t b0 = bufsize ? buffer[0] : 0;
    uint8_t b1 = bufsize > 1 ? buffer[1] : 0;
    uint8_t b2 = bufsize > 2 ? buffer[2] : 0;
    uint8_t b3 = bufsize > 3 ? buffer[3] : 0;
    ESP_LOGI(TAG,
             "SET_REPORT id=%u type=%u len=%u head=%02x %02x %02x %02x",
             report_id, report_type, bufsize, b0, b1, b2, b3);
}

void tud_suspend_cb(bool remote_wakeup_en)
{
    s_suspended = true;
    ESP_LOGI(TAG, "USB suspended, remote_wakeup=%u", remote_wakeup_en);
}

void tud_resume_cb(void)
{
    s_suspended = false;
    ESP_LOGI(TAG, "USB resumed");
}

static void send_assistive_report(void)
{
    uint8_t report[3];
    report[0] = (uint8_t)(1u << (xorshift32() & 7u)); /* one switch/button */
#if SEND_POINTER_DELTAS
    report[1] = (int8_t)((xorshift32() % 7) - 3);    /* small dx */
    report[2] = (int8_t)((xorshift32() % 7) - 3);    /* small dy */
#else
    report[1] = 0;
    report[2] = 0;
#endif
    tud_hid_report(REPORT_ID_ASSISTIVE, report, sizeof(report));
}

static void send_braille_report(void)
{
    uint8_t report[16];
    fill_fuzz(report, sizeof(report));
    tud_hid_report(REPORT_ID_BRAILLE, report, sizeof(report));
}

static void send_vendor_report(void)
{
    uint8_t report[63];
    fill_fuzz(report, sizeof(report));
    tud_hid_report(REPORT_ID_VENDOR, report, sizeof(report));
}

static void fuzz_task(void *arg)
{
    (void)arg;
    while (true) {
        if (tud_mounted() && !s_suspended && tud_hid_ready()) {
            switch (xorshift32() % 3u) {
            case 0:
                send_assistive_report();
                break;
            case 1:
                send_braille_report();
                break;
            default:
                send_vendor_report();
                break;
            }
        }
        vTaskDelay(pdMS_TO_TICKS(FUZZ_INTERVAL_MS));
    }
}

void app_main(void)
{
    const gpio_config_t boot_button_config = {
        .pin_bit_mask = BIT64(APP_BOOT_BUTTON),
        .mode = GPIO_MODE_INPUT,
        .intr_type = GPIO_INTR_DISABLE,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&boot_button_config));

    uint32_t seed = FUZZ_SEED ? FUZZ_SEED : esp_random();
    if (gpio_get_level(APP_BOOT_BUTTON) == 0) {
        seed ^= 0xB007B007u;
        ESP_LOGW(TAG, "BOOT held: using alternate seed mix");
    }
    s_rng = seed ? seed : 0x12345678u;

    ESP_LOGI(TAG, "USB Accessibility HID Fuzzer starting");
    ESP_LOGI(TAG, "FUZZ_SEED=0x%08" PRIx32, s_rng);
    ESP_LOGI(TAG, "interval=%u ms, pointer_deltas=%u",
             (unsigned)FUZZ_INTERVAL_MS, (unsigned)SEND_POINTER_DELTAS);

    tinyusb_config_t tusb_cfg = TINYUSB_DEFAULT_CONFIG();
    tusb_cfg.descriptor.device = &device_descriptor;
    tusb_cfg.descriptor.full_speed_config = configuration_descriptor;
    tusb_cfg.descriptor.string = string_descriptor;
    tusb_cfg.descriptor.string_count = sizeof(string_descriptor) / sizeof(string_descriptor[0]);
#if (TUD_OPT_HIGH_SPEED)
    tusb_cfg.descriptor.high_speed_config = configuration_descriptor;
#endif

    ESP_ERROR_CHECK(tinyusb_driver_install(&tusb_cfg));
    ESP_LOGI(TAG, "TinyUSB installed");

    xTaskCreate(fuzz_task, "hid_fuzz", 4096, NULL, 5, NULL);
}
