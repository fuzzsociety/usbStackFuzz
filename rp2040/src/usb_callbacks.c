/*
 * Class-level callbacks and post-enumeration traffic.
 *
 * After a case enumerates, the firmware drives light, fuzzed class traffic so
 * the host exercises class drivers (not just descriptor parsing): HID reports
 * and GET/SET_REPORT control transfers, USB-MIDI event packets, CDC bytes, and
 * vendor bulk writes. Only the active profile's traffic actually runs.
 */

#include <stdio.h>
#include <string.h>

#include "tusb.h"
#include "fuzz.h"
#include "usb_descriptors.h"

#define REPORT_ID_ASSISTIVE 1
#define REPORT_ID_BRAILLE   2
#define REPORT_ID_VENDOR    3

/* Keep relative pointer deltas off by default; this is not a mouse injector. */
#ifndef SEND_POINTER_DELTAS
#define SEND_POINTER_DELTAS 0
#endif

/* ---------------------------------------------------------------------------
 * HID class callbacks (required whenever CFG_TUD_HID is enabled)
 * ------------------------------------------------------------------------- */
uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id,
                               hid_report_type_t report_type,
                               uint8_t *buffer, uint16_t reqlen) {
    (void)instance;
    printf("[HID] GET_REPORT id=%u type=%u reqlen=%u\n", report_id, report_type, reqlen);

    uint16_t n = reqlen > 63 ? 63 : reqlen;
    switch (report_id) {
    case REPORT_ID_ASSISTIVE: if (n > 3) n = 3; break;
    case REPORT_ID_BRAILLE:
        if (report_type == HID_REPORT_TYPE_FEATURE) n = (n > 1) ? 1 : n;
        else if (n > 16) n = 16;
        break;
    case REPORT_ID_VENDOR: break;
    default: return 0; /* STALL unknown IDs */
    }

    fuzz_fill(buffer, n);
    if (report_id == REPORT_ID_ASSISTIVE && SEND_POINTER_DELTAS == 0) {
        if (n > 1) buffer[1] = 0;
        if (n > 2) buffer[2] = 0;
    }
    return n;
}

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id,
                           hid_report_type_t report_type,
                           uint8_t const *buffer, uint16_t bufsize) {
    (void)instance;
    uint8_t b0 = bufsize ? buffer[0] : 0;
    uint8_t b1 = bufsize > 1 ? buffer[1] : 0;
    printf("[HID] SET_REPORT id=%u type=%u len=%u head=%02x %02x\n",
           report_id, report_type, bufsize, b0, b1);
}

/* ---------------------------------------------------------------------------
 * Traffic senders
 * ------------------------------------------------------------------------- */
static void send_hid(void) {
    switch (fuzz_rand() % 3u) {
    case 0: {
        uint8_t r[3];
        r[0] = (uint8_t)(1u << (fuzz_rand() & 7u)); /* one switch/button */
        r[1] = 0;
        r[2] = 0;
        tud_hid_report(REPORT_ID_ASSISTIVE, r, sizeof(r));
        break;
    }
    case 1: {
        uint8_t r[16];
        fuzz_fill(r, sizeof(r));
        tud_hid_report(REPORT_ID_BRAILLE, r, sizeof(r));
        break;
    }
    default: {
        uint8_t r[63];
        fuzz_fill(r, sizeof(r));
        tud_hid_report(REPORT_ID_VENDOR, r, sizeof(r));
        break;
    }
    }
}

static void send_midi(void) {
    uint8_t pkt[4];
    switch (fuzz_rand() % 8u) {
    case 0: pkt[0] = 0x09; pkt[1] = 0x90; pkt[2] = fuzz_rand8() & 0x7f; pkt[3] = 0x40; break; /* note on  */
    case 1: pkt[0] = 0x08; pkt[1] = 0x80; pkt[2] = fuzz_rand8() & 0x7f; pkt[3] = 0x00; break; /* note off */
    case 2: pkt[0] = 0x0B; pkt[1] = 0xB0; pkt[2] = fuzz_rand8() & 0x7f; pkt[3] = fuzz_rand8() & 0x7f; break; /* CC */
    case 3: pkt[0] = 0x0C; pkt[1] = 0xC0; pkt[2] = fuzz_rand8() & 0x7f; pkt[3] = fuzz_rand8(); break; /* prog change */
    case 4: pkt[0] = 0x04; pkt[1] = 0xF0; pkt[2] = fuzz_rand8(); pkt[3] = fuzz_rand8(); break; /* sysex start */
    case 5: pkt[0] = 0x07; pkt[1] = fuzz_rand8(); pkt[2] = fuzz_rand8(); pkt[3] = 0xF7; break; /* sysex end */
    case 6: pkt[0] = fuzz_rand8() & 0x0f; pkt[1] = fuzz_rand8(); pkt[2] = fuzz_rand8(); pkt[3] = fuzz_rand8(); break; /* CIN/status mismatch */
    default:
        pkt[0] = (uint8_t)(((fuzz_rand() & 0x0f) << 4) | (fuzz_rand() & 0x0f));
        pkt[1] = fuzz_rand8(); pkt[2] = fuzz_rand8(); pkt[3] = fuzz_rand8(); break; /* cable-number fuzz */
    }
    tud_midi_packet_write(pkt);
}

static void send_cdc(void) {
    uint8_t buf[32];
    uint16_t n = (uint16_t)(1 + (fuzz_rand() % sizeof(buf)));
    fuzz_fill(buf, n);
    if (tud_cdc_write_available() >= n) {
        tud_cdc_write(buf, n);
        tud_cdc_write_flush();
    }
}

static void send_vendor(void) {
    uint8_t buf[32];
    uint16_t n = (uint16_t)(1 + (fuzz_rand() % sizeof(buf)));
    fuzz_fill(buf, n);
    if (tud_vendor_write_available() >= n) {
        tud_vendor_write(buf, n);
        tud_vendor_write_flush();
    }
}

/* Called periodically from the main dwell loop. */
void usb_fuzz_traffic_tick(void) {
    if (!tud_mounted()) return;
    fuzz_profile_t p = usb_fuzz_active_profile();

    if ((p == PROF_HID_ACCESS || p == PROF_COMPOSITE) && tud_hid_ready()) {
        send_hid();
    }
    if (p == PROF_MIDI && tud_midi_mounted()) {
        send_midi();
    }
    if ((p == PROF_CDC || p == PROF_COMPOSITE) && tud_cdc_connected()) {
        send_cdc();
    }
    if (p == PROF_VENDOR) {
        send_vendor();
    }
}
