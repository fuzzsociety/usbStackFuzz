/*
 * RP2040 USB multi-peripheral descriptor/behaviour fuzzer.
 *
 * Lab firmware for Raspberry Pi Pico / RP2040 boards with native USB. It runs a
 * deterministic campaign: each boot picks the next case, exposes one fuzzed USB
 * peripheral (HID, MIDI, CDC, Vendor, a CDC+HID composite, or a descriptor-only
 * MSC/Audio device), dwells while driving light fuzzed class traffic, marks the
 * case clean, and reboots into the next case.
 *
 * Because cases are deterministic, a host crash at a known wall-clock time maps
 * to a small, replayable case range (set AUTO_ADVANCE_CASE 0 + CASE_OVERRIDE).
 *
 * Logs go out over UART0 (GP0 TX / GP1 RX) at 115200, NOT over USB: the native
 * USB port is the surface presented to the target host.
 *
 * Use only on machines you own or are explicitly authorized to test.
 */

#include <stdio.h>

#include "pico/stdlib.h"
#include "hardware/watchdog.h"
#include "tusb.h"

#include "fuzz.h"
#include "usb_descriptors.h"

void usb_fuzz_traffic_tick(void);

#define TRAFFIC_PERIOD_MS 50u

static uint32_t now_ms(void) {
    return to_ms_since_boot(get_absolute_time());
}

/* Jumper CAMPAIGN_RESET_PIN to GND at boot to wipe campaign state and restart
 * the campaign from case 0. */
static void maybe_reset_campaign(void) {
    gpio_init(CAMPAIGN_RESET_PIN);
    gpio_set_dir(CAMPAIGN_RESET_PIN, GPIO_IN);
    gpio_pull_up(CAMPAIGN_RESET_PIN);
    sleep_ms(10);
    if (gpio_get(CAMPAIGN_RESET_PIN) == 0) {
        printf("[RESET] campaign reset pin (GP%d) low -> erasing campaign state\n",
               CAMPAIGN_RESET_PIN);
        fuzz_campaign_erase();
        sleep_ms(50);
        watchdog_reboot(0, 0, 0);
        for (;;) { tight_loop_contents(); }
    }
}

int main(void) {
    stdio_init_all();
    sleep_ms(200);

    printf("\n=== RP2040 USB multi-peripheral fuzzer ===\n");
    printf("Flash size: %u bytes\n", (unsigned)PICO_FLASH_SIZE_BYTES);

    maybe_reset_campaign();

    fuzz_case_t c;
    fuzz_campaign_begin(&c);

    /* Build descriptors/strings and seed the PRNG for this case. */
    usb_fuzz_prepare(&c);

    if (!tusb_init()) {
        printf("[FATAL] tusb_init() failed; rebooting\n");
        sleep_ms(500);
        watchdog_reboot(0, 0, 0);
    }

    const uint32_t dwell = AUTO_ADVANCE_CASE ? CASE_DWELL_MS : REPLAY_DWELL_MS;
    const uint32_t start = now_ms();
    uint32_t last_traffic = start;

    printf("[RUN] dwell=%lu ms (auto_advance=%d)\n",
           (unsigned long)dwell, (int)AUTO_ADVANCE_CASE);

    while ((now_ms() - start) < dwell) {
        tud_task();
        uint32_t n = now_ms();
        if ((n - last_traffic) >= TRAFFIC_PERIOD_MS) {
            last_traffic = n;
            usb_fuzz_traffic_tick();
        }
    }

    /* Survived the dwell: clear the in-flight flag so this is not counted as a
     * suspect on the next boot. Only next_case advancement depends on
     * AUTO_ADVANCE_CASE (handled in fuzz_campaign_begin). */
    fuzz_campaign_mark_clean(&c);
    printf("[CLEAN] case %lu completed; rebooting%s\n",
           (unsigned long)c.case_id,
           AUTO_ADVANCE_CASE ? " to next case" : " (replay)");

    sleep_ms(50);
    watchdog_reboot(0, 0, 0);
    for (;;) { tight_loop_contents(); }
}
