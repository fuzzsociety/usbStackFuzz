/*
 * Descriptor / string fuzzing surface for the RP2040 USB fuzzer.
 */

#ifndef USB_DESCRIPTORS_H_
#define USB_DESCRIPTORS_H_

#include "fuzz.h"

/* Resolve the device descriptor PID, Unicode string set and configuration
 * descriptor bytes for the given case, and seed the shared PRNG from it.
 * Call once before tud_init(). */
void usb_fuzz_prepare(const fuzz_case_t *c);

/* Profile chosen for this boot (used by the class-traffic senders). */
fuzz_profile_t usb_fuzz_active_profile(void);

#endif /* USB_DESCRIPTORS_H_ */
