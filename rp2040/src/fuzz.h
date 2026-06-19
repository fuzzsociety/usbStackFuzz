/*
 * Fuzz core for the RP2040 USB multi-peripheral fuzzer.
 *
 * Provides:
 *   - a deterministic xorshift PRNG and "interesting byte" filler,
 *   - a flash-backed deterministic campaign (case N -> reboot -> case N+1),
 *   - power-loss / crash ("suspect") detection across reboots,
 *   - per-case selection of a peripheral profile, seed and descriptor variant.
 *
 * The model mirrors the ESP32-S3 MIDI firmware: given a case id, the firmware
 * always chooses the same profile, seed, variant, Unicode string set and
 * descriptor bytes, so a crash at a known wall-clock time maps to a small,
 * replayable case range.
 */

#ifndef FUZZ_H_
#define FUZZ_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ----- Campaign tunables ----- */

/* Seconds the device stays enumerated per case before advancing.
 * USB enumeration + class binding on some hosts is slow; keep generous. */
#ifndef CASE_DWELL_MS
#define CASE_DWELL_MS        30000u
#endif

/* When replaying (AUTO_ADVANCE_CASE 0), dwell longer on the single case. */
#ifndef REPLAY_DWELL_MS
#define REPLAY_DWELL_MS      90000u
#endif

/* Set to 0 and pick CASE_OVERRIDE to replay one suspect case repeatedly. */
#ifndef AUTO_ADVANCE_CASE
#define AUTO_ADVANCE_CASE    1
#endif

#ifndef CASE_OVERRIDE
#define CASE_OVERRIDE        0u
#endif

/* GPIO pulled low at boot -> erase campaign state and restart from case 0.
 * Wire a button or jumper from this pin to GND. Internal pull-up is enabled. */
#ifndef CAMPAIGN_RESET_PIN
#define CAMPAIGN_RESET_PIN   15
#endif

/* ----- Peripheral profiles rotated across the campaign ----- */
typedef enum {
    PROF_HID_ACCESS = 0,   /* real HID: accessibility / Braille / vendor reports */
    PROF_MIDI,             /* real USB-MIDI: AudioControl + MIDIStreaming + jacks */
    PROF_CDC,              /* real CDC-ACM serial */
    PROF_VENDOR,           /* real vendor-specific bulk interface */
    PROF_COMPOSITE,        /* real composite: CDC + HID behind an IAD */
    PROF_MSC_DESC_ONLY,    /* descriptor-only Mass Storage (BOT/SCSI) bytes */
    PROF_AUDIO_DESC_ONLY,  /* descriptor-only UAC AudioControl/Streaming bytes */
    PROF_COUNT
} fuzz_profile_t;

/* ----- Descriptor variants (how a profile's bytes are mutated) ----- */
typedef enum {
    VAR_VALID = 0,            /* clean baseline, expected to enumerate */
    VAR_BAD_TOTAL_LENGTHS,    /* corrupt wTotalLength / class total length fields */
    VAR_BAD_BLENGTHS,         /* corrupt a random bLength */
    VAR_BAD_CLASS_BYTES,      /* flip interface class/subclass/protocol */
    VAR_BAD_STRING_INDEX,     /* point string indices at out-of-range entries */
    VAR_BAD_ENDPOINTS,        /* corrupt endpoint address / attributes / mps */
    VAR_RANDOM_CS_TRAILERS,   /* append junk class-specific descriptors */
    VAR_TRUNCATE_EXTEND,      /* report a length longer/shorter than real bytes */
    VAR_COUNT
} fuzz_variant_t;

/* Resolved state for the current boot. */
typedef struct {
    uint32_t case_id;
    uint32_t seed;
    fuzz_profile_t profile;
    fuzz_variant_t variant;
    bool      mutate;          /* false on the first clean pass over all profiles */
} fuzz_case_t;

/* ----- PRNG ----- */
void     fuzz_srand(uint32_t seed);     /* seed the shared stream */
uint32_t fuzz_rand(void);               /* xorshift32 */
uint8_t  fuzz_rand8(void);
/* Fill buf with a deterministic pattern (zeros/ones/ramp/interesting/random). */
void     fuzz_fill(uint8_t *buf, size_t len);

/* ----- Campaign ----- */

/* Read persisted state, detect a power-loss/crash suspect from the previous
 * case, then resolve the case to run this boot. Returns it in *out. */
void fuzz_campaign_begin(fuzz_case_t *out);

/* Mark the resolved case clean (survived its full dwell) and persist progress
 * so the next boot advances. Call right before rebooting. */
void fuzz_campaign_mark_clean(const fuzz_case_t *c);

/* Erase all campaign state (used by the reset-pin gesture). */
void fuzz_campaign_erase(void);

const char *fuzz_profile_name(fuzz_profile_t p);
const char *fuzz_variant_name(fuzz_variant_t v);

#endif /* FUZZ_H_ */
