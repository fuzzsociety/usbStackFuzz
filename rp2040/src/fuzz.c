/*
 * Fuzz core implementation. See fuzz.h for the model.
 */

#include "fuzz.h"

#include <string.h>
#include <stdio.h>

#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "hardware/sync.h"

/* ----------------------------------------------------------------------------
 * PRNG
 * ------------------------------------------------------------------------- */

static uint32_t s_rng = 0x12345678u;

void fuzz_srand(uint32_t seed) {
    s_rng = seed ? seed : 0x12345678u;
}

uint32_t fuzz_rand(void) {
    uint32_t x = s_rng;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    s_rng = x ? x : 0xA5A5A5A5u;
    return s_rng;
}

uint8_t fuzz_rand8(void) {
    return (uint8_t)(fuzz_rand() & 0xffu);
}

void fuzz_fill(uint8_t *buf, size_t len) {
    static const uint8_t interesting[] = {
        0x00, 0x01, 0x02, 0x03, 0x07, 0x08, 0x0f, 0x10,
        0x1f, 0x20, 0x3f, 0x40, 0x7f, 0x80, 0xfe, 0xff
    };
    uint32_t mode = fuzz_rand() & 7u;
    for (size_t i = 0; i < len; i++) {
        switch (mode) {
        case 0: buf[i] = 0x00; break;
        case 1: buf[i] = 0xff; break;
        case 2: buf[i] = (uint8_t)i; break;
        case 3: buf[i] = (uint8_t)(len - i); break;
        case 4: buf[i] = interesting[fuzz_rand() % sizeof(interesting)]; break;
        default: buf[i] = fuzz_rand8(); break;
        }
    }
}

/* ----------------------------------------------------------------------------
 * Flash-backed campaign state
 *
 * The last flash sector holds a small record. We rewrite it twice per case:
 * once before enumeration (active=1, so a crash/power-loss is detectable on the
 * next boot) and once after the dwell completes (active=0, clean). That is two
 * sector erases per case; fine for lab campaigns, but see the README note on
 * flash wear for very long overnight runs.
 * ------------------------------------------------------------------------- */

#define STATE_MAGIC   0x52503455u  /* "RP4U" */
#define STATE_VERSION 1u

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t next_case;     /* case to run on the next clean boot */
    uint32_t active;        /* 1 => a case was in-flight (suspect on reboot) */
    uint32_t active_case;
    uint32_t active_seed;
    uint32_t active_profile;
    uint32_t active_variant;
    uint32_t suspect_count; /* cumulative power-loss/crash suspects observed */
    uint32_t crc;
} campaign_state_t;

#define FLASH_TARGET_OFFSET (PICO_FLASH_SIZE_BYTES - FLASH_SECTOR_SIZE)

static uint32_t crc32_buf(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int k = 0; k < 8; k++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
        }
    }
    return ~crc;
}

static uint32_t state_crc(const campaign_state_t *s) {
    return crc32_buf((const uint8_t *)s, sizeof(*s) - sizeof(uint32_t));
}

static void state_read(campaign_state_t *out) {
    const campaign_state_t *flash =
        (const campaign_state_t *)(XIP_BASE + FLASH_TARGET_OFFSET);
    memcpy(out, flash, sizeof(*out));
    if (out->magic != STATE_MAGIC ||
        out->version != STATE_VERSION ||
        out->crc != state_crc(out)) {
        memset(out, 0, sizeof(*out));
        out->magic = STATE_MAGIC;
        out->version = STATE_VERSION;
        out->next_case = 0;
        out->active = 0;
        out->suspect_count = 0;
    }
}

static void state_write(const campaign_state_t *s) {
    /* Stage into a page-sized, RAM-resident buffer. */
    static uint8_t page[FLASH_PAGE_SIZE];
    campaign_state_t tmp = *s;
    tmp.crc = state_crc(&tmp);
    memset(page, 0xff, sizeof(page));
    memcpy(page, &tmp, sizeof(tmp));

    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(FLASH_TARGET_OFFSET, FLASH_SECTOR_SIZE);
    flash_range_program(FLASH_TARGET_OFFSET, page, FLASH_PAGE_SIZE);
    restore_interrupts(ints);
}

void fuzz_campaign_erase(void) {
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(FLASH_TARGET_OFFSET, FLASH_SECTOR_SIZE);
    restore_interrupts(ints);
}

/* ----------------------------------------------------------------------------
 * Case resolution
 * ------------------------------------------------------------------------- */

static void resolve_case(uint32_t case_id, fuzz_case_t *out) {
    out->case_id = case_id;
    out->seed    = 0xA11D0000u ^ (case_id * 0x9E3779B9u) ^ 0x52503234u; /* "RP24" */
    out->profile = (fuzz_profile_t)(case_id % (uint32_t)PROF_COUNT);

    uint32_t pass = case_id / (uint32_t)PROF_COUNT;
    out->mutate = (pass > 0);

    if (!out->mutate) {
        out->variant = VAR_VALID;
    } else {
        /* Deterministic non-VALID variant from the case seed. */
        uint32_t s = out->seed ^ 0xD15EA5E5u;
        s ^= s << 13; s ^= s >> 17; s ^= s << 5;
        out->variant = (fuzz_variant_t)(1u + (s % (uint32_t)(VAR_COUNT - 1)));
    }
}

void fuzz_campaign_begin(fuzz_case_t *out) {
    campaign_state_t st;
    state_read(&st);

    /* A case that was marked active but never marked clean implies the previous
     * boot crashed the host hard enough to cut our power, hung, or watchdog-
     * reset mid-case: a suspect worth replaying. */
    if (st.active == 1) {
        st.suspect_count++;
        printf("[SUSPECT] previous case did not complete cleanly:\n");
        printf("          case=%lu profile=%s variant=%s seed=0x%08lx (total suspects=%lu)\n",
               (unsigned long)st.active_case,
               fuzz_profile_name((fuzz_profile_t)st.active_profile),
               fuzz_variant_name((fuzz_variant_t)st.active_variant),
               (unsigned long)st.active_seed,
               (unsigned long)st.suspect_count);
        st.active = 0;
        state_write(&st);
    }

#if AUTO_ADVANCE_CASE
    uint32_t case_id = st.next_case;
#else
    uint32_t case_id = CASE_OVERRIDE;
#endif

    resolve_case(case_id, out);

    /* Persist that this case is now in-flight before we expose USB. */
    st.active = 1;
    st.active_case = out->case_id;
    st.active_seed = out->seed;
    st.active_profile = (uint32_t)out->profile;
    st.active_variant = (uint32_t)out->variant;
#if AUTO_ADVANCE_CASE
    st.next_case = case_id + 1u;
#endif
    state_write(&st);
}

void fuzz_campaign_mark_clean(const fuzz_case_t *c) {
    (void)c;
    campaign_state_t st;
    state_read(&st);
    st.active = 0;
    state_write(&st);
}

/* ----------------------------------------------------------------------------
 * Names
 * ------------------------------------------------------------------------- */

const char *fuzz_profile_name(fuzz_profile_t p) {
    switch (p) {
    case PROF_HID_ACCESS:      return "HID-accessibility";
    case PROF_MIDI:            return "MIDI";
    case PROF_CDC:             return "CDC-ACM";
    case PROF_VENDOR:          return "Vendor-bulk";
    case PROF_COMPOSITE:       return "Composite-CDC+HID";
    case PROF_MSC_DESC_ONLY:   return "MSC-desc-only";
    case PROF_AUDIO_DESC_ONLY: return "Audio-desc-only";
    default:                   return "?";
    }
}

const char *fuzz_variant_name(fuzz_variant_t v) {
    switch (v) {
    case VAR_VALID:            return "valid";
    case VAR_BAD_TOTAL_LENGTHS:return "bad-total-lengths";
    case VAR_BAD_BLENGTHS:     return "bad-blengths";
    case VAR_BAD_CLASS_BYTES:  return "bad-class-bytes";
    case VAR_BAD_STRING_INDEX: return "bad-string-index";
    case VAR_BAD_ENDPOINTS:    return "bad-endpoints";
    case VAR_RANDOM_CS_TRAILERS:return "random-cs-trailers";
    case VAR_TRUNCATE_EXTEND:  return "truncate-extend";
    default:                   return "?";
    }
}
