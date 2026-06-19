/*
 * TinyUSB configuration for the RP2040 USB multi-peripheral fuzzer.
 *
 * Several device classes are compiled in so a single firmware image can
 * enumerate as different peripheral types across a deterministic campaign.
 * MSC and Audio drivers are deliberately left OFF: those profiles are
 * descriptor-only (they exercise the host's configuration-descriptor parser
 * during GET_DESCRIPTOR; the device is not expected to fully configure them).
 */

#ifndef _TUSB_CONFIG_H_
#define _TUSB_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

/* ------------- Board / MCU ------------- */
#ifndef CFG_TUSB_MCU
#define CFG_TUSB_MCU            OPT_MCU_RP2040
#endif

#define CFG_TUSB_OS             OPT_OS_PICO

#ifndef CFG_TUSB_DEBUG
#define CFG_TUSB_DEBUG          0
#endif

/* RP2040 native USB is full-speed only. */
#define CFG_TUD_ENABLED         1
#define CFG_TUD_MAX_SPEED       OPT_MODE_FULL_SPEED

#ifndef CFG_TUSB_MEM_SECTION
#define CFG_TUSB_MEM_SECTION
#endif

#ifndef CFG_TUSB_MEM_ALIGN
#define CFG_TUSB_MEM_ALIGN      __attribute__ ((aligned(4)))
#endif

/* ------------- Endpoint 0 ------------- */
#define CFG_TUD_ENDPOINT0_SIZE  64

/* ------------- Device class drivers ------------- */
/* Only one profile is active per boot, but all "real" drivers are compiled in
 * so the campaign can rotate between them without reflashing. */
#define CFG_TUD_HID             1
#define CFG_TUD_CDC             1
#define CFG_TUD_MIDI            1
#define CFG_TUD_VENDOR          1
#define CFG_TUD_MSC             0   /* descriptor-only profile */
#define CFG_TUD_AUDIO           0   /* descriptor-only profile */

/* ------------- Class buffer sizes ------------- */
#define CFG_TUD_HID_EP_BUFSIZE  64

#define CFG_TUD_CDC_RX_BUFSIZE  64
#define CFG_TUD_CDC_TX_BUFSIZE  64

#define CFG_TUD_MIDI_RX_BUFSIZE 64
#define CFG_TUD_MIDI_TX_BUFSIZE 64

#define CFG_TUD_VENDOR_RX_BUFSIZE 64
#define CFG_TUD_VENDOR_TX_BUFSIZE 64

#ifdef __cplusplus
}
#endif

#endif /* _TUSB_CONFIG_H_ */
