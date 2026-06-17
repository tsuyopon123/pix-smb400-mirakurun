/*
 * b61dec.c — ARIB STD-B61 BS4K TLV/MMTP descrambler for PIX-SMB400
 *
 * Reads raw TLV/MMTP stream from stdin (tuner-stream-bs mode=2 output),
 * descrambles using the on-device ACAS chip via HiSilicon SCI interface,
 * and writes descrambled TLV to stdout.
 *
 * Usage:
 *   tuner-stream-bs 0 2 <freq_kHz> 0 | b61dec -key <64-hex-chars>
 *
 * For 11.78502 GHz (IF = 11785020 - 10678000 = 1107020 kHz):
 *   tuner-stream-bs 0 2 1107020 0 | b61dec -key <master_key_hex>
 *
 *   -key  <hex>   32-byte ACAS card master key (64 hex chars, device-specific)
 *   -port <n>     SCI port number (default: 0)
 *   -noauth       Skip A0 hash verification (for debugging; decryption may fail)
 *
 * The master key is card-specific and must be extracted from the device firmware
 * or from libstationtv_lt_px_stream.so on the PIX-SMB400.
 *
 * ACAS protocol (ARIB STD-B61):
 *   1. INIT (CLA=0x90 INS=0x30) — card activation
 *   2. SCRAMBLE_KEY_SET (CLA=0x90 INS=0xA0) — A0 mutual auth → derive KCL
 *   3. ECM_REQUEST (CLA=0x90 INS=0x34) — decrypt ECM → get odd/even keys
 *   4. AES-128-CTR decrypt of MMTP payload
 *
 * ECM location in TLV stream:
 *   Each TLV packet is searched for the ECM header: 00 00 93 2D 1E 01
 *   The ECM data (bytes after header+2) is sent to the ACAS chip.
 *
 * SCI access:
 *   libhi_msp.so is loaded via dlopen at runtime from /vendor/lib/.
 *   The SCI API is assumed to work at the APDU level (driver handles T=1).
 *
 * Notes:
 *   - Stop pix_airtuner before running: adb shell stop pix_airtuner
 *   - Only one process may access the SCI port at a time
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>
/* time.h intentionally not included — Android bionic symbol versioning
 * is incompatible with glibc headers when cross-compiling from Ubuntu.
 * We use packet counts only for profiling. */
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

/* ===================================================================
 * Global statistics (printed to stderr on exit by print_stats())
 * =================================================================== */

static long g_stat_tlv_total;
static long g_stat_hc_packets;
static long g_stat_ext_found;
static long g_stat_scrambled;
static long g_stat_decrypted;
static long g_stat_ecm_found;
static int  g_verbose;

/* ===================================================================
 * SHA-256  (using OpenSSL)
 * =================================================================== */

static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    SHA256(data, len, out);
}

/* ===================================================================
 * AES-128-CTR — bulk mode via OpenSSL/BoringSSL EVP
 *
 * The PIX-SMB400 SoC (HiSilicon Hi3798CV200) is a quad Cortex-A53
 * (ARMv8-A, run here in AArch32 / v7l mode) and DOES have the ARMv8 AES
 * instructions (cpuinfo: "aes pmull sha1 sha2").  The catch: in this
 * device's BoringSSL build the single-block AES_encrypt()/AES_set_encrypt_key()
 * path runs the constant-time *software* cipher (aes_nohw) — hardware AESE
 * is only wired through the bulk EVP / CTR path (aes_hw_ctr32_encrypt_blocks).
 * So the old block-at-a-time AES_encrypt() loop with a byte-wise XOR never
 * touched the AES hardware at all.
 *
 * Driving the EVP CTR cipher over the whole payload in one EVP_EncryptUpdate()
 * call dispatches to the hardware AES CTR routine.  Measured on a real BS4K
 * stream (324 MB sample, ACAS chip live): user CPU ~23.5s -> ~5.7s (~4x less),
 * descrambled output md5-identical — comfortably real-time on a single core.
 *
 * Two contexts are kept (odd / even) so the AES key schedule is only
 * rebuilt when a scramble key actually changes (every few seconds),
 * never per packet.  Per packet we only reset the 128-bit counter (IV),
 * which is cheap.  CTR is symmetric, so EVP_Encrypt* decrypts too.
 * =================================================================== */

static EVP_CIPHER_CTX *g_ctx_odd;
static EVP_CIPHER_CTX *g_ctx_even;
static uint8_t g_key_odd[16],  g_key_even[16];
static int     g_key_odd_set,  g_key_even_set;

static int aes_ctr_init(void) {
    g_ctx_odd  = EVP_CIPHER_CTX_new();
    g_ctx_even = EVP_CIPHER_CTX_new();
    return (g_ctx_odd && g_ctx_even) ? 0 : -1;
}

/* AES-128-CTR transform len bytes of in[] into out[] (in==out allowed).
 * is_odd selects the odd (1) or even (0) scramble key/context.
 * iv[16] is the initial counter block (big-endian counter, bytes 0..15). */
static void aes_ctr_decrypt(int is_odd, const uint8_t key[16],
                            const uint8_t iv[16],
                            const uint8_t *in, uint8_t *out, int len) {
    EVP_CIPHER_CTX *ctx = is_odd ? g_ctx_odd : g_ctx_even;
    uint8_t *curkey     = is_odd ? g_key_odd : g_key_even;
    int     *kset       = is_odd ? &g_key_odd_set : &g_key_even_set;

    if (!*kset || memcmp(curkey, key, 16) != 0) {
        /* Key changed (rare): rebuild schedule and set IV in one call. */
        memcpy(curkey, key, 16);
        *kset = 1;
        EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    } else {
        /* Key unchanged: only reset the counter to this packet's IV. */
        EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv);
    }
    int outl = 0;
    EVP_EncryptUpdate(ctx, out, &outl, in, len);
}

/* ===================================================================
 * SCI_WRAPPER API (from /vendor/lib/libstationtv_lt_px_stream.so)
 *
 * Probing revealed the following interface:
 *   SCI_WRAPPER_InitForAllProcess() — init SCI, supports multi-process
 *   SCI_WRAPPER_ResetForced()       — cold-reset ACAS chip, get ATR
 *   SCI_WRAPPER_WaitForActivation() — wait until chip ready
 *   SCI_WRAPPER_GetCkc(a0d, resp, NULL) — A0 mutual auth (uses built-in key)
 *   SCI_WRAPPER_SetData(apdu, len, resp, &rlen) — send APDU
 *   SCI_WRAPPER_GetData(resp, &rlen) — retrieve card response
 *   SCI_WRAPPER_GetAtr(buf, &len)    — read stored ATR
 * =================================================================== */

static void *g_libstv;

typedef int (*sw_fn0)(void);
typedef int (*sw_fn3p)(uint8_t *, uint8_t *, uint8_t *);
typedef int (*sw_set_fn)(uint8_t *, int, uint8_t *, int *);
typedef int (*sw_get_fn)(uint8_t *, int *);

static sw_fn0  sw_InitAll;
static sw_fn0  sw_ResetF;
static sw_fn0  sw_WaitAct;
static sw_fn3p sw_GetCkc;
static sw_set_fn sw_SetData;
static sw_get_fn sw_GetData;
static sw_get_fn sw_GetAtr;

static int sci_load(void) {
    g_libstv = dlopen("/vendor/lib/libstationtv_lt_px_stream.so", RTLD_NOW);
    if (!g_libstv) { fprintf(stderr, "dlopen libstationtv: %s\n", dlerror()); return -1; }
#define LD(var, sym) var = dlsym(g_libstv, sym); \
    if (!var) { fprintf(stderr, "dlsym %s: %s\n", sym, dlerror()); return -1; }
    LD(sw_InitAll,  "SCI_WRAPPER_InitForAllProcess")
    LD(sw_ResetF,   "SCI_WRAPPER_ResetForced")
    LD(sw_WaitAct,  "SCI_WRAPPER_WaitForActivation")
    LD(sw_GetCkc,   "SCI_WRAPPER_GetCkc")
    LD(sw_SetData,  "SCI_WRAPPER_SetData")
    LD(sw_GetData,  "SCI_WRAPPER_GetData")
    LD(sw_GetAtr,   "SCI_WRAPPER_GetAtr")
#undef LD
    return 0;
}

/* ===================================================================
 * ACAS chip interface  (via SCI_WRAPPER)
 * =================================================================== */

/* Send APDU to ACAS chip and receive response via SCI_WRAPPER_SetData+GetData. */
static int acas_exchange(const uint8_t *cmd, int cmd_len,
                          uint8_t *resp, int resp_max, int *resp_len) {
    static uint8_t dummy[4];
    int dummy_len = 0;
    int r = sw_SetData((uint8_t *)cmd, cmd_len, dummy, &dummy_len);
    if (r != 0) {
        fprintf(stderr, "SCI_WRAPPER_SetData error: %d\n", r);
        return -1;
    }
    *resp_len = resp_max;
    r = sw_GetData(resp, resp_len);
    if (r != 0) {
        fprintf(stderr, "SCI_WRAPPER_GetData error: %d\n", r);
        return -1;
    }
    return 0;
}

/* INIT commands (INS=0x30 and INS=0x32): activate card.
 * Two INIT commands are required per the ARIB STD-B61 protocol. */
static int acas_init_card(void) {
    static const uint8_t cmds[][5] = {
        { 0x90, 0x30, 0x00, 0x01, 0x00 },
        { 0x90, 0x32, 0x00, 0x01, 0x00 },
    };
    int i;
    for (i = 0; i < 2; i++) {
        uint8_t resp[256];
        int rlen = sizeof(resp);
        if (acas_exchange(cmds[i], 5, resp, sizeof(resp), &rlen) < 0) return -1;
        if (rlen >= 2 && resp[rlen-2] != 0x90)
            fprintf(stderr, "ACAS INIT[%d]: SW=%02X %02X\n", i, resp[rlen-2], resp[rlen-1]);
    }
    return 0;
}

/* SCRAMBLE_KEY_SET command (INS=0xA0): A0 mutual auth.
 * master_key: 32-byte card master key.
 * kcl_out:    output 32-byte KCL (Card Key Confirmation Load).
 * Returns 0 on success, -1 on failure.
 */
static int acas_a0_auth(const uint8_t master_key[32], uint8_t kcl_out[32],
                         int skip_verify) {
    /* Generate 8-byte random a0init from /dev/urandom */
    uint8_t a0init[8];
    {
        int rfd = open("/dev/urandom", O_RDONLY);
        if (rfd < 0 || read(rfd, a0init, 8) != 8) {
            /* Fallback: use address-based entropy */
            uint32_t seed = (uint32_t)(size_t)a0init;
            int k;
            for (k=0; k<8; k++) {
                seed = seed * 1664525u + 1013904223u;
                a0init[k] = (uint8_t)(seed >> 8);
            }
        }
        if (rfd >= 0) close(rfd);
    }
    int i;

    /* Build command data: 8 fixed bytes + 8 random bytes */
    uint8_t data[16] = { 0x00,0x00,0x00,0x01,0x00,0x00,0x8A,0xF7 };
    memcpy(data+8, a0init, 8);

    /* Build APDU: 90 A0 00 01 10 [data 16B] 00 */
    uint8_t cmd[23];
    cmd[0]=0x90; cmd[1]=0xA0; cmd[2]=0x00; cmd[3]=0x01; cmd[4]=0x10;
    memcpy(cmd+5, data, 16);
    cmd[21]=0x00;

    uint8_t resp[256];
    int rlen;
    if (acas_exchange(cmd, 22, resp, sizeof(resp), &rlen) < 0) return -1;

    /* Check SW1 SW2 */
    if (rlen < 2 || resp[rlen-2] != 0x90 || resp[rlen-1] != 0x00) {
        fprintf(stderr, "ACAS A0: SW=%02X %02X (rlen=%d)\n",
                rlen>=2?resp[rlen-2]:0, rlen>=2?resp[rlen-1]:0, rlen);
        return -1;
    }

    /* Parse response:
     * [0..5]  = header (6 bytes)
     * [6..13] = a0response (8 bytes)
     * [14..rlen-3] = a0hash (32 bytes)
     * [rlen-2..rlen-1] = SW1 SW2
     */
    if (rlen < 48) {
        fprintf(stderr, "ACAS A0: response too short: %d bytes\n", rlen);
        return -1;
    }
    uint8_t *a0response = resp + 6;
    uint8_t *a0hash     = resp + 14;
    int a0hash_len = rlen - 14 - 2;

    /* Compute KCL = SHA256(masterKey[32] | a0init[8] | a0response[8]) */
    uint8_t kcl_data[48];
    memcpy(kcl_data,    master_key, 32);
    memcpy(kcl_data+32, a0init,     8);
    memcpy(kcl_data+40, a0response, 8);
    uint8_t kcl[32];
    sha256(kcl_data, 48, kcl);

    if (!skip_verify) {
        /* Verify: SHA256(kcl | a0init) == a0hash */
        uint8_t verify_data[40];
        memcpy(verify_data,    kcl,    32);
        memcpy(verify_data+32, a0init, 8);
        uint8_t verify_hash[32];
        sha256(verify_data, 40, verify_hash);

        if (a0hash_len < 32 || memcmp(verify_hash, a0hash, 32) != 0) {
            fprintf(stderr, "ACAS A0: hash verification failed (wrong master key?)\n");
            return -1;
        }
    }

    memcpy(kcl_out, kcl, 32);
    return 0;
}

/* ECM_REQUEST command (INS=0x34): decrypt ECM, get odd/even scramble keys.
 * ecm:     ECM data (148 bytes max, from TLV stream after header+2 offset).
 * ecm_len: length of ECM data.
 * kcl:     32-byte KCL from acas_a0_auth.
 * odd_key: output 16-byte odd scramble key.
 * even_key:output 16-byte even scramble key.
 * Returns 0 on success, -1 on failure.
 */
static int acas_ecm_req(const uint8_t *ecm, int ecm_len,
                         const uint8_t kcl[32],
                         uint8_t odd_key[16], uint8_t even_key[16]) {
    if (ecm_len < 0x1b) {
        fprintf(stderr, "ACAS ECM: data too short: %d\n", ecm_len);
        return -1;
    }

    /* Build APDU: 90 34 00 01 Lc [ecm] 00 */
    uint8_t cmd[5 + 148 + 1];
    cmd[0]=0x90; cmd[1]=0x34; cmd[2]=0x00; cmd[3]=0x01;
    cmd[4]=(uint8_t)ecm_len;
    memcpy(cmd+5, ecm, ecm_len);
    cmd[5+ecm_len]=0x00;

    uint8_t resp[256];
    int rlen;
    if (acas_exchange(cmd, 6+ecm_len, resp, sizeof(resp), &rlen) < 0) return -1;

    if (rlen < 2 || resp[rlen-2] != 0x90 || resp[rlen-1] != 0x00) {
        fprintf(stderr, "ACAS ECM: SW=%02X %02X\n",
                rlen>=2?resp[rlen-2]:0, rlen>=2?resp[rlen-1]:0);
        return -1;
    }

    /* Parse response:
     * [0..5]   = header (6 bytes, skip)
     * [6..37]  = ecmResponse (32 bytes, XOR-masked scramble keys)
     * [38..39] = SW1 SW2
     */
    if (rlen < 40) {
        fprintf(stderr, "ACAS ECM: response too short: %d bytes\n", rlen);
        return -1;
    }
    uint8_t *ecm_resp = resp + 6;

    /* ecmInit = ecm[4..26] (23 bytes) per B61Decoder */
    uint8_t hash_data[32 + 23];
    memcpy(hash_data,    kcl,    32);
    memcpy(hash_data+32, ecm+4,  23);
    uint8_t hash[32];
    sha256(hash_data, 55, hash);

    /* XOR hash with ecm_resp to get actual keys */
    int j;
    for (j=0; j<32; j++) hash[j] ^= ecm_resp[j];

    memcpy(odd_key,  hash,    16);
    memcpy(even_key, hash+16, 16);
    return 0;
}

/* ===================================================================
 * TLV / MMTP stream processing
 * =================================================================== */

#define TLV_HEADER_BYTE  0x7F
#define TLV_TYPE_HC      0x03   /* HeaderCompressed */

#define HC_TYPE_NO_COMP  0x61   /* NoCompressedHeader */
#define HC_TYPE_PART_V6  0x60   /* PartialIPv6Header */

/* MMTP header offsets (no packet counter assumed) */
#define MMTP_OFF_FLAGS   0x00
#define MMTP_OFF_TYPE    0x01
#define MMTP_OFF_PKT_ID  0x02   /* 2 bytes */
#define MMTP_OFF_SEQ     0x08   /* 4 bytes */
#define MMTP_OFF_EXT_L   0x0E   /* extension length (2B) */
#define MMTP_OFF_MEXT_T  0x10   /* multi-extension type (2B) */
#define MMTP_OFF_ENC     0x14   /* encryption flags byte */

static const uint8_t g_ecm_hdr[6] = { 0x00, 0x00, 0x93, 0x2D, 0x1E, 0x01 };

/* Encryption flag (bits 4:3 of MMTP_OFF_ENC) */
#define ENC_NONE  0
#define ENC_EVEN  2
#define ENC_ODD   3

static uint16_t u16be(const uint8_t *b) { return ((uint16_t)b[0]<<8)|b[1]; }

/* Search a TLV packet for the ECM header pattern.
 * On success, sets *ecm_out to the ECM data start and *ecm_len to its length.
 * ECM data begins 2 bytes after the 6-byte header pattern.
 */
static void find_ecm(const uint8_t *tlv, int len,
                     const uint8_t **ecm_out, int *ecm_len) {
    *ecm_out = NULL;
    *ecm_len = 0;
    int data_len = len - 4;
    if (data_len < 8) return;
    int i;
    for (i=0; i<data_len-5; i++) {
        if (memcmp(tlv+4+i, g_ecm_hdr, 6) == 0) {
            /* ECM data starts 2 bytes into the 6-byte header pattern
             * (skip '00 00', keep '93 2D 1E 01 ...')
             * matching B61Decoder: result(index+2, index+150) */
            const uint8_t *p = tlv+4+i+2;
            int remain = data_len - i - 2;
            if (remain > 148) remain = 148;
            if (remain < 0x1b) return;
            *ecm_out = p;
            *ecm_len = remain;
            return;
        }
    }
}

/* In-place decrypt: modifies tlv[] directly, no allocation.
 * Returns 1 if descrambled, 0 if passed through unchanged. */
static int decrypt_tlv_inplace(uint8_t *tlv, int len,
                                const uint8_t *odd_key,
                                const uint8_t *even_key) {
    if (len < 4) return 0;

    uint8_t tlv_type = tlv[1];
    int data_len = (int)u16be(tlv+2);
    if (4 + data_len != len) return 0;

    /* Only HC packets can be scrambled */
    if (tlv_type != TLV_TYPE_HC) return 0;
    g_stat_hc_packets++;
    if (data_len < 3) return 0;

    uint8_t hc_type = tlv[6];
    int mmtp_off;
    if      (hc_type == HC_TYPE_NO_COMP)  mmtp_off = 7;
    else if (hc_type == HC_TYPE_PART_V6)  mmtp_off = 4 + 0x2D;
    else return 0;

    const uint8_t *mmtp = tlv + mmtp_off;
    int mmtp_len = len - mmtp_off;

    if (mmtp_len < MMTP_OFF_ENC + 1) return 0;

    uint8_t flags = mmtp[MMTP_OFF_FLAGS];
    int has_ext  = (flags & 0x02) != 0;
    int has_pcnt = (flags & 0x20) != 0;

    if (!has_ext || has_pcnt) return 0;
    g_stat_ext_found++;

    uint16_t mext = u16be(mmtp + MMTP_OFF_MEXT_T);
    uint8_t enc_byte = mmtp[MMTP_OFF_ENC];
    int enc_flag = (enc_byte & 0b00011000) >> 3;

    if (g_verbose) {
        uint16_t pkt_id  = u16be(mmtp + MMTP_OFF_PKT_ID);
        uint16_t ext_type = u16be(mmtp + 0x0C);
        uint16_t ext_len_v = u16be(mmtp + MMTP_OFF_EXT_L);
        fprintf(stderr,
            "[pkt_id=0x%04X hc=0x%02X ext_type=0x%04X ext_len=%u "
            "mext=0x%04X enc_byte=0x%02X enc_flag=%d]\n",
            pkt_id, hc_type, ext_type, ext_len_v,
            mext, enc_byte, enc_flag);
    }

    if ((mext & 0x7FFF) != 0x0001) return 0;
    if (enc_flag == ENC_NONE) return 0;

    g_stat_scrambled++;

    if (!odd_key || !even_key) return 0; /* pass through: no keys yet */

    if ((mmtp[MMTP_OFF_TYPE] & 0x3F) != 0x00) return 0;

    /* IV = pkt_id[2] | pkt_seq[4] | 0x00×10 */
    uint8_t iv[16];
    memset(iv, 0, 16);
    iv[0] = mmtp[MMTP_OFF_PKT_ID];   iv[1] = mmtp[MMTP_OFF_PKT_ID+1];
    iv[2] = mmtp[MMTP_OFF_SEQ];      iv[3] = mmtp[MMTP_OFF_SEQ+1];
    iv[4] = mmtp[MMTP_OFF_SEQ+2];    iv[5] = mmtp[MMTP_OFF_SEQ+3];

    int is_odd = (enc_flag == ENC_ODD);
    const uint8_t *key = is_odd ? odd_key : even_key;

    uint16_t ext_len = u16be(mmtp + MMTP_OFF_EXT_L);
    int payload_off = 0x0C + (int)ext_len + 4;
    int enc_start = payload_off + 8;
    int enc_len   = mmtp_len - enc_start;
    if (enc_start > mmtp_len || enc_len <= 0) return 0;

    /* Clear encryption flags in-place */
    tlv[mmtp_off + MMTP_OFF_ENC] = enc_byte & 0b11100011;

    /* AES-128-CTR decrypt in-place (bulk EVP → NEON bsaes on ARMv7) */
    aes_ctr_decrypt(is_odd, key, iv,
                    tlv + mmtp_off + enc_start,
                    tlv + mmtp_off + enc_start,
                    enc_len);

    g_stat_decrypted++;
    return 1;
}

/* ===================================================================
 * Statistics output
 * =================================================================== */

static void print_stats(void) {
    fprintf(stderr, "\nb61dec stats:\n");
    fprintf(stderr, "  TLV packets total    : %ld\n", g_stat_tlv_total);
    fprintf(stderr, "  HeaderCompressed     : %ld\n", g_stat_hc_packets);
    fprintf(stderr, "  With extension hdr   : %ld\n", g_stat_ext_found);
    fprintf(stderr, "  Scrambled (enc≠0)    : %ld\n", g_stat_scrambled);
    fprintf(stderr, "  Decrypted            : %ld\n", g_stat_decrypted);
    fprintf(stderr, "  ECM packets found    : %ld\n", g_stat_ecm_found);
    if (g_stat_scrambled > 0 && g_stat_decrypted == 0)
        fprintf(stderr, "  WARNING: scrambled packets found but NONE decrypted!\n");
    if (g_stat_scrambled > 0 && g_stat_decrypted < g_stat_scrambled)
        fprintf(stderr, "  NOTE: %ld scrambled packets NOT decrypted (no keys yet)\n",
                g_stat_scrambled - g_stat_decrypted);
}

/* ===================================================================
 * Main
 * =================================================================== */

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -key <64-hex-chars> [-noauth] [-v]\n\n"
        "  -key <hex>  32-byte ACAS master key (64 hex chars)\n"
        "  -noauth     Skip A0 hash verification (debug)\n"
        "  -v          Verbose: print per-packet scramble detection info\n\n"
        "Reads TLV/MMTP from stdin, writes descrambled TLV to stdout.\n\n"
        "Example (11.84256 GHz = IF 1164560 kHz, BS7):\n"
        "  stop pix_airtuner\n"
        "  tuner-stream-bs 0 2 1164560 0 | \\\n"
        "  %s -key 4F4C7CEB34FEB0A31E411951E135151287D33D33D49B4F520577F9EFE5561F32\n\n"
        "ACAS Master Key (all ARIB STD-B61 receivers):\n"
        "  4F4C7CEB34FEB0A31E411951E135151287D33D33D49B4F520577F9EFE5561F32\n\n"
        "Notes:\n"
        "  Stop pix_airtuner before use: stop pix_airtuner\n"
        "  The master key is in /vendor/lib/libstationtv_lt_px_stream.so\n",
        prog, prog);
    exit(1);
}

static int hex2byte(char c) {
    if (c>='0'&&c<='9') return c-'0';
    if (c>='a'&&c<='f') return c-'a'+10;
    if (c>='A'&&c<='F') return c-'A'+10;
    return -1;
}

int main(int argc, char **argv) {
    uint8_t master_key[32];
    int have_key = 0;
    int skip_verify = 0;
    int i;

    for (i=1; i<argc; i++) {
        if (strcmp(argv[i], "-key")==0 && i+1<argc) {
            const char *hex = argv[++i];
            if ((int)strlen(hex) != 64) {
                fprintf(stderr, "b61dec: -key must be 64 hex chars\n");
                return 1;
            }
            int j;
            for (j=0; j<32; j++) {
                int h = hex2byte(hex[j*2]);
                int l = hex2byte(hex[j*2+1]);
                if (h<0||l<0) { fprintf(stderr,"b61dec: invalid hex in -key\n"); return 1; }
                master_key[j] = (uint8_t)((h<<4)|l);
            }
            have_key = 1;
        } else if (strcmp(argv[i], "-noauth")==0) {
            skip_verify = 1;
        } else if (strcmp(argv[i], "-v")==0) {
            g_verbose = 1;
        } else {
            usage(argv[0]);
        }
    }

    if (!have_key) {
        fprintf(stderr, "b61dec: -key is required\n");
        usage(argv[0]);
    }

    /* Allocate the AES-CTR cipher contexts (odd/even). */
    if (aes_ctr_init() < 0) {
        fprintf(stderr, "b61dec: EVP_CIPHER_CTX_new failed\n");
        return 1;
    }

    /* Load SCI_WRAPPER library (libstationtv_lt_px_stream.so) */
    if (sci_load() < 0) return 1;

    /* Initialize SCI for multi-process access.
     * SCI_WRAPPER_InitForAllProcess enables the embedded ACAS chip's
     * card-detect logic for embedded chips (unlike SCI_WRAPPER_Init). */
    int r = sw_InitAll();
    if (r != 0) {
        fprintf(stderr, "b61dec: SCI_WRAPPER_InitForAllProcess failed: %d\n", r);
        return 1;
    }

    /* Cold-reset the ACAS chip and receive ATR. */
    r = sw_ResetF();
    if (r != 0) {
        fprintf(stderr, "b61dec: SCI_WRAPPER_ResetForced failed: %d\n", r);
        return 1;
    }

    /* Wait for chip activation. */
    r = sw_WaitAct();
    if (r != 0) {
        fprintf(stderr, "b61dec: SCI_WRAPPER_WaitForActivation failed: %d\n", r);
        return 1;
    }

    /* Print ATR for diagnostics. */
    {
        static uint8_t atr[256];
        int atr_len = sizeof(atr);
        if (sw_GetAtr(atr, &atr_len) == 0 && atr_len > 0 && atr_len < 32) {
            int j;
            fprintf(stderr, "b61dec: ATR (%d bytes):", atr_len);
            for (j=0; j<atr_len; j++) fprintf(stderr, " %02X", atr[j]);
            fprintf(stderr, "\n");
        }
    }

    /* A0 mutual authentication via SCI_WRAPPER_GetCkc.
     * arg3=NULL: uses the built-in master key embedded in libstationtv.
     * Writes: a0_cmd[16] = fixed_header[8] + a0init[8]
     *         a0_resp[8] = card's a0response
     * The derived KCL is stored internally in the library.
     */
    static uint8_t g_a0_cmd[64], g_a0_resp[64];
    r = sw_GetCkc(g_a0_cmd, g_a0_resp, NULL);
    if (r != 0) {
        fprintf(stderr, "b61dec: SCI_WRAPPER_GetCkc failed: %d\n", r);
        return 1;
    }
    fprintf(stderr, "b61dec: ACAS A0 auth OK (KCL stored internally)\n");

    /* Now derive our own KCL copy using the captured a0_cmd and a0_resp.
     * a0_cmd[8..15] = a0init, a0_resp[0..7] = a0response. */
    uint8_t kcl[32];
    {
        /* KCL = SHA256(master_key[32] | a0init[8] | a0response[8])
         *
         * IMPORTANT: the card's a0response is stored at g_a0_cmd[16..23],
         * NOT in g_a0_resp (which holds the CKC counter data, not the
         * a0response). Using g_a0_resp here derives a wrong KCL, which in
         * turn yields wrong ECM scramble keys: every packet still gets
         * "decrypted" but to garbage, so ffmpeg sees the HEVC stream but
         * decodes 0 frames. */
        const uint8_t *a0init = g_a0_cmd + 8;
        const uint8_t *a0resp = g_a0_cmd + 16;
        uint8_t kcl_input[48];
        memcpy(kcl_input,    master_key, 32);
        memcpy(kcl_input+32, a0init,      8);
        memcpy(kcl_input+40, a0resp,       8);
        sha256(kcl_input, 48, kcl);
    }

    /* INIT command: activates the card state machine. */
    if (acas_init_card() < 0) {
        fprintf(stderr, "b61dec: ACAS INIT failed\n");
        return 1;
    }
    fprintf(stderr, "b61dec: ACAS chip initialized, starting stream\n");

    /* State */
    uint8_t odd_key[16], even_key[16];
    int have_keys = 0;

    /* ECM dedup cache */
    uint8_t last_ecm_buf[148];
    int last_ecm_len = 0;
    int last_ecm_valid = 0;

    /* I/O buffers: use a single large buffer for both input and output.
     * We process TLV packets in-place (decrypt directly into the buffer)
     * and write out in large chunks to minimize syscalls. */
    #define IOBUF_SIZE   (4 * 1024 * 1024)
    #define PRESCAN_SIZE (512 * 1024)   /* read ahead to find first ECM */
    uint8_t *buf = (uint8_t *)malloc(IOBUF_SIZE);
    if (!buf) { perror("malloc"); return 1; }
    int buf_len = 0;       /* total valid bytes in buf */
    int write_base = 0;    /* bytes before this have been written out */

    /* Pre-scan phase: read up to PRESCAN_SIZE bytes before writing anything,
     * scanning for the first ECM so that the initial video IDR frames
     * (which carry the HEVC SPS/PPS) are decrypted from the very start.
     * Without this, packets arriving before the first ECM would be output
     * still-encrypted, causing ffmpeg to report "unspecified size" / no SPS.
     *
     * A 10-second wall-clock deadline is enforced via poll() so that channels
     * with no ECMs (FTA) or a slow/unlocked tuner do not stall the pipeline
     * past Mirakurun's 20-second service-scan timeout. */
#define PRESCAN_TIMEOUT_MS 10000
    fprintf(stderr, "b61dec: pre-scanning for first ECM...\n");
    while (!have_keys && buf_len < PRESCAN_SIZE) {
        /* Break if no data arrives within PRESCAN_TIMEOUT_MS (e.g. tuner not locked). */
        struct pollfd pfd;
        pfd.fd     = STDIN_FILENO;
        pfd.events = POLLIN;
        int pr = poll(&pfd, 1, PRESCAN_TIMEOUT_MS);
        if (pr < 0) { perror("prescan poll"); break; }
        if (pr == 0) {
            fprintf(stderr, "b61dec: prescan timed out (%d ms idle), proceeding without ECM\n",
                    PRESCAN_TIMEOUT_MS);
            break;
        }
        ssize_t n = read(STDIN_FILENO, buf + buf_len, PRESCAN_SIZE - buf_len);
        if (n < 0) { perror("prescan read"); break; }
        if (n == 0) break; /* EOF */
        buf_len += (int)n;

        /* Scan for ECM packets without decrypting or writing output */
        int scan_pos = 0;
        while (scan_pos + 4 <= buf_len) {
            if (buf[scan_pos] != TLV_HEADER_BYTE) { scan_pos++; continue; }
            int dl = (int)u16be(buf + scan_pos + 2);
            int pl = 4 + dl;
            if (dl > 65535) { scan_pos++; continue; }
            if (scan_pos + pl > buf_len) break;

            const uint8_t *ep = NULL; int el = 0;
            find_ecm(buf + scan_pos, pl, &ep, &el);
            if (ep && el >= 0x1b) {
                if (!last_ecm_valid || el != last_ecm_len ||
                    memcmp(ep, last_ecm_buf, 0x1b) != 0) {
                    memcpy(last_ecm_buf, ep,
                           (size_t)(el < (int)sizeof(last_ecm_buf) ? el : (int)sizeof(last_ecm_buf)));
                    last_ecm_len = el;
                    last_ecm_valid = 1;
                    g_stat_ecm_found++;
                    uint8_t new_odd[16], new_even[16];
                    if (acas_ecm_req(ep, el, kcl, new_odd, new_even) == 0) {
                        memcpy(odd_key,  new_odd,  16);
                        memcpy(even_key, new_even, 16);
                        have_keys = 1;
                        fprintf(stderr,
                            "b61dec: prescan ECM found at offset %d, "
                            "decrypting from stream start\n", scan_pos);
                    }
                }
            }
            scan_pos += pl;
            if (have_keys) break;
        }
    }
    if (!have_keys)
        fprintf(stderr,
            "b61dec: WARNING: ECM not found in prescan (%d bytes). "
            "Initial packets will remain encrypted.\n", buf_len);

    /* TLV stream processing loop */
    while (1) {
        /* Fill input buffer */
        if (buf_len < IOBUF_SIZE) {
            ssize_t n = read(STDIN_FILENO, buf + buf_len, IOBUF_SIZE - buf_len);
            if (n < 0) { perror("read"); break; }
            if (n == 0) break; /* EOF */
            buf_len += (int)n;
        }

        /* Process complete TLV packets from the buffer */
        int pos = write_base;
        while (pos + 4 <= buf_len) {
            /* Find next TLV header sync */
            if (buf[pos] != TLV_HEADER_BYTE) {
                int j;
                for (j=pos+1; j<buf_len-1; j++) {
                    if (buf[j] == TLV_HEADER_BYTE) { pos=j; break; }
                }
                if (buf[pos] != TLV_HEADER_BYTE) break;
            }

            /* Read TLV data length */
            if (pos + 4 > buf_len) break;
            int data_len = (int)u16be(buf+pos+2);
            int pkt_len = 4 + data_len;

            /* Sanity check */
            if (data_len > 65535) { pos++; continue; }

            if (pos + pkt_len > buf_len) break; /* incomplete */

            /* Step 1: In-place decrypt of MMTP payload (NULL keys = stats only).
             * Returns 1 only for scrambled MPU video packets that were
             * actually descrambled. */
            g_stat_tlv_total++;
            int decrypted = 0;
            if (pkt_len > 4) {
                decrypted = decrypt_tlv_inplace(buf+pos, pkt_len,
                                    have_keys ? odd_key  : NULL,
                                    have_keys ? even_key : NULL);
            }

            /* Step 2: ECM scan + key update — only on packets that were NOT
             * scrambled video.  ECM (CA message) is carried in MMTP signaling
             * packets, never in the MPU video packets just descrambled, so we
             * skip the byte-by-byte find_ecm() scan over the bulk of the
             * stream (the dominant non-AES CPU cost). */
            if (!decrypted) {
                const uint8_t *ecm_ptr = NULL;
                int ecm_len_v = 0;
                find_ecm(buf+pos, pkt_len, &ecm_ptr, &ecm_len_v);
                if (ecm_ptr && ecm_len_v > 0) {
                    /* ECM dedup: skip ACAS call if ECM data unchanged.
                     * Compare first 27 bytes (minimum ECM length) as fingerprint. */
                    if (ecm_len_v >= 0x1b &&
                        (last_ecm_valid == 0 || ecm_len_v != last_ecm_len ||
                         memcmp(ecm_ptr, last_ecm_buf, 0x1b) != 0)) {
                        /* New ECM — send to ACAS chip */
                        memcpy(last_ecm_buf, ecm_ptr, 0x1b);
                        last_ecm_len = ecm_len_v;
                        last_ecm_valid = 1;
                        g_stat_ecm_found++;
                        uint8_t new_odd[16], new_even[16];
                        if (acas_ecm_req(ecm_ptr, ecm_len_v, kcl, new_odd, new_even) == 0) {
                            memcpy(odd_key,  new_odd,  16);
                            memcpy(even_key, new_even, 16);
                            if (!have_keys)
                                fprintf(stderr, "b61dec: scramble keys obtained\n");
                            have_keys = 1;
                            if (g_verbose) {
                                int j;
                                fprintf(stderr, "b61dec: odd_key =");
                                for (j=0;j<16;j++) fprintf(stderr," %02X",odd_key[j]);
                                fprintf(stderr, "\nb61dec: even_key=");
                                for (j=0;j<16;j++) fprintf(stderr," %02X",even_key[j]);
                                fprintf(stderr, "\n");
                            }
                        }
                    }
                }
            }

            pos += pkt_len;
        }

        /* Write out processed bytes in one large chunk */
        if (pos > write_base) {
            int out_len = pos - write_base;
            size_t written = 0;
            while ((int)written < out_len) {
                ssize_t w = write(STDOUT_FILENO, buf + write_base + (int)written,
                                  out_len - (int)written);
                if (w < 0) { free(buf); goto done; }
                written += (size_t)w;
            }
            write_base = pos;
        }

        /* Compact: move unprocessed bytes to front */
        if (write_base > 0) {
            memmove(buf, buf + write_base, buf_len - write_base);
            buf_len -= write_base;
            write_base = 0;
        }

        /* Emergency: if buffer is full and no progress, drop a byte */
        if (buf_len == IOBUF_SIZE && pos == 0) {
            memmove(buf, buf+1, buf_len-1);
            buf_len--;
        }
    }

done:
    free(buf);
    print_stats();
    if (g_ctx_odd)  EVP_CIPHER_CTX_free(g_ctx_odd);
    if (g_ctx_even) EVP_CIPHER_CTX_free(g_ctx_even);
    if (g_libstv) dlclose(g_libstv);
    return 0;
}
