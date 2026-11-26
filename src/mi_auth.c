/*
 * mi_auth.c
 * MiHome app connection support (protocol recovered from the original MJWSD06MMC firmware 2.1.1_0009):
 *
 *  - Service 0xFE95: 0x0004 version, 0x0010 auth (cmd/status), 0x0019 framed transfer.
 *  - Login (device already bound in MiHome, token kept in the Mi key record 0x10):
 *      app -> 0x0010: 0x24 (login)
 *      app -> 0x0019: type 0x0B, app_rand[16]
 *      dev: K = HKDF-SHA256(ikm = token[12], salt = app_rand|dev_rand, info = "mible-login-info")
 *           dev_key = K[0..15], app_key = K[16..31]
 *      dev -> 0x0019: type 0x0D, dev_rand[16]
 *      dev -> 0x0019: type 0x0C, HMAC-SHA256(dev_key, dev_rand|app_rand)
 *      app -> 0x0019: type 0x0A, HMAC-SHA256(app_key, app_rand|dev_rand)
 *      dev -> 0x0010: 0x21 (ok) / 0x23 (error)
 *  - Framed transfer on 0x0019:
 *      header  00 00 00 <type> <frames lo> <frames hi>, receiver answers 00 00 01 01 (ready)
 *      frames  <idx lo> <idx hi> <data...> (idx = 1..frames),  receiver answers 00 00 01 00 (ok)
 *      short   00 00 02 <type> <data...> (single packet)
 *  - Service ebe0ccb0: time, temperature unit, current temp/humi/voltage, battery.
 */
#include "tl_common.h"
#if USE_MI_AUTH
#include "stack/ble/ble.h"
#include "ble.h"
#include "app.h"
#include "lcd.h"
#include "flash_eep.h"
#include "cmd_parser.h"
#if (DEV_SERVICES & SERVICE_HISTORY) || USE_MI_TIME_SAVE
#include "drivers.h"
#endif
#if (DEV_SERVICES & SERVICE_HISTORY)
#include "logger.h"
#endif
#if (DEV_SERVICES & SERVICE_HARD_CLOCK)
#include "rtc.h"
#endif
#include "mi_auth.h"

#define MI_FRAME_DATA_SIZE	18 // (ATT_MTU 23) - 3 - 2

#if (DEV_SERVICES & SERVICE_TIME_ADJUST)
extern u32 utc_set_time_sec; // cmd_parser.c
#endif

/* --- GATT values --- */
#if (DEVICE_TYPE == DEVICE_LYWSD02MMC)
const u8 mi_version_str[10] = {'2','.','0','.','1','_','0','0','2','1'};
#else
const u8 mi_version_str[10] = {'2','.','1','.','1','_','0','0','0','9'};
#endif
const u8 mi_wo_val[20] = {0};
RAM u16 mi_auth_ccc;
RAM u16 mi_std_ccc;
RAM u8 mi_th_val[5];
RAM u8 mi_tunit_val;
RAM u16 mi_th_ccc;
#if (DEV_SERVICES & SERVICE_HARD_CLOCK)
RAM u8 mi_time_val[7];
RAM s8 mi_tz[2]; // [0] = timezone hour (-24..24), [1] = 15-min quarter (-4..4)

s32 mi_tz_offset_sec(void) {
	return ((s32)mi_tz[0] * 60 + (s32)mi_tz[1] * 15) * 60;
}

/* hour -24..24, quarter -4..4 -> as the original firmware stores it: sign, hours (mod 24) and
 * quarters of the absolute offset (+5 h -2 q -> +4:30, +24 h -> 0); returns 0 if out of range */
static int mi_tz_norm(s8 *tz) {
	if (tz[0] < -24 || tz[0] > 24 || tz[1] < -4 || tz[1] > 4)
		return 0;
	s32 m = (s32)tz[0] * 60 + (s32)tz[1] * 15;
	u32 a = (m < 0) ? -m : m;
	tz[0] = (s8)((a / 60) % 24);
	tz[1] = (s8)((a % 60) / 15);
	if (m < 0) {
		tz[0] = -tz[0];
		tz[1] = -tz[1];
	}
	return 1;
}

int mi_time_read(void * p) {
	(void) p;
	memcpy(mi_time_val, &wrk.utc_time_sec, 4);
	mi_time_val[4] = (u8)mi_tz[0];
	mi_time_val[5] = (u8)mi_tz[1];
	mi_time_val[6] = cfg.flg.time_am_pm ? 0xAA : 0;
	return 0;
}
#endif

/* --- login state --- */
enum {
	MI_LINK_IDLE = 0,
	MI_LINK_RX,			// waiting for header/frames from app
	MI_LINK_TX_RDY,		// header sent, waiting app "ready"
	MI_LINK_TX_OK		// frames sent, waiting app "ok"
};

enum {
	MI_STEP_NONE = 0,
	MI_STEP_APP_RAND,	// wait app random (type 0x0B)
	MI_STEP_DEV_RAND,	// send dev random (type 0x0D)
	MI_STEP_DEV_INFO,	// send dev confirm (type 0x0C)
	MI_STEP_APP_INFO,	// wait app confirm (type 0x0A)
	MI_STEP_LOGGED
};

#define MI_TYPE_APP_RAND	0x0B
#define MI_TYPE_DEV_RAND	0x0D
#define MI_TYPE_DEV_INFO	0x0C
#define MI_TYPE_APP_INFO	0x0A

typedef struct {
	u8 step;
	u8 link;
	u8 type;		// frame type expected / transmitted
	u8 frames;		// number of frames
	u8 stride;		// rx frame payload size
	u8 len;			// payload length
	u8 buf[32];		// rx/tx payload
	u8 rnd[32];		// app_rand[16] | dev_rand[16]
	u8 key[32];		// dev_key[16] | app_key[16]
} mi_auth_t;

RAM mi_auth_t mi_auth;

static const u8 mi_login_info[16] = {'m','i','b','l','e','-','l','o','g','i','n','-','i','n','f','o'};
static const u8 mi_rcv_rdy[4] = {0, 0, 1, 1};
static const u8 mi_rcv_ok[4] = {0, 0, 1, 0};

/* ---------------------------------------------------------------------------------------------
 *  SHA-256 / HMAC-SHA256 (compact, no packed structs: state kept in aligned locals)
 * -------------------------------------------------------------------------------------------*/
static const u32 sha_k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(u32 *h, const u8 *p) {
	u32 w[64];
	u32 a, b, c, d, e, f, g, hh, t1, t2;
	int i;
	for (i = 0; i < 16; i++, p += 4)
		w[i] = ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
	for (; i < 64; i++) {
		u32 s0 = ROR32(w[i-15], 7) ^ ROR32(w[i-15], 18) ^ (w[i-15] >> 3);
		u32 s1 = ROR32(w[i-2], 17) ^ ROR32(w[i-2], 19) ^ (w[i-2] >> 10);
		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}
	a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];
	for (i = 0; i < 64; i++) {
		t1 = hh + (ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25)) + ((e & f) ^ (~e & g)) + sha_k[i] + w[i];
		t2 = (ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
		hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	}
	h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void sha256_init(u32 *h) {
	h[0] = 0x6a09e667; h[1] = 0xbb67ae85; h[2] = 0x3c6ef372; h[3] = 0xa54ff53a;
	h[4] = 0x510e527f; h[5] = 0x9b05688c; h[6] = 0x1f83d9ab; h[7] = 0x5be0cd19;
}

/* cnt[0] = total length; buf = 64-byte block buffer */
static void sha256_update(u32 *h, u8 *buf, u32 *cnt, const u8 *data, u32 len) {
	while (len--) {
		buf[cnt[0] & 63] = *data++;
		cnt[0]++;
		if ((cnt[0] & 63) == 0)
			sha256_block(h, buf);
	}
}

static void sha256_final(u32 *h, u8 *buf, u32 *cnt, u8 *out) {
	u32 bits = cnt[0] << 3;
	u32 i = cnt[0] & 63;
	int k;
	buf[i++] = 0x80;
	if (i > 56) {
		while (i < 64) buf[i++] = 0;
		sha256_block(h, buf);
		i = 0;
	}
	while (i < 60) buf[i++] = 0;
	buf[60] = bits >> 24; buf[61] = bits >> 16; buf[62] = bits >> 8; buf[63] = bits;
	sha256_block(h, buf);
	for (k = 0; k < 8; k++) {
		*out++ = h[k] >> 24; *out++ = h[k] >> 16; *out++ = h[k] >> 8; *out++ = h[k];
	}
}

/* HMAC-SHA256, key <= 64 bytes, message = m1 | m2 */
static void hmac_sha256(const u8 *key, u32 klen, const u8 *m1, u32 l1, const u8 *m2, u32 l2, u8 *out) {
	u32 h[8];
	u32 cnt[1];
	u8 buf[64];
	u8 pad[64];
	u8 ih[32];
	int i;
	for (i = 0; i < 64; i++)
		pad[i] = ((u32)i < klen ? key[i] : 0) ^ 0x36;
	sha256_init(h); cnt[0] = 0;
	sha256_update(h, buf, cnt, pad, 64);
	sha256_update(h, buf, cnt, m1, l1);
	if (l2)
		sha256_update(h, buf, cnt, m2, l2);
	sha256_final(h, buf, cnt, ih);
	for (i = 0; i < 64; i++)
		pad[i] ^= 0x36 ^ 0x5c;
	sha256_init(h); cnt[0] = 0;
	sha256_update(h, buf, cnt, pad, 64);
	sha256_update(h, buf, cnt, ih, 32);
	sha256_final(h, buf, cnt, out);
}

/* ---------------------------------------------------------------------------------------------
 *  Notify helpers
 * -------------------------------------------------------------------------------------------*/
static void mi_auth_status(u8 code) {
	u8 v[MI_AUTH_VAL_LEN] = {code, 0, 0, 0};
	bls_att_pushNotifyData(Mi_AUTH_DP_H, v, sizeof(v));
}

static void mi_std_notify(const u8 *p, int len) {
	bls_att_pushNotifyData(Mi_STD_DP_H, (u8 *)p, len);
}

static void mi_rx_start(u8 type) {
	mi_auth.link = MI_LINK_RX;
	mi_auth.type = type;
	mi_auth.frames = 0;
	mi_auth.stride = 0;
	mi_auth.len = 0;
}

static void mi_tx_start(u8 type, u8 len) {
	u8 hdr[6];
	mi_auth.type = type;
	mi_auth.len = len;
	mi_auth.frames = (len + MI_FRAME_DATA_SIZE - 1) / MI_FRAME_DATA_SIZE;
	mi_auth.link = MI_LINK_TX_RDY;
	hdr[0] = 0; hdr[1] = 0; hdr[2] = 0; hdr[3] = type;
	hdr[4] = mi_auth.frames; hdr[5] = 0;
	mi_std_notify(hdr, sizeof(hdr));
}

static void mi_tx_frames(void) {
	u8 pkt[2 + MI_FRAME_DATA_SIZE];
	u8 i, off = 0, n;
	for (i = 1; i <= mi_auth.frames; i++) {
		n = mi_auth.len - off;
		if (n > MI_FRAME_DATA_SIZE)
			n = MI_FRAME_DATA_SIZE;
		pkt[0] = i;
		pkt[1] = 0;
		memcpy(&pkt[2], &mi_auth.buf[off], n);
		mi_std_notify(pkt, n + 2);
		off += n;
	}
	mi_auth.link = MI_LINK_TX_OK;
}

static void mi_login_fail(u8 code) {
	memset(&mi_auth, 0, sizeof(mi_auth));
	mi_auth_status(code);
}

/* token = Mi key record 0x10 (token[12] + bindkey[16]) written by the original firmware */
static int mi_get_token(u8 *token) {
	if (find_mi_keys(MI_KEYTBIND_ID, 1) && keybuf.klen >= 12) {
		memcpy(token, keybuf.data, 12);
		return 1;
	}
	return 0;
}

/* complete message received from app */
static void mi_rx_done(void) {
	u8 tmp[32];
	mi_auth.link = MI_LINK_IDLE;
	if (mi_auth.step == MI_STEP_APP_RAND && mi_auth.type == MI_TYPE_APP_RAND && mi_auth.len >= 16) {
		u8 token[12];
		if (!mi_get_token(token)) {
			mi_login_fail(MI_AUTH_NOT_REG);
			return;
		}
		memcpy(mi_auth.rnd, mi_auth.buf, 16);
		generateRandomNum(16, &mi_auth.rnd[16]);
		// HKDF-SHA256: PRK = HMAC(salt = app_rand|dev_rand, token); T1 = HMAC(PRK, info | 0x01)
		hmac_sha256(mi_auth.rnd, 32, token, sizeof(token), NULL, 0, tmp);
		mi_auth.buf[0] = 1;
		hmac_sha256(tmp, 32, mi_login_info, sizeof(mi_login_info), mi_auth.buf, 1, mi_auth.key);
		memset(token, 0, sizeof(token));
		// send dev_rand
		memcpy(mi_auth.buf, &mi_auth.rnd[16], 16);
		mi_auth.step = MI_STEP_DEV_RAND;
		mi_tx_start(MI_TYPE_DEV_RAND, 16);
	} else if (mi_auth.step == MI_STEP_APP_INFO && mi_auth.type == MI_TYPE_APP_INFO && mi_auth.len >= 32) {
		// expected = HMAC(app_key, app_rand | dev_rand)
		hmac_sha256(&mi_auth.key[16], 16, mi_auth.rnd, 32, NULL, 0, tmp);
		if (memcmp(tmp, mi_auth.buf, 32) == 0) {
			memset(&mi_auth, 0, sizeof(mi_auth));
			mi_auth.step = MI_STEP_LOGGED;
			mi_auth_status(MI_AUTH_LOGIN_OK);
		} else
			mi_login_fail(MI_AUTH_LOGIN_ERR);
	} else
		mi_login_fail(MI_AUTH_LOGIN_ERR);
}

/* our message acknowledged by app */
static void mi_tx_done(void) {
	mi_auth.link = MI_LINK_IDLE;
	if (mi_auth.step == MI_STEP_DEV_RAND) {
		// dev_info = HMAC(dev_key, dev_rand | app_rand)
		hmac_sha256(mi_auth.key, 16, &mi_auth.rnd[16], 16, mi_auth.rnd, 16, mi_auth.buf);
		mi_auth.step = MI_STEP_DEV_INFO;
		mi_tx_start(MI_TYPE_DEV_INFO, 32);
	} else if (mi_auth.step == MI_STEP_DEV_INFO) {
		mi_auth.step = MI_STEP_APP_INFO;
		mi_rx_start(MI_TYPE_APP_INFO);
	}
}

/* ---------------------------------------------------------------------------------------------
 *  GATT callbacks
 * -------------------------------------------------------------------------------------------*/
int mi_auth_write(void * p) {
	rf_packet_att_data_t *req = (rf_packet_att_data_t*) p;
	u32 len = req->l2cap - 3;
	if (len && req->dat[0] == MI_AUTH_CMD_LOGIN) {
		memset(&mi_auth, 0, sizeof(mi_auth));
		mi_auth.step = MI_STEP_APP_RAND;
		mi_rx_start(MI_TYPE_APP_RAND);
	}
	return 0;
}

int mi_std_write(void * p) {
	rf_packet_att_data_t *req = (rf_packet_att_data_t*) p;
	u32 len = req->l2cap - 3;
	u8 *d = req->dat;
	u16 idx;
	if (len < 2 || len > 20)
		return 0;
	idx = d[0] | (d[1] << 8);
	if (idx == 0) {
		if (len < 4)
			return 0;
		if (d[2] == 0x01) { // ack from app
			if (d[3] == 0x01 && mi_auth.link == MI_LINK_TX_RDY)
				mi_tx_frames();
			else if (d[3] == 0x00 && mi_auth.link == MI_LINK_TX_OK)
				mi_tx_done();
			else if (d[3] == 0x05 && mi_auth.link == MI_LINK_TX_OK)
				mi_tx_frames(); // resend request
		} else if (mi_auth.link == MI_LINK_RX && d[3] == mi_auth.type) {
			if (d[2] == 0x00 && len >= 6) { // header
				mi_auth.frames = d[4];
				mi_auth.stride = 0;
				mi_auth.len = 0;
				mi_std_notify(mi_rcv_rdy, sizeof(mi_rcv_rdy));
			} else if (d[2] == 0x02) { // single packet
				len -= 4;
				if (len > sizeof(mi_auth.buf))
					len = sizeof(mi_auth.buf);
				memcpy(mi_auth.buf, &d[4], len);
				mi_auth.len = len;
				mi_std_notify(mi_rcv_ok, sizeof(mi_rcv_ok));
				mi_rx_done();
			}
		}
		return 0;
	}
	if (mi_auth.link == MI_LINK_RX && mi_auth.frames && idx <= mi_auth.frames) {
		u32 n = len - 2, off;
		if (idx == 1)
			mi_auth.stride = n;
		off = (idx - 1) * mi_auth.stride;
		if (off + n <= sizeof(mi_auth.buf)) {
			memcpy(&mi_auth.buf[off], &d[2], n);
			if (off + n > mi_auth.len)
				mi_auth.len = off + n;
		}
		if (idx == mi_auth.frames) {
			mi_std_notify(mi_rcv_ok, sizeof(mi_rcv_ok));
			mi_rx_done();
		}
	}
	return 0;
}

int mi_time_write(void * p) {
	rf_packet_att_data_t *req = (rf_packet_att_data_t*) p;
	u32 len = req->l2cap - 3;
#if (DEV_SERVICES & SERVICE_HARD_CLOCK)
	/* As the original LYWSD02MMC 2.0.1_0021 firmware:
	 * 5: utc + tz hour; 6: utc + tz hour + tz quarter (15 min); 7: only the 12/24h mode (0xAA = 12h).
	 * An invalid timezone (hour -24..24, quarter -4..4) discards the whole write.
	 * 4: utc only (extension, the timezone is kept). */
	if (len == 7) {
		u8 am_pm = (req->dat[6] == 0xAA) ? 1 : 0;
		if (cfg.flg.time_am_pm != am_pm) {
			cfg.flg.time_am_pm = am_pm;
			flash_write_cfg(&cfg, EEP_ID_CFG, sizeof(cfg));
		}
		SET_LCD_UPDATE();
		return 0;
	}
	if (len > 7)
		return 0;
	if (len >= 5) {
		s8 tz[2];
		tz[0] = (s8)req->dat[4];
		tz[1] = (len == 6) ? (s8)req->dat[5] : 0;
		if (!mi_tz_norm(tz))
			return 0;
		if (mi_tz[0] != tz[0] || mi_tz[1] != tz[1]) {
			mi_tz[0] = tz[0];
			mi_tz[1] = tz[1];
			flash_write_cfg(mi_tz, EEP_ID_MTZ, sizeof(mi_tz));
		}
	}
#endif
	if (len >= 4) {
		u32 t;
		memcpy(&t, req->dat, 4);
		mi_time_set(t);
	}
	return 0;
}

int mi_tunit_write(void * p) {
	rf_packet_att_data_t *req = (rf_packet_att_data_t*) p;
	u32 len = req->l2cap - 3;
	if (len) {
#if (DEVICE_TYPE == DEVICE_LYWSD02MMC)
		// as the original 2.0.1_0021 firmware (FUN_a0e4): only 0x01 = F, other values = C (0xFF: C of the old LYWSD02)
		u8 f = (req->dat[0] == 1) ? 1 : 0;
#else
		u8 f = req->dat[0] ? 1 : 0;
#endif
		mi_tunit_val = f;
		if (cfg.flg.temp_F_or_C != f) {
			cfg.flg.temp_F_or_C = f;
			flash_write_cfg(&cfg, EEP_ID_CFG, sizeof(cfg));
			SET_LCD_UPDATE();
		}
	}
	return 0;
}

/* ---------------------------------------------------------------------------------------------
 *  Data service values
 * -------------------------------------------------------------------------------------------*/
/* ebe0ccc1: s16 temperature x0.01 C with 0.1 C resolution (as the original firmware; here the
 * rounded 0.1 C value shown on the LCD), u8 humidity %, u16 battery mV */
void mi_th_update(void) {
	s16 t = measured_data.temp_x01 * 10;
	u16 mv = measured_data.battery_mv;
	mi_th_val[0] = (u8)t;
	mi_th_val[1] = (u8)(t >> 8);
	mi_th_val[2] = measured_data.humi_x1;
	mi_th_val[3] = (u8)mv;
	mi_th_val[4] = (u8)(mv >> 8);
	mi_tunit_val = cfg.flg.temp_F_or_C;
}

void mi_th_notify(void) {
	mi_th_update();
	if (mi_th_ccc)
		bls_att_pushNotifyData(MiTH_DATA_DP_H, mi_th_val, sizeof(mi_th_val));
}

u8 mi_auth_logged(void) {
	return mi_auth.step == MI_STEP_LOGGED;
}

#if USE_MI_COMFORT
RAM u8 mi_cmf_val[6];
#if (DEV_SERVICES & SERVICE_HISTORY)
static void hist_stop(void);
#endif

/* ebe0ccbe read: the current unit (also when changed by TelinkMiFlasher), as the original firmware */
int mi_tunit_read(void * p) {
	(void) p;
	mi_tunit_val = cfg.flg.temp_F_or_C;
	return 0;
}

/* ebe0ccd7 comfort range as the original LYWSD02MMC 2.0.1_0021 firmware (FUN_9fdc, FUN_c400, FUN_9f9c):
 * write: s16 Thigh, s16 Tlow (x0.1 C), u8 Hhigh, u8 Hlow (%);
 * read: u16 Thigh, u16 Tlow (x0.01 C), u8 Hhigh, u8 Hlow (%);
 * accepted: Thigh >= Tlow, Hhigh >= Hlow, Tlow >= -10 C, Thigh <= 100 C, Hhigh <= 99 %.
 * The original firmware takes both humidity limits from byte 4 (Hlow is lost); here byte 5 is Hlow
 * (a 5-byte write sets both, as the original). Stored in cmf (x0.01, the comfort smiley). */
int mi_cmf_write(void * p) {
	rf_packet_att_data_t *req = (rf_packet_att_data_t*) p;
	u32 len = req->l2cap - 3;
	if (len < 5 || len > 6)
		return 0;
	s32 th = (s16)(req->dat[0] | (req->dat[1] << 8)) * 10;
	s32 tl = (s16)(req->dat[2] | (req->dat[3] << 8)) * 10;
	u32 hh = req->dat[4] * 100;
	u32 hl = (len == 6) ? req->dat[5] * 100 : hh;
	if (th < tl || hh < hl || tl < -1000 || th > 10000 || hh > 9900)
		return 0;
	cmf.t[0] = (s16)tl;
	cmf.t[1] = (s16)th;
	cmf.h[0] = (u16)hl;
	cmf.h[1] = (u16)hh;
	flash_write_cfg(&cmf, EEP_ID_CMF, sizeof(cmf));
	if (!cfg.flg.comfort_smiley) { // the original firmware always shows the comfort face
		cfg.flg.comfort_smiley = 1;
		flash_write_cfg(&cfg, EEP_ID_CFG, sizeof(cfg));
	}
	SET_LCD_UPDATE();
	return 0;
}

int mi_cmf_read(void * p) {
	(void) p;
	mi_cmf_val[0] = (u8)cmf.t[1];
	mi_cmf_val[1] = (u8)(cmf.t[1] >> 8);
	mi_cmf_val[2] = (u8)cmf.t[0];
	mi_cmf_val[3] = (u8)(cmf.t[0] >> 8);
	mi_cmf_val[4] = (u8)(cmf.h[1] / 100);
	mi_cmf_val[5] = (u8)(cmf.h[0] / 100);
	return 0;
}

/* ebe0ccd4 "reset data" as the original firmware (FUN_a028): 0x01 from a logged-in MiHome session
 * clears the measurement history and resets the settings of the original firmware (FUN_c35c
 * clear_syspara): C, 24h, comfort range, timezone UTC+8 (the UTC clock keeps running).
 * The Mi key records (binding) are kept; the original firmware reboots afterwards, not needed here. */
int mi_reset_write(void * p) {
	rf_packet_att_data_t *req = (rf_packet_att_data_t*) p;
	if (req->l2cap <= 3 || req->dat[0] != 1 || !mi_auth_logged())
		return 0;
#if (DEV_SERVICES & SERVICE_HISTORY)
	hist_stop();
	clear_memo();
#endif
	cfg.flg.temp_F_or_C = 0;
	cfg.flg.time_am_pm = 0;
	cfg.flg.comfort_smiley = 1;
	flash_write_cfg(&cfg, EEP_ID_CFG, sizeof(cfg));
	memcpy(&cmf, &def_cmf, sizeof(cmf));
	flash_write_cfg(&cmf, EEP_ID_CMF, sizeof(cmf));
#if (DEV_SERVICES & SERVICE_HARD_CLOCK)
	mi_tz[0] = 8;
	mi_tz[1] = 0;
	flash_write_cfg(mi_tz, EEP_ID_MTZ, sizeof(mi_tz));
	rtc_set_utime(wrk.utc_time_sec + mi_tz_offset_sec());
#endif
	SET_LCD_UPDATE();
	return 0;
}
#endif // USE_MI_COMFORT

#if (DEV_SERVICES & SERVICE_HISTORY)
/* ---------------------------------------------------------------------------------------------
 *  History (ebe0ccb9..ebe0ccbc) as the original firmware:
 *  index = hour number (utc / 3600); record = [u32 index][u32 time = end of hour]
 *  [s16 Tmax x0.1 C][u8 Hmax %][s16 Tmin x0.1 C][u8 Hmin %]. Only complete hours are reported.
 *  USE_MI_HIST_MAXMIN: max/min of all measurements of the hour (own flash ring);
 *  otherwise max/min of the pvvx logger records (averages) whose averaging window is centred
 *  in that hour.
 * -------------------------------------------------------------------------------------------*/
#define MI_HIST_TIME_MIN	MI_TIME_MIN // older time stamps = clock was not set

RAM u8 mi_hist_count_val[8];	// ebe0ccb9: u32 last index, u32 count
RAM u8 mi_hist_index_val[4];	// ebe0ccba: u32 index
RAM u8 mi_hist_read_val[14];	// ebe0ccbb: newest record
RAM u16 mi_hist_ccc;

static void put32(u8 *p, u32 v) {
	p[0] = (u8)v; p[1] = (u8)(v >> 8); p[2] = (u8)(v >> 16); p[3] = (u8)(v >> 24);
}

#if USE_MI_HIST_MAXMIN
/* ---------------------------------------------------------------------------------------------
 *  USE_MI_HIST_MAXMIN: max/min of all measurements of each hour, as the original firmware.
 *  The current hour is collected in RAM; when the hour changes it is appended to a ring of two
 *  flash sectors (0x72000..0x73FFF, 341 hours each: 14..28 days). Records are in time order:
 *  the older sector first, then the current one; the older sector is erased when the current
 *  one is full. A slot that is written but not valid (power lost while writing) is skipped.
 * -------------------------------------------------------------------------------------------*/
#define HR_START	FLASH_ADDR_END_MEMO					// 0x72000
#define HR_END		(HR_START + 2 * FLASH_SECTOR_SIZE)	// 0x74000
#define HR_SEC_RECS	(FLASH_SECTOR_SIZE / sizeof(hr_rec_t))	// 341
#define HR_MARK		0x5AA5

typedef struct {
	u32 hour;	// utc / 3600
	s16 tmax;	// x0.1 C
	s16 tmin;	// x0.1 C
	u8 hmax;	// %
	u8 hmin;	// %
	u16 mark;	// HR_MARK: valid record
} hr_rec_t;		// 12 bytes

typedef struct {
	u32 cur_sec;	// current sector (being written)
	u32 wr;			// next free slot in cur_sec
	u32 old_n;		// slots used in the other (older) sector
	u32 last_wr;	// hour of the newest record in the ring
	hr_rec_t acc;	// current hour (mark = 0: no data yet)
	// MiHome transfer
	u32 first;		// first hour index
	u32 last;		// last hour index
	u32 count;		// last - first + 1, 0 = no data
	u32 cur;		// next hour index to send
	u32 pos;		// next record (0 = oldest) to send
	u8 active;		// transfer started by index write
} mi_hist_t;
RAM mi_hist_t mi_hist;

static u32 hr_other(u32 sec) {
	return (sec == HR_START) ? HR_START + FLASH_SECTOR_SIZE : HR_START;
}

static u32 hr_total(void) {
	return mi_hist.old_n + (mi_hist.wr - mi_hist.cur_sec) / sizeof(hr_rec_t);
}

/* record i (0 = oldest); returns 1 if valid */
static int hr_get(u32 i, hr_rec_t *p) {
	u32 faddr;
	if (i < mi_hist.old_n)
		faddr = hr_other(mi_hist.cur_sec) + i * sizeof(hr_rec_t);
	else
		faddr = mi_hist.cur_sec + (i - mi_hist.old_n) * sizeof(hr_rec_t);
	flash_read_page(FLASH_BASE_ADDR + faddr, sizeof(hr_rec_t), (u8 *)p);
	return p->mark == HR_MARK && p->hour >= MI_HIST_TIME_MIN / 3600 && p->hour < 0x80000000u / 3600;
}

/* used slots of a sector (up to the first erased slot), newest valid hour in *plast;
 * returns -1 if the sector holds other data (the logger used it before) */
static int hr_scan_sec(u32 sec, u32 *plast) {
	hr_rec_t r;
	u32 n;
	u8 *b = (u8 *)&r;
	*plast = 0;
	for (n = 0; n < HR_SEC_RECS; n++) {
		flash_read_page(FLASH_BASE_ADDR + sec + n * sizeof(hr_rec_t), sizeof(r), b);
		if (r.hour == 0xffffffff && r.mark == 0xffff && r.tmax == -1 && r.tmin == -1)
			break; // erased
		if (r.mark == HR_MARK)
			*plast = r.hour;
		else if (n == 0)
			return -1;
	}
	return n;
}

static void hr_erase(u32 sec) {
	flash_erase_sector(FLASH_BASE_ADDR + sec);
}

/* power-on: find the current sector and the write position */
void mi_hist_init(void) {
	u32 la, lb;
	int na, nb;
	memset(&mi_hist, 0, sizeof(mi_hist));
	na = hr_scan_sec(HR_START, &la);
	if (na < 0) {
		hr_erase(HR_START);
		na = 0;
	}
	nb = hr_scan_sec(HR_START + FLASH_SECTOR_SIZE, &lb);
	if (nb < 0) {
		hr_erase(HR_START + FLASH_SECTOR_SIZE);
		nb = 0;
	}
	if (na == HR_SEC_RECS && nb == HR_SEC_RECS) { // both full (power lost before the erase)
		if (la < lb) {
			hr_erase(HR_START);
			na = 0;
		} else {
			hr_erase(HR_START + FLASH_SECTOR_SIZE);
			nb = 0;
		}
	}
	// current = the one that is not full and has the newer records (or A if both are empty)
	if (na == HR_SEC_RECS || (nb != HR_SEC_RECS && nb && lb > la)) {
		mi_hist.cur_sec = HR_START + FLASH_SECTOR_SIZE;
		mi_hist.wr = mi_hist.cur_sec + nb * sizeof(hr_rec_t);
		mi_hist.old_n = na;
		mi_hist.last_wr = (nb && lb) ? lb : la;
	} else {
		mi_hist.cur_sec = HR_START;
		mi_hist.wr = HR_START + na * sizeof(hr_rec_t);
		mi_hist.old_n = nb;
		mi_hist.last_wr = (na && la) ? la : lb;
	}
}

static void hist_stop(void);

static void hr_append(hr_rec_t *p) {
	if (mi_hist.wr + sizeof(hr_rec_t) > mi_hist.cur_sec + FLASH_SECTOR_SIZE) {
		// current sector full: it becomes the older one, the oldest sector is erased
		hist_stop(); // a running MiHome transfer may read the erased sector
		mi_hist.old_n = (mi_hist.wr - mi_hist.cur_sec) / sizeof(hr_rec_t);
		mi_hist.cur_sec = hr_other(mi_hist.cur_sec);
		hr_erase(mi_hist.cur_sec);
		mi_hist.wr = mi_hist.cur_sec;
	}
	flash_write_page(FLASH_BASE_ADDR + mi_hist.wr, sizeof(hr_rec_t), (u8 *)p);
	mi_hist.wr += sizeof(hr_rec_t);
	mi_hist.last_wr = p->hour;
}

/* clear_memo(): clock set back, MiHome "reset data", TelinkMiFlasher "clear log" */
void mi_hist_clear(void) {
	hist_stop();
	hr_erase(HR_START);
	hr_erase(HR_START + FLASH_SECTOR_SIZE);
	mi_hist.cur_sec = HR_START;
	mi_hist.wr = HR_START;
	mi_hist.old_n = 0;
	mi_hist.last_wr = 0;
	mi_hist.acc.mark = 0;
}

/* each measurement: max/min of the current hour; a new hour appends the previous one */
void mi_hist_measure(void) {
	u32 t = wrk.utc_time_sec, h;
	s16 tv = measured_data.temp_x01;	// 0.1 C as shown
	u8 hv = measured_data.humi_x1;		// % as shown
	if (t < MI_HIST_TIME_MIN)
		return; // clock not set
	h = t / 3600;
	if (mi_hist.acc.mark) {
		if (h < mi_hist.acc.hour)
			return; // stepped back a little (minute resync from the RTC): ignore the sample
		if (h > mi_hist.acc.hour) {
			if (mi_hist.acc.hour > mi_hist.last_wr)
				hr_append(&mi_hist.acc);
			mi_hist.acc.mark = 0;
		}
	}
	if (!mi_hist.acc.mark) {
		mi_hist.acc.hour = h;
		mi_hist.acc.tmax = mi_hist.acc.tmin = tv;
		mi_hist.acc.hmax = mi_hist.acc.hmin = hv;
		mi_hist.acc.mark = HR_MARK;
	} else {
		if (tv > mi_hist.acc.tmax) mi_hist.acc.tmax = tv;
		if (tv < mi_hist.acc.tmin) mi_hist.acc.tmin = tv;
		if (hv > mi_hist.acc.hmax) mi_hist.acc.hmax = hv;
		if (hv < mi_hist.acc.hmin) mi_hist.acc.hmin = hv;
	}
}

static void hr_out(hr_rec_t *r, u8 *out) {
	put32(&out[0], r->hour);
	put32(&out[4], (r->hour + 1) * 3600);
	out[8] = (u8)r->tmax; out[9] = (u8)(r->tmax >> 8);
	out[10] = r->hmax;
	out[11] = (u8)r->tmin; out[12] = (u8)(r->tmin >> 8);
	out[13] = r->hmin;
}

/* first / last hour of the ring (complete hours only; the current hour is in RAM) */
static void hist_scan(void) {
	hr_rec_t r;
	u32 i, n = hr_total();
	mi_hist.first = 0;
	mi_hist.last = 0;
	mi_hist.count = 0;
	for (i = 0; i < n; i++)
		if (hr_get(i, &r)) {
			mi_hist.first = r.hour;
			break;
		}
	for (i = n; i > 0; i--)
		if (hr_get(i - 1, &r)) {
			mi_hist.last = r.hour;
			break;
		}
	if (mi_hist.first && mi_hist.last >= mi_hist.first)
		mi_hist.count = mi_hist.last - mi_hist.first + 1;
	else
		mi_hist.last = 0;
	put32(&mi_hist_count_val[0], mi_hist.last);
	put32(&mi_hist_count_val[4], mi_hist.count);
}

static void hist_stop(void) {
	if (mi_hist.active)
		bls_pm_setManualLatency(cfg.connect_latency);
	mi_hist.active = 0;
	mi_hist.cur = 0;
}

int mi_hist_count_read(void * p) {
	(void) p;
	hist_scan();
	return 0;
}

int mi_hist_index_write(void * p) {
	rf_packet_att_data_t *req = (rf_packet_att_data_t*) p;
	hr_rec_t r;
	u32 len = req->l2cap - 3, idx, i, n;
	if (len >= 4) {
		idx = req->dat[0] | (req->dat[1] << 8) | (req->dat[2] << 16) | ((u32)req->dat[3] << 24);
		hist_scan();
		if (!mi_hist.count || idx > mi_hist.last) {
			hist_stop();
		} else {
			if (idx < mi_hist.first)
				idx = mi_hist.first;
			// first record with hour >= idx
			n = hr_total();
			for (i = 0; i < n; i++)
				if (hr_get(i, &r) && r.hour >= idx)
					break;
			mi_hist.pos = i;
			mi_hist.cur = idx;
			if (!mi_hist.active)
				bls_pm_setManualLatency(0);
			mi_hist.active = 1;
		}
		put32(mi_hist_index_val, mi_hist.cur);
	}
	return 0;
}

int mi_hist_index_read(void * p) {
	(void) p;
	put32(mi_hist_index_val, mi_hist.cur);
	return 0;
}

int mi_hist_read_read(void * p) {
	hr_rec_t r;
	u32 i;
	(void) p;
	memset(mi_hist_read_val, 0, sizeof(mi_hist_read_val));
	for (i = hr_total(); i > 0; i--)
		if (hr_get(i - 1, &r)) {
			hr_out(&r, mi_hist_read_val);
			break;
		}
	return 0;
}

/* the stack does not store the value of an attribute that has a write callback */
int mi_hist_ccc_write(void * p) {
	rf_packet_att_data_t *req = (rf_packet_att_data_t*) p;
	if (req->l2cap - 3 >= 2) {
		mi_hist_ccc = req->dat[0] | (req->dat[1] << 8);
		if (!mi_hist_ccc)
			hist_stop();
	}
	return 0;
}

u8 mi_hist_busy(void) {
	return mi_hist.active && mi_hist_ccc;
}

/* main loop, connected and TX FIFO ready: send one hourly record */
void mi_hist_task(void) {
	hr_rec_t r;
	u8 rec[sizeof(mi_hist_read_val)]; // the stack copies notification data
	while (mi_hist.active) {
		if (mi_hist.pos >= hr_total()) {
			hist_stop();
			return;
		}
		if (hr_get(mi_hist.pos++, &r)) {
			hr_out(&r, rec);
			bls_att_pushNotifyData(MiTH_HNTF_DP_H, rec, sizeof(rec));
			mi_hist.cur = r.hour + 1;
			return;
		}
	}
}

#else // USE_MI_HIST_MAXMIN
#define MI_HIST_SEC_RECS_DEF	((FLASH_SECTOR_SIZE - sizeof(memo_head_t)) / sizeof(memo_blk_t))
#if USE_MEMO_1M
#define H_SEC_RECS	(mi_hist.snap.sectors)
#define H_START		(mi_hist.snap.start_addr)
#define H_END		(mi_hist.snap.end_addr)
#else
#define H_SEC_RECS	MI_HIST_SEC_RECS_DEF
#define H_START		FLASH_ADDR_START_MEMO
#define H_END		FLASH_ADDR_END_MEMO
#endif

typedef struct {
	memo_inf_t snap;	// logger snapshot
	u32 total;			// records in the snapshot
	u32 first;			// first hour index
	u32 last;			// last complete hour index
	u32 count;			// last - first + 1, 0 = no data
	u32 cur;			// next hour index to send
	u32 bnum;			// logger cursor: 1 = newest record
	u8 active;			// transfer started by index write
} mi_hist_t;
RAM mi_hist_t mi_hist;

static u32 hist_sec_prev(u32 faddr) {
	faddr -= FLASH_SECTOR_SIZE;
	if (faddr < H_START || faddr >= H_END)
		faddr = H_END - FLASH_SECTOR_SIZE;
	return faddr;
}

/* read record bnum (1 = newest) of the snapshot */
static int hist_get(u32 bnum, memo_blk_t *p) {
	memo_head_t mhs;
	u32 faddr = mi_hist.snap.faddr & ~(FLASH_SECTOR_SIZE - 1);
	if (bnum == 0 || bnum > mi_hist.total)
		return 0;
	if (bnum > mi_hist.snap.cnt_cur_sec) {
		bnum -= mi_hist.snap.cnt_cur_sec;
		faddr = hist_sec_prev(faddr);
		while (bnum > H_SEC_RECS) {
			bnum -= H_SEC_RECS;
			faddr = hist_sec_prev(faddr);
		}
		bnum = H_SEC_RECS - bnum;
		flash_read_page(FLASH_BASE_ADDR + faddr, sizeof(mhs), (u8 *)&mhs);
		if (mhs.id != MEMO_SEC_ID || mhs.flg != 0)
			return 0;
	} else
		bnum = mi_hist.snap.cnt_cur_sec - bnum;
	faddr += sizeof(memo_head_t) + bnum * sizeof(memo_blk_t);
	flash_read_page(FLASH_BASE_ADDR + faddr, sizeof(memo_blk_t), (u8 *)p);
	return 1;
}

/* hour index of a record (centre of its averaging window), 0 = invalid time
 * (clock not set, or later than now: written before the clock was set back) */
static u32 hist_hour(u32 t) {
	u32 half;
	if (t < MI_HIST_TIME_MIN || t >= 0xfffffffe)
		return 0;
	if (wrk.utc_time_sec >= MI_HIST_TIME_MIN && t > wrk.utc_time_sec + 60)
		return 0;
	// half window = measurement_step_time (system ticks) * averaging_measurements / 2, in seconds
	half = (wrk.measurement_step_time / CLOCK_16M_SYS_TIMER_CLK_1MS) * cfg.averaging_measurements / 2000;
	return (t - half) / 3600;
}

static u32 hist_seek(u32 hour);

/* snapshot the logger and compute first / last complete hour */
static void hist_scan(void) {
	memo_head_t mhs;
	memo_blk_t r;
	u32 faddr, n, i, h, now_h;
	memcpy(&mi_hist.snap, &memo, sizeof(mi_hist.snap));
	mi_hist.total = 0;
	mi_hist.count = 0;
	mi_hist.first = 0;
	mi_hist.last = 0;
	if (mi_hist.snap.faddr) {
		n = mi_hist.snap.cnt_cur_sec;
		faddr = mi_hist.snap.faddr & ~(FLASH_SECTOR_SIZE - 1);
		for (i = 1; i < (H_END - H_START) / FLASH_SECTOR_SIZE; i++) {
			faddr = hist_sec_prev(faddr);
			flash_read_page(FLASH_BASE_ADDR + faddr, sizeof(mhs), (u8 *)&mhs);
			if (mhs.id != MEMO_SEC_ID || mhs.flg != 0)
				break;
			n += H_SEC_RECS;
		}
		mi_hist.total = n;
		// current (incomplete) hour is not reported
		now_h = (wrk.utc_time_sec >= MI_HIST_TIME_MIN) ? wrk.utc_time_sec / 3600 : 0xffffffff;
		for (i = 1; i <= n && i <= 64; i++) { // newest valid record
			if (hist_get(i, &r) && (h = hist_hour(r.time)) != 0) {
				mi_hist.last = (h < now_h) ? h : now_h - 1;
				break;
			}
		}
		// oldest valid record (invalid ones - clock not set / set back - are only at the old end)
		i = hist_seek(1);
		if (i && hist_get(i, &r))
			mi_hist.first = hist_hour(r.time);
		if (mi_hist.first && mi_hist.last >= mi_hist.first)
			mi_hist.count = mi_hist.last - mi_hist.first + 1;
	}
	if (!mi_hist.count)
		mi_hist.last = 0;
	put32(&mi_hist_count_val[0], mi_hist.last);
	put32(&mi_hist_count_val[4], mi_hist.count);
}

/* aggregate hour 'hour' from cursor *pbnum toward newer records, build 14-byte record */
static int hist_make(u32 *pbnum, u32 hour, u8 *out) {
	memo_blk_t r;
	s16 tmax = -32768, tmin = 32767;
	u16 hmax = 0, hmin = 0xffff;
	u32 h, n = 0;
	while (*pbnum) {
		if (!hist_get(*pbnum, &r)) {
			*pbnum = 0;
			break;
		}
		h = hist_hour(r.time);
		if (h > hour)
			break;
		if (h == hour) {
			if (r.val1 > tmax) tmax = r.val1;
			if (r.val1 < tmin) tmin = r.val1;
			if (r.val2 > hmax) hmax = r.val2;
			if (r.val2 < hmin) hmin = r.val2;
			n++;
		}
		(*pbnum)--;
	}
	if (!n)
		return 0;
	tmax /= 10;
	tmin /= 10;
	put32(&out[0], hour);
	put32(&out[4], (hour + 1) * 3600);
	out[8] = (u8)tmax; out[9] = (u8)(tmax >> 8);
	out[10] = (u8)(hmax / 100);
	out[11] = (u8)tmin; out[12] = (u8)(tmin >> 8);
	out[13] = (u8)(hmin / 100);
	return 1;
}

/* largest bnum (oldest) whose hour >= hour */
static u32 hist_seek(u32 hour) {
	memo_blk_t r;
	u32 lo = 1, hi = mi_hist.total, mid, res = 0;
	while (lo <= hi) {
		mid = (lo + hi) / 2;
		if (hist_get(mid, &r) && hist_hour(r.time) >= hour) {
			res = mid;
			lo = mid + 1;
		} else
			hi = mid - 1;
	}
	return res;
}

static void hist_stop(void) {
	if (mi_hist.active)
		bls_pm_setManualLatency(cfg.connect_latency);
	mi_hist.active = 0;
	mi_hist.cur = 0;
}

int mi_hist_count_read(void * p) {
	(void) p;
	hist_scan();
	return 0;
}

int mi_hist_index_write(void * p) {
	rf_packet_att_data_t *req = (rf_packet_att_data_t*) p;
	u32 len = req->l2cap - 3, idx;
	if (len >= 4) {
		idx = req->dat[0] | (req->dat[1] << 8) | (req->dat[2] << 16) | ((u32)req->dat[3] << 24);
		hist_scan();
		if (!mi_hist.count || idx > mi_hist.last) {
			hist_stop();
		} else {
			if (idx < mi_hist.first)
				idx = mi_hist.first;
			mi_hist.cur = idx;
			mi_hist.bnum = hist_seek(idx);
			if (!mi_hist.active)
				bls_pm_setManualLatency(0);
			mi_hist.active = 1;
		}
		put32(mi_hist_index_val, mi_hist.cur);
	}
	return 0;
}

int mi_hist_index_read(void * p) {
	(void) p;
	put32(mi_hist_index_val, mi_hist.cur);
	return 0;
}

int mi_hist_read_read(void * p) {
	u32 bnum;
	(void) p;
	memset(mi_hist_read_val, 0, sizeof(mi_hist_read_val));
	hist_scan();
	if (mi_hist.count) {
		bnum = hist_seek(mi_hist.last);
		hist_make(&bnum, mi_hist.last, mi_hist_read_val);
	}
	return 0;
}

/* the stack does not store the value of an attribute that has a write callback */
int mi_hist_ccc_write(void * p) {
	rf_packet_att_data_t *req = (rf_packet_att_data_t*) p;
	if (req->l2cap - 3 >= 2) {
		mi_hist_ccc = req->dat[0] | (req->dat[1] << 8);
		if (!mi_hist_ccc)
			hist_stop();
	}
	return 0;
}

u8 mi_hist_busy(void) {
	return mi_hist.active && mi_hist_ccc;
}

/* main loop, connected and TX FIFO ready: send one hourly record */
void mi_hist_task(void) {
	memo_blk_t r;
	u8 rec[sizeof(mi_hist_read_val)]; // the stack copies notification data
	while (mi_hist.active) {
		if (mi_hist.cur > mi_hist.last || !mi_hist.bnum) {
			hist_stop();
			return;
		}
		if (hist_make(&mi_hist.bnum, mi_hist.cur, rec)) {
			bls_att_pushNotifyData(MiTH_HNTF_DP_H, rec, sizeof(rec));
			mi_hist.cur++;
			return;
		}
		// no data for this hour: continue with the hour of the next record
		if (mi_hist.bnum && hist_get(mi_hist.bnum, &r) && hist_hour(r.time) > mi_hist.cur)
			mi_hist.cur = hist_hour(r.time);
		else
			mi_hist.cur++;
	}
}
#endif // USE_MI_HIST_MAXMIN
#endif // (DEV_SERVICES & SERVICE_HISTORY)

#if USE_MI_TIME_SAVE
/* ---------------------------------------------------------------------------------------------
 *  Clock kept in flash as the original firmware (FUN_0000ac88 / abec / accc): u32 UTC entries
 *  appended to 0x7A000..0x7BFFF every 5 minutes and when the clock is set; both sectors are
 *  erased when the area is full. Power-on: the newest entry is restored (if newer than the
 *  logger time). The same format lets the original firmware restore the clock too.
 * -------------------------------------------------------------------------------------------*/
#define MI_TLOG_START	0x7A000
#define MI_TLOG_END		0x7C000
#define MI_TLOG_STEP	300 // seconds

RAM u32 mi_tlog_addr;	// next free entry
RAM u32 mi_tlog_next;	// next periodic save time

#define MI_TLOG_VALID(v)	((v) >= MI_TIME_MIN && (v) < 0x80000000u) // not erased / not a partially written word

#define MI_TLOG_EARLY	(12 * 4)	// last 12 entries (1 hour of saves): erased early when not connected
#define MI_TLOG_RETRY	10			// seconds: retry of a postponed save while connected

/* append t; returns 0 if postponed (area full while connected: no sector erase during a connection,
 * retried every MI_TLOG_RETRY seconds) */
static int mi_tlog_write(u32 t) {
	u32 v = 0;
	if (mi_tlog_addr >= MI_TLOG_START && mi_tlog_addr + 4 <= MI_TLOG_END)
		flash_read_page(FLASH_BASE_ADDR + mi_tlog_addr, 4, (u8 *)&v);
	// full, or not erased (power lost during the erase of the two sectors): erase and restart;
	// nearly full and not connected: erase now, so that the area hardly ever gets full during a connection
	if (v != 0xffffffff || (!wrk.ble_connected && mi_tlog_addr >= MI_TLOG_END - MI_TLOG_EARLY)) {
		if (wrk.ble_connected) {
			mi_tlog_next = t + MI_TLOG_RETRY;
			return 0;
		}
		flash_erase_sector(FLASH_BASE_ADDR + MI_TLOG_START);
		flash_erase_sector(FLASH_BASE_ADDR + MI_TLOG_START + FLASH_SECTOR_SIZE);
		mi_tlog_addr = MI_TLOG_START;
	}
	flash_write_page(FLASH_BASE_ADDR + mi_tlog_addr, 4, (u8 *)&t);
	mi_tlog_addr += 4;
	mi_tlog_next = t - (t % MI_TLOG_STEP) + MI_TLOG_STEP;
	return 1;
}

/* power-on, after memo_init() (which sets the clock from the last logger record + 5 s, l).
 * Saved clock t (newest entry, at most 5 minutes old at the reset):
 *  l <= t + 6 min: the newer of both (a logger record may follow the last save);
 *  t + 6 min < l <= t + 1 h: t (the clock was set back: the newest records are ahead);
 *  l > t + 1 h: l (area left by the original firmware or not written for a long time). */
void mi_time_load(void) {
#if (DEV_SERVICES & SERVICE_HARD_CLOCK)
	// normalized as written (also values saved by earlier builds, e.g. +24 h -> 0)
	if (flash_read_cfg(mi_tz, EEP_ID_MTZ, sizeof(mi_tz)) != sizeof(mi_tz) || !mi_tz_norm(mi_tz)) {
		mi_tz[0] = 8; // default UTC+8
		mi_tz[1] = 0;
	}
#endif
	u32 a, v, t = 0, l = wrk.utc_time_sec;
	for (a = MI_TLOG_START; a < MI_TLOG_END; a += 4) {
		flash_read_page(FLASH_BASE_ADDR + a, 4, (u8 *)&v);
		if (v == 0xffffffff)
			break;
		if (MI_TLOG_VALID(v))
			t = v;
	}
	mi_tlog_addr = a;
	if (t && (l < MI_TIME_MIN || t >= l || (l - t > MI_TLOG_STEP + 60 && l - t <= 3600)))
		wrk.utc_time_sec = t;
	t = wrk.utc_time_sec;
	mi_tlog_next = t - (t % MI_TLOG_STEP) + MI_TLOG_STEP;
}

/* OTA start: save the clock now, so that a restore from the flash after the reboot (RTC not
 * usable) loses only the OTA time instead of up to 5 minutes */
void mi_time_save(void) {
	if (wrk.utc_time_sec >= MI_TIME_MIN)
		mi_tlog_write(wrk.utc_time_sec);
}

/* main loop (called when MI_TIME_TASK_DUE()): save the clock every 5 minutes */
void mi_time_task(void) {
	u32 t = wrk.utc_time_sec;
	if (t >= mi_tlog_next) {
		if (t >= MI_TIME_MIN)
			mi_tlog_write(t);
		else // clock not set: nothing to save, check again in 5 minutes
			mi_tlog_next = t - (t % MI_TLOG_STEP) + MI_TLOG_STEP;
	}
}
#endif // USE_MI_TIME_SAVE

/* Set the clock (UTC, as MiHome uses it). A step back of more than one hour would leave the
 * logger out of order (newer records with older time stamps), so the logger is cleared then. */
void mi_time_set(u32 t) {
#if (DEV_SERVICES & SERVICE_HISTORY)
	if (wrk.utc_time_sec >= MI_HIST_TIME_MIN && t + 3600 < wrk.utc_time_sec) {
		hist_stop();
		clear_memo();
	}
#endif
	wrk.utc_time_sec = t;
#if (DEV_SERVICES & SERVICE_TIME_ADJUST)
	utc_set_time_sec = t;
#endif
#if (DEV_SERVICES & SERVICE_HARD_CLOCK)
	rtc_set_utime(t + mi_tz_offset_sec());
#endif
#if USE_MI_TIME_SAVE
	if (t >= MI_TIME_MIN) {
		mi_tlog_write(t); // area full while connected: saved after the disconnect (retry every MI_TLOG_RETRY s)
	}
#endif
	SET_LCD_UPDATE();
}

/* ebe0ccc8 "Disconnect": as the original firmware (FUN_b868), 0x88 stops the c1/history
 * notifications and terminates the connection (reason 0x13); other values are ignored. */
int mi_disc_write(void * p) {
	rf_packet_att_data_t *req = (rf_packet_att_data_t*) p;
	if (req->l2cap > 3 && req->dat[0] == 0x88) {
		mi_th_ccc = 0;
#if (DEV_SERVICES & SERVICE_HISTORY)
		hist_stop();
		mi_hist_ccc = 0;
#endif
		bls_ll_terminateConnection(HCI_ERR_REMOTE_USER_TERM_CONN);
	}
	return 0;
}

void mi_auth_reset(void) {
	memset(&mi_auth, 0, sizeof(mi_auth));
	mi_auth_ccc = 0;
	mi_std_ccc = 0;
	mi_th_ccc = 0;
	mi_th_update();
#if (DEV_SERVICES & SERVICE_HISTORY)
	mi_hist.active = 0;
	mi_hist.cur = 0;
	mi_hist_ccc = 0;
#endif
}

#endif // USE_MI_AUTH
