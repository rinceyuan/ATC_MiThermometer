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
#include "mi_auth.h"

#define MI_FRAME_DATA_SIZE	18 // (ATT_MTU 23) - 3 - 2

#if (DEV_SERVICES & SERVICE_TIME_ADJUST)
extern u32 utc_set_time_sec; // cmd_parser.c
#endif

/* --- GATT values --- */
const u8 mi_version_str[10] = {'2','.','1','.','1','_','0','0','0','9'};
RAM u8 mi_auth_val[4];
RAM u8 mi_std_val[20];
RAM u16 mi_auth_ccc;
RAM u16 mi_std_ccc;
RAM u8 mi_th_val[5];
RAM u8 mi_tunit_val;
RAM u16 mi_th_ccc;

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
	mi_auth_val[0] = code;
	mi_auth_val[1] = 0;
	mi_auth_val[2] = 0;
	mi_auth_val[3] = 0;
	bls_att_pushNotifyData(Mi_AUTH_DP_H, mi_auth_val, sizeof(mi_auth_val));
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
	if (len >= 4) {
		memcpy(&wrk.utc_time_sec, req->dat, 4);
#if (DEV_SERVICES & SERVICE_TIME_ADJUST)
		utc_set_time_sec = wrk.utc_time_sec;
#endif
		SET_LCD_UPDATE();
	}
	return 0;
}

int mi_tunit_write(void * p) {
	rf_packet_att_data_t *req = (rf_packet_att_data_t*) p;
	u32 len = req->l2cap - 3;
	if (len) {
		u8 f = req->dat[0] ? 1 : 0;
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
void mi_th_update(void) {
	s16 t = measured_data.temp;
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

void mi_auth_reset(void) {
	memset(&mi_auth, 0, sizeof(mi_auth));
	mi_auth_ccc = 0;
	mi_std_ccc = 0;
	mi_th_ccc = 0;
	mi_th_update();
}

#endif // USE_MI_AUTH
