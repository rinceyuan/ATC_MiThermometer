/*
 * mi_auth.h
 * MiHome app connection support: Xiaomi "standard auth" login on service 0xFE95
 * (re-uses the token stored by the original firmware in the Mi key records)
 * and the ebe0ccb0 data service of the original Xiaomi thermometer firmware.
 */
#ifndef _MI_AUTH_H_
#define _MI_AUTH_H_

#if USE_MI_AUTH

#define MI_UUID_VERSION		0x0004
#define MI_UUID_AUTH		0x0010
#define MI_UUID_STANDARD	0x0019

#define MI_AUTH_CMD_LOGIN	0x24
#define MI_AUTH_LOGIN_OK	0x21
#define MI_AUTH_LOGIN_ERR	0x23
#define MI_AUTH_NOT_REG		0xE0

extern const u8 mi_version_str[10];
extern u8 mi_auth_val[4];
extern u8 mi_std_val[20];
extern u16 mi_auth_ccc;
extern u16 mi_std_ccc;

extern u8 mi_th_val[5];
extern u8 mi_tunit_val;
extern u16 mi_th_ccc;

int mi_auth_write(void * p);	// 0x0010 write
int mi_std_write(void * p);		// 0x0019 write
int mi_time_write(void * p);	// ebe0ccb7 write
int mi_tunit_write(void * p);	// ebe0ccbe write

void mi_auth_reset(void);		// on connect / disconnect
void mi_th_update(void);		// refresh ebe0ccc1/ebe0ccbe values
void mi_th_notify(void);		// refresh + notify ebe0ccc1 if enabled
u8 mi_auth_logged(void);

#endif // USE_MI_AUTH
#endif // _MI_AUTH_H_
