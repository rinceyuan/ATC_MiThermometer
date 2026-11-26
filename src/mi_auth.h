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
#define MI_AUTH_VAL_LEN	4
// value of the write-only 0x0010 / 0x0019 attributes: the stack does not store values of
// attributes with a write callback, so they share one constant (notifications use locals)
extern const u8 mi_wo_val[20];
extern u16 mi_auth_ccc;
extern u16 mi_std_ccc;

extern u8 mi_th_val[5];
extern u8 mi_tunit_val;
extern u16 mi_th_ccc;

int mi_auth_write(void * p);	// 0x0010 write
int mi_std_write(void * p);		// 0x0019 write
int mi_time_write(void * p);	// ebe0ccb7 write
#if (DEV_SERVICES & SERVICE_HARD_CLOCK)
extern u8 mi_time_val[7];
int mi_time_read(void * p);		// ebe0ccb7 read (utc + tz + 12/24h mode)
s32 mi_tz_offset_sec(void);
#endif
int mi_tunit_write(void * p);	// ebe0ccbe write
#if USE_MI_COMFORT
extern u8 mi_cmf_val[6];
int mi_tunit_read(void * p);	// ebe0ccbe read
int mi_cmf_write(void * p);		// ebe0ccd7 write: comfort range
int mi_cmf_read(void * p);		// ebe0ccd7 read
int mi_reset_write(void * p);	// ebe0ccd4 write: 0x01 - clear history and settings
#endif
int mi_disc_write(void * p);	// ebe0ccc8 write: 0x88 - terminate connection
void mi_time_set(u32 t);		// set clock (UTC); clears the logger on a step back > 1 hour
#if USE_MI_TIME_SAVE
void mi_time_load(void);		// power-on: restore the clock saved in flash (0x7A000)
void mi_time_task(void);		// main loop: save the clock every 5 minutes
extern u32 mi_tlog_next;
#define MI_TIME_TASK_DUE()	(wrk.utc_time_sec >= mi_tlog_next)
#endif

#if (DEV_SERVICES & SERVICE_HISTORY)
extern u8 mi_hist_count_val[8];		// ebe0ccb9
extern u8 mi_hist_index_val[4];		// ebe0ccba
extern u8 mi_hist_read_val[14];		// ebe0ccbb
extern u16 mi_hist_ccc;
int mi_hist_count_read(void * p);
int mi_hist_index_write(void * p);
int mi_hist_index_read(void * p);
int mi_hist_read_read(void * p);
int mi_hist_ccc_write(void * p);
u8 mi_hist_busy(void);
void mi_hist_task(void);		// main loop: send next hourly record
#endif

void mi_auth_reset(void);		// on connect / disconnect
void mi_th_update(void);		// refresh ebe0ccc1/ebe0ccbe values
void mi_th_notify(void);		// refresh + notify ebe0ccc1 if enabled
u8 mi_auth_logged(void);

#endif // USE_MI_AUTH
#endif // _MI_AUTH_H_
