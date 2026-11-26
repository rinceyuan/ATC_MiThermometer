"""Xiaomi LYWSD02MMC (Clock / E-Ink Thermometer) firmware simulator for Windows.

Runs the real compiled firmware (lcd(), update_lcd(), utime_to_rtc(), WakeupLowPowerCb(),
check_battery(), mi_th_update(), mi_encrypt_data_beacon()) from ../out/LYWSD02MMC_v60.elf
using TC32->Thumb translation (tc32thumb.py) + Unicorn and draws the 16-byte E-Ink display.

  python lywsd02_sim.py                             GUI, firmware ../out/LYWSD02MMC_v60.elf
  python lywsd02_sim.py --selftest                  headless checks, screen decoded as text
  python lywsd02_sim.py --autoclose 3               GUI smoke test + layout check
  python lywsd02_sim.py --elf X.elf [--bin X.bin]   other LYWSD02MMC build
"""
import argparse
import datetime as dt
import os
import struct
import sys
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_EXEC, UC_PROT_ALL
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_SP, UC_ARM_REG_LR, \
    UC_ARM_REG_PC

from tc32thumb import Translator

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, '..'))
DEF_ELF = os.path.join(REPO, 'out', 'LYWSD02MMC_v60.elf')

FLASH, SRAM, REG, STOP = 0x0, 0x840000, 0x800000, 0x1ff000
STACK_TOP = 0x84ff00

# Packed struct offsets of LYWSD02MMC build (app.h / lcd.h / sensor.h / ble.h)
CFG_FLG, CFG_FLG2, CFG_FLG3, CFG_ADV_INT, CFG_MEAS_INT, CFG_LCD_STEP = 0, 1, 2, 4, 5, 8
MD_TEMP = 2
WRK_UTC, WRK_CONN = 0, 28
SENS_TIME_MEASURE = 26
LCDF_UPDATE_NEXT = 12  # lcd_flg.update_next_measure
ADVB_COUNT = 0
ADVB_DATA = {71: 12, 39: 11}

# cfg.flg bits for DEVICE_LYWSD02MMC
F_COMFORT = 0x04
F_SHOW_BAT = 0x08
F_FAHR = 0x10
F_AM_PM = 0x20
# cfg.flg2 bits
F2_SMILEY = 0x07
F2_CRYPTO = 0x08
F2_SCREEN_OFF = 0x80
# cfg.flg3 bits
F3_SHOW_DOW = 0x80

ENTRIES = ['lcd', 'update_lcd', 'WakeupLowPowerCb', 'check_battery', 'get_battery_level',
           'utime_to_rtc', 'mi_th_update', 'mi_beacon_init', 'mi_encrypt_data_beacon',
           'mi_time_write', 'mi_time_read']
STUBS = ['init_lcd', 'send_i2c_byte', 'send_i2c_buf', 'read_sensor_cb', 'get_adc_mv',
         'low_vbat', 'go_sleep', 'write_memo', 'bls_pm_setAppWakeupLowPower',
         '__divsi3', '__modsi3', '__udivsi3', '__umodsi3', 'aes_encrypt', 'flash_write_cfg', 'mi_time_set']
SCRATCH = 0x84e000  # SRAM buffer for ATT write packets

BINDKEY = bytes(range(0x10, 0x20))
MAC = bytes.fromhex('d5e76338c1a4')  # A4:C1:38:63:E7:D5 little-endian


class FwError(Exception):
    pass


class LYWSD02Firmware:
    def __init__(self, elf_path=DEF_ELF, bin_path=None):
        self.elf_path, self.bin_path = elf_path, bin_path
        if not os.path.isfile(elf_path):
            raise FwError(f'{elf_path} not found: build LYWSD02MMC_v60 first')
        elf = ELFFile(open(elf_path, 'rb'))
        self.sym = {s.name: (s['st_value'], s['st_size']) for s in elf.get_section_by_name('.symtab').iter_symbols()
                    if s.name}
        missing = [n for n in ('lcd', 'update_lcd', 'WakeupLowPowerCb', 'check_battery', 'display_buff', 'rtc',
                               'utime_to_rtc')
                   if n not in self.sym]
        if missing:
            raise FwError(f'{os.path.basename(elf_path)} is not an LYWSD02MMC build (missing {", ".join(missing)})')
        if self.sym['display_buff'][1] != 16:
            raise FwError(f'Expected 16-byte EPD display_buff, got {self.sym["display_buff"][1]}')

        secs = [s for s in elf.iter_sections() if s['sh_type'] == 'SHT_PROGBITS' and 0 < s['sh_size']
                and s['sh_addr'] < SRAM and s['sh_flags'] & 2]
        fw = bytearray(max(s['sh_addr'] + s['sh_size'] for s in secs))
        for s in secs:
            fw[s['sh_addr']:s['sh_addr'] + s['sh_size']] = s.data()
        if bin_path:
            if not os.path.isfile(bin_path):
                raise FwError(f'{bin_path} not found')
            img = open(bin_path, 'rb').read()
            for s in secs:
                if s.name in ('.ram_code', '.text', '.rodata') and \
                        img[s['sh_addr']:s['sh_addr'] + s['sh_size']] != s.data():
                    raise FwError(f'{os.path.basename(bin_path)} does not match {os.path.basename(elf_path)} '
                                  f'({s.name})')

        self.has_mi = 'mi_th_update' in self.sym
        self.has_beacon = 'mi_encrypt_data_beacon' in self.sym and 'mi_beacon_init' in self.sym
        text = elf.get_section_by_name('.text')
        code_end = text['sh_addr'] + text['sh_size']
        tr = Translator(bytes(fw), code_end, code_start=0x0)
        for n in ENTRIES:
            if n in self.sym:
                tr.walk(self.sym[n][0] & ~1)
        img = bytes(tr.image())

        uc = self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.mem_map(FLASH, 0x20000, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_write(FLASH, img[:0x20000])
        uc.mem_map(SRAM, 0x10000, UC_PROT_ALL)
        for s in elf.iter_sections():
            if s['sh_addr'] >= SRAM and s['sh_type'] == 'SHT_PROGBITS':
                uc.mem_write(s['sh_addr'], s.data())
        uc.mem_map(REG, 0x10000, UC_PROT_ALL)
        uc.mem_map(STOP, 0x1000, UC_PROT_ALL)
        for n in STUBS:
            if n in self.sym:
                a = self.sym[n][0] & ~1
                uc.hook_add(UC_HOOK_CODE, self._stub, user_data=n, begin=a, end=a)

        self.temp_x100, self.humi_x100, self.vbat_mv = 2519, 4620, 2950
        self.tz_hours = 8
        self.lcd_frames = 0
        self.sensor_reads = 0
        self.logger_records = 0
        self.low_vbat = False
        self.beacon = {}
        self.mi_time_sets = []

        # Power-on defaults
        self.write('cfg', 0, self.read('def_cfg', 0, self.sym['def_cfg'][1]))
        self.write('cmf', 0, self.read('def_cmf', 0, self.sym['def_cmf'][1]))
        self.write('mac_public', 0, MAC)
        if 'lcd_refresh_cnt' in self.sym:
            self.write('lcd_refresh_cnt', 0, struct.pack('<H', 2048))
        if 'mi_tz' in self.sym:
            self.write('mi_tz', 0, struct.pack('<bb', self.tz_hours, 0))
        if self.has_beacon:
            self.write('bindkey', 0, BINDKEY)
            self.call('mi_beacon_init')
            self.write32('adv_buf', ADVB_COUNT, 0x10000)

    def addr(self, name, off=0):
        return self.sym[name][0] + off

    def read(self, name, off, n):
        return bytes(self.uc.mem_read(self.addr(name, off), n))

    def write(self, name, off, data):
        self.uc.mem_write(self.addr(name, off), bytes(data))

    def read8(self, name, off=0):
        return self.read(name, off, 1)[0]

    def write8(self, name, off, v):
        self.write(name, off, bytes([v & 0xff]))

    def read32(self, name, off=0):
        return struct.unpack('<I', self.read(name, off, 4))[0]

    def write32(self, name, off, v):
        self.write(name, off, struct.pack('<I', v & 0xffffffff))

    def _ret(self, v=0):
        self.uc.reg_write(UC_ARM_REG_R0, v & 0xffffffff)
        self.uc.reg_write(UC_ARM_REG_PC, self.uc.reg_read(UC_ARM_REG_LR))

    def _stub(self, uc, address, size, name):
        r0, r1, r2 = (uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
        if name == 'read_sensor_cb':
            self.write('measured_data', MD_TEMP, struct.pack('<hH', self.temp_x100, self.humi_x100))
            self.sensor_reads += 1
            self._ret(1)
        elif name == 'get_adc_mv':
            self._ret(self.vbat_mv)
        elif name in ('low_vbat', 'go_sleep'):
            self.low_vbat = True
            self._ret(0)
        elif name == 'write_memo':
            self.logger_records += 1
            self._ret(0)
        elif name == 'mi_time_set':
            self.mi_time_sets.append(r0)
            self._ret(0)
        elif name in ('__udivsi3', '__umodsi3'):
            q, m = divmod(r0, r1) if r1 else (0xffffffff, r0)
            self._ret(q if name == '__udivsi3' else m)
        elif name in ('__divsi3', '__modsi3'):
            a = r0 - (1 << 32) if r0 & 0x80000000 else r0
            b = r1 - (1 << 32) if r1 & 0x80000000 else r1
            q = int(a / b) if b else -1
            self._ret(q if name == '__divsi3' else a - q * b)
        elif name == 'aes_encrypt':
            key, blk = bytes(uc.mem_read(r0, 16)), bytes(uc.mem_read(r1, 16))
            enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
            uc.mem_write(r2, enc.update(blk) + enc.finalize())
            self._ret(0)
        else:
            self._ret(0)

    def call(self, fn, *args):
        uc = self.uc
        for r, v in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2), args):
            uc.reg_write(r, v & 0xffffffff)
        uc.reg_write(UC_ARM_REG_SP, STACK_TOP)
        uc.reg_write(UC_ARM_REG_LR, STOP | 1)
        try:
            uc.emu_start(self.sym[fn][0] | 1, STOP, count=3_000_000)
        except UcError as e:
            raise FwError(f'{fn}: CPU fault {e} at {uc.reg_read(UC_ARM_REG_PC):#x}')
        if uc.reg_read(UC_ARM_REG_PC) & ~1 != STOP:
            raise FwError(f'{fn}: did not return (pc={uc.reg_read(UC_ARM_REG_PC):#x})')
        return uc.reg_read(UC_ARM_REG_R0)

    def set_inputs(self, temp_c=None, humi=None, vbat_mv=None):
        if temp_c is not None:
            self.temp_x100 = max(-32768, min(32767, int(round(temp_c * 100))))
        if humi is not None:
            self.humi_x100 = max(0, min(10000, int(round(humi * 100))))
        if vbat_mv is not None:
            self.vbat_mv = int(vbat_mv)

    def reset_battery_average(self):
        self.write('bat_average', 0, bytes(self.sym['bat_average'][1]))

    def set_clock(self, utc, tz_hours=None):
        if tz_hours is not None:
            self.tz_hours = int(tz_hours)
            if 'mi_tz' in self.sym:
                self.write('mi_tz', 0, struct.pack('<bb', self.tz_hours, 0))
        u = int(utc)
        self.write32('wrk', WRK_UTC, u)
        self.call('utime_to_rtc', u + self.tz_hours * 3600, self.addr('rtc'))

    def clock(self):
        return self.read32('wrk', WRK_UTC)

    def rtc_tuple(self):
        return struct.unpack('<7B', self.read('rtc', 0, 7))  # h, m, s, weekday, month, days, year

    def set_connected(self, on):
        v = self.read8('wrk', WRK_CONN)
        self.write8('wrk', WRK_CONN, (v | 1) if on else (v & ~1))

    def cfg_flags(self):
        return self.read8('cfg', CFG_FLG), self.read8('cfg', CFG_FLG2), self.read8('cfg', CFG_FLG3)

    def set_flag(self, idx, mask, on):
        off = (CFG_FLG, CFG_FLG2, CFG_FLG3)[idx]
        v = self.read8('cfg', off)
        self.write8('cfg', off, (v | mask) if on else (v & ~mask))

    def set_smiley(self, n):
        f2 = self.read8('cfg', CFG_FLG2)
        self.write8('cfg', CFG_FLG2, (f2 & ~F2_SMILEY) | (n & F2_SMILEY))

    def lcd_step_ms(self):
        return max(10, self.read8('cfg', CFG_LCD_STEP)) * 50

    def set_lcd_step_ms(self, ms):
        self.write8('cfg', CFG_LCD_STEP, max(10, min(255, int(round(ms / 50)))))

    def measure_interval_ms(self):
        return self.read8('cfg', CFG_ADV_INT) * self.read8('cfg', CFG_MEAS_INT) * 62.5

    def measure(self):
        self.call('check_battery')
        before = self.sensor_reads
        self.write32('sensor_cfg', SENS_TIME_MEASURE, 1)
        self.call('WakeupLowPowerCb', 0)
        if self.sensor_reads == before:
            raise FwError('WakeupLowPowerCb did not read the sensor')
        self.write32('adv_buf', ADVB_COUNT, self.read32('adv_buf', ADVB_COUNT) + 1)
        if self.has_beacon and (self.read8('cfg', CFG_FLG) & 3) == 2 and self.read8('cfg', CFG_FLG2) & F2_CRYPTO:
            self.call('mi_encrypt_data_beacon')
            self._decode_beacon()

    def lcd_step(self, force=True):
        """force: as SET_LCD_UPDATE() (clock minute, settings); False: update after a new measurement only."""
        self.write8('stage_lcd', 0, 0)
        if force:
            self.write8('lcd_flg', LCDF_UPDATE_NEXT, 0)
        self.call('lcd')
        self.call('update_lcd')
        if self.read8('stage_lcd', 0):
            self.lcd_frames += 1
            self.write8('stage_lcd', 0, 0)
        return self.display()

    def mi_time_write(self, data):
        """ATT write to ebe0ccb7; returns the UTC values passed to mi_time_set()."""
        pkt = bytearray(13 + len(data))  # rf_packet_att_data_t: l2cap at 6, dat at 13
        struct.pack_into('<H', pkt, 6, len(data) + 3)
        pkt[13:] = data
        self.uc.mem_write(SCRATCH, bytes(pkt))
        self.mi_time_sets = []
        self.call('mi_time_write', SCRATCH)
        return self.mi_time_sets

    def mi_time_read(self):
        self.call('mi_time_read', 0)
        return self.read('mi_time_val', 0, 7)

    def display(self):
        return self.read('display_buff', 0, 16)

    def screen_off(self):
        return bool(self.read8('cfg', CFG_FLG2) & F2_SCREEN_OFF)

    def values(self):
        avg, temp, humi, _cnt, mv, t01, h01, h1, lvl = struct.unpack('<HhHHHhHBB', self.read('measured_data', 0, 16))
        c1 = None
        if self.has_mi:
            self.call('mi_th_update')
            c1 = self.read('mi_th_val', 0, 5)
        return {'avg_mv': avg, 'temp_x100': temp, 'humi_x100': humi, 'mv': mv, 'temp_x01': t01,
                'humi_x01': h01, 'humi_x1': h1, 'batt': lvl, 'c1': c1}

    def _decode_beacon(self):
        d = self.read('adv_buf', ADVB_DATA[self.sym['adv_buf'][1]], 31)
        if d[1] != 0x16 or d[2:4] != b'\x95\xfe':
            return
        v = d[4:1 + d[0]]
        fc, pid, cnt = struct.unpack_from('<HHB', v)
        p = 5 + (6 if fc & 0x10 else 0)
        body, ext, mic = v[p:-7], v[-7:-4], v[-4:]
        nonce = MAC + struct.pack('<H', pid) + bytes([cnt]) + ext
        try:
            pt = AESCCM(BINDKEY, tag_length=4).decrypt(nonce, body + mic, b'\x11')
        except Exception:
            return
        obj, n = struct.unpack_from('<HB', pt)
        raw = pt[3:3 + n]
        val = struct.unpack('<f', raw)[0] if obj in (0x4801, 0x4c01) and n == 4 else raw[0]
        self.beacon[obj] = (val, cnt | int.from_bytes(ext, 'little') << 8, fc, pid)


# ---------------------------------------------------------------------------------------------
#  EPD segment map (epd_lywsd02mmc.c): segments ordered a, b, c, d, e, f, g -> (byte, bit)
# ---------------------------------------------------------------------------------------------
S1 = [
    {'a': (6, 0), 'b': (6, 3), 'c': (6, 4), 'd': (6, 2), 'e': (5, 7), 'f': (5, 6), 'g': (6, 1)},
    {'a': (6, 7), 'b': (7, 2), 'c': (7, 3), 'd': (7, 1), 'e': (6, 6), 'f': (6, 5), 'g': (7, 0)},
    {'a': (8, 1), 'b': (8, 4), 'c': (8, 5), 'd': (8, 3), 'e': (8, 0), 'f': (7, 7), 'g': (8, 2)},
    {'a': (9, 0), 'b': (9, 3), 'c': (9, 4), 'd': (9, 2), 'e': (8, 7), 'f': (8, 6), 'g': (9, 1)},
    {'a': (9, 7), 'b': (10, 2), 'c': (10, 3), 'd': (10, 1), 'e': (9, 6), 'f': (9, 5), 'g': (10, 0)},
]
S2 = [
    {'a': (11, 4), 'b': (11, 7), 'c': (12, 0), 'd': (11, 6), 'e': (11, 3), 'f': (11, 2), 'g': (11, 5)},
    {'a': (12, 3), 'b': (12, 6), 'c': (12, 7), 'd': (12, 5), 'e': (12, 2), 'f': (12, 1), 'g': (12, 4)},
    {'a': (13, 2), 'b': (13, 5), 'c': (13, 6), 'd': (13, 4), 'e': (13, 1), 'f': (13, 0), 'g': (13, 3)},
]
S3 = [
    {'a': (0, 2), 'b': (0, 5), 'c': (0, 6), 'd': (0, 4), 'e': (0, 1), 'f': (0, 0), 'g': (0, 3)},
    {'a': (1, 1), 'b': (1, 4), 'c': (1, 5), 'd': (1, 3), 'e': (1, 0), 'f': (0, 7), 'g': (1, 2)},
]
S4 = [
    {'a': (2, 2), 'b': (2, 5), 'c': (2, 6), 'd': (2, 4), 'e': (2, 1), 'f': (2, 0), 'g': (2, 3)},
    {'a': (3, 1), 'b': (3, 4), 'c': (3, 5), 'd': (3, 3), 'e': (3, 0), 'f': (2, 7), 'g': (3, 2)},
    {'a': (4, 1), 'b': (4, 4), 'c': (4, 5), 'd': (4, 3), 'e': (4, 0), 'f': (3, 7), 'g': (4, 2)},
]

BIT_COLON_TOP, BIT_COLON_BOT, BIT_S1_DP = (7, 4), (7, 5), (7, 6)
BIT_S1_BAT, BIT_S1_BAT_FULL, BIT_S1_BLE = (10, 6), (10, 7), (11, 0)
BIT_S1_PCT, BIT_S1_DEG = (10, 4), (10, 5)
BIT_S2_ONE, BIT_S2_PCT = (11, 1), (13, 7)
BIT_S3_PCT = (1, 6)
BIT_S4_ONE, BIT_S4_DP, BIT_S4_C, BIT_S4_F = (1, 7), (3, 6), (4, 6), (4, 7)
BIT_SM_RING = (5, 0)
BIT_SM_HAPPY_M, BIT_SM_SAD_M, BIT_SM_SAD_E, BIT_SM_HAPPY_E1, BIT_SM_HAPPY_E2 = (5, 1), (5, 2), (5, 3), (5, 4), (5, 5)

SEVEN = {
    '0': 'abcdef', '1': 'bc', '2': 'abged', '3': 'abgcd', '4': 'fgbc', '5': 'afgcd', '6': 'afgedc', '7': 'abc',
    '8': 'abcdefg', '9': 'abcdfg', 'A': 'abcefg', 'b': 'fgecd', 'C': 'afed', 'd': 'bgecd', 'E': 'afged',
    'F': 'afge', 'H': 'fbgec', 'i': 'e', 'L': 'fed', 'o': 'gecd', 'U': 'bcdef', '-': 'g', ' ': ''
}


def on(buf, bb):
    return bool(buf[bb[0]] >> bb[1] & 1)


def digit_char(buf, segmap):
    segs = ''.join(s for s, bb in segmap.items() if on(buf, bb))
    for ch, pat in SEVEN.items():
        if sorted(pat) == sorted(segs):
            return ch
    return '?'


def decode(buf, screen_off=False):
    if screen_off:
        return '(screen off)'
    colon = ':' if (on(buf, BIT_COLON_TOP) and on(buf, BIT_COLON_BOT)) else ('.' if on(buf, BIT_S1_DP) else ' ')
    s1 = digit_char(buf, S1[0]) + digit_char(buf, S1[1]) + colon + digit_char(buf, S1[2]) + digit_char(buf, S1[3])
    s1_extra = digit_char(buf, S1[4]).strip()
    if on(buf, BIT_S1_DEG):
        s1_extra = '°' + s1_extra
    if on(buf, BIT_S1_PCT):
        s1_extra += '%'
    s2 = ('1' if on(buf, BIT_S2_ONE) else '') + ''.join(digit_char(buf, m) for m in S2) + ('%' if on(buf, BIT_S2_PCT) else '')
    s3 = ''.join(digit_char(buf, m) for m in S3) + ('%' if on(buf, BIT_S3_PCT) else '')
    s4 = ('1' if on(buf, BIT_S4_ONE) else '') + digit_char(buf, S4[0]) + digit_char(buf, S4[1]) + \
        ('.' if on(buf, BIT_S4_DP) else '') + digit_char(buf, S4[2]) + \
        ('°C' if on(buf, BIT_S4_C) else ('°F' if on(buf, BIT_S4_F) else ''))
    hap = on(buf, BIT_SM_HAPPY_M) and on(buf, BIT_SM_HAPPY_E1)
    sad = on(buf, BIT_SM_SAD_M) and on(buf, BIT_SM_SAD_E)
    face = {(0, 0): '   ', (1, 0): '^-^', (0, 1): '-^-', (1, 1): 'ooo'}[(hap, sad)]
    face = f'({face})' if on(buf, BIT_SM_RING) else f' {face} '
    syms = []
    if on(buf, BIT_S1_BLE):
        syms.append('BLE')
    if on(buf, BIT_S1_BAT):
        syms.append('BAT_FULL' if on(buf, BIT_S1_BAT_FULL) else 'BAT_LOW')
    parts = [f'CLK={s1}' + (f'[{s1_extra}]' if s1_extra else ''),
             f'T={s4.strip()}', f'H={s3.strip()}', f'S2={s2.strip()}', face]
    if syms:
        parts.append(' '.join(syms))
    return ' | '.join(parts)


# ---------------------------------------------------------------------------------------------
#  Headless self test
# ---------------------------------------------------------------------------------------------
def selftest(elf, binf):
    f = LYWSD02Firmware(elf, binf)
    f.set_clock(1795593600, tz_hours=8)  # 2026-11-25 16:00:00 UTC+8 (Wednesday = 3)
    ok = True

    def show(title, expect=None):
        nonlocal ok
        f.measure()
        txt = decode(f.lcd_step(), f.screen_off())
        good = expect is None or all(e in txt for e in expect)
        ok &= good
        print(f'  [{"OK" if good else "FAIL"}] {title:<40} {txt}')
        return txt

    print(f'firmware: {f.elf_path}' + (f' (= {f.bin_path})' if f.bin_path else ''))
    show('25.19C 46.2% 16:00 UTC+8', expect=['CLK=16:00', 'T=25.2°C', 'H=46%', 'S2=1125', '(^-^)'])
    f.set_flag(2, F3_SHOW_DOW, True)
    show('show day-of-week (Wed=3)', expect=['CLK=16:00[3]'])
    f.set_flag(0, F_AM_PM, True)
    show('12h AM/PM (16:00 -> 04:00, Wed=3)', expect=['CLK=04:00[3]'])
    f.set_flag(0, F_AM_PM, False)
    f.set_flag(2, F3_SHOW_DOW, False)
    for t, e in ((25.15, 'T=25.2°C'), (-3.45, 'T=-3.5°C'), (-12.5, 'T=-13°C')):
        f.set_inputs(temp_c=t)
        show(f'temperature {t} C', expect=[e])
    f.set_inputs(temp_c=25.19, humi=46.2)
    show('forced update (clock minute) 25.19 C 46.2%', expect=['T=25.2°C', 'H=46%'])

    def show_meas(title, expect):
        nonlocal ok
        f.measure()
        frames = f.lcd_frames
        txt = decode(f.lcd_step(force=False), f.screen_off())
        good = all(e in txt for e in expect)
        ok &= good
        print(f'  [{"OK" if good else "FAIL"}] {title:<40} {txt}  (EPD refresh: {f.lcd_frames - frames})')
    f.set_inputs(temp_c=25.59, humi=48.2)
    show_meas('measurement +0.4 C +2%: wait for minute', expect=['T=25.2°C', 'H=46%'])
    f.set_inputs(temp_c=25.79)
    show_meas('measurement +0.6 C: shown at once', expect=['T=25.8°C', 'H=48%'])
    f.set_inputs(temp_c=25.79, humi=51.2)
    show_meas('measurement +3%: shown at once', expect=['T=25.8°C', 'H=51%'])
    f.set_inputs(temp_c=25.19, humi=46.2)
    f.set_flag(0, F_FAHR, True)
    show('Fahrenheit (25.19 C -> 77.4 F)', expect=['T=77.4°F'])
    f.set_flag(0, F_FAHR, False)
    f.set_flag(0, F_SHOW_BAT, True)
    show('show battery in S2 (2950 mV -> 100%)', expect=['S2=100%', 'BAT_FULL'])
    f.set_inputs(vbat_mv=2350)
    f.reset_battery_average()
    show('low battery (2350 mV -> 8%)', expect=['S2=8%', 'BAT_LOW'])
    f.set_flag(0, F_SHOW_BAT, False)
    f.set_inputs(vbat_mv=2412)
    f.reset_battery_average()
    if 'BAT' in show('no low battery icon above 10% (2412 mV -> 14%)'):
        print('  [FAIL] battery icon shown above LOW_BATTERY_LEVEL')
        ok = False
    f.set_inputs(vbat_mv=2950)
    f.reset_battery_average()
    f.set_connected(True)
    show('BLE connected', expect=['BLE'])
    f.set_connected(False)

    if 'mi_time_write' in f.sym:
        # ebe0ccb7 as the original 2.0.1_0021 firmware
        ts = 1795593600
        u = struct.pack('<I', ts)

        def tcase(title, data, set_ok, tz=None, mode=None):
            nonlocal ok
            sets = f.mi_time_write(data)
            r = f.mi_time_read()
            good = (sets == [ts]) == set_ok
            if tz is not None:
                good &= struct.unpack('<bb', r[4:6]) == tz
            if mode is not None:
                good &= r[6] == mode
            ok &= good
            print(f'  [{"OK" if good else "FAIL"}] {title:<40} set={bool(sets)} read={r.hex(" ")}')
        tcase('time 6 B: UTC-3:30', u + bytes([0xfd, 0xfe]), True, tz=(-3, -2))
        tcase('time 6 B: +5 h -2 q -> stored +4:30', u + bytes([5, 0xfe]), True, tz=(4, 2))
        tcase('time 5 B: +24 h -> 0 (mod 24)', u + bytes([24]), True, tz=(0, 0))
        tcase('time 6 B: invalid tz 25 h -> ignored', u + bytes([25, 0]), False, tz=(0, 0))
        tcase('time 5 B: UTC+8', u + bytes([8]), True, tz=(8, 0))
        tcase('time 7 B: 0xAA -> 12h, time not set', u + bytes([8, 0, 0xaa]), False, mode=0xaa)
        tcase('time 7 B: 0x00 -> 24h', u + bytes([8, 0, 0]), False, mode=0)
        tcase('time 8 B: ignored', u + bytes([8, 0, 0, 0]), False, tz=(8, 0))

    v = f.values()
    if v['c1'] is not None:
        print(f'  MiHome ebe0ccc1: {v["c1"].hex()}  (temp {int.from_bytes(v["c1"][:2], "little", signed=True)/100:.2f}C, '
              f'humi {v["c1"][2]}%, {int.from_bytes(v["c1"][3:], "little")} mV)')
    for _ in range(3):
        f.measure()
    if f.has_beacon:
        if 0x4c01 not in f.beacon or 0x4c02 not in f.beacon or 0x4803 not in f.beacon:
            print('  [FAIL] missing decrypted MiBeacon spec objects (expected 0x4c01/0x4c02/0x4803)')
            ok = False
        else:
            dec = {hex(k): (round(val, 2) if isinstance(val, float) else val, hex(pid))
                   for k, (val, _cnt, _fc, pid) in f.beacon.items()}
            print('  MiBeacon (decrypted):', dec)
            ok &= abs(f.beacon[0x4c01][0] - 25.2) < 0.01 and f.beacon[0x4c02][0] == 46 and f.beacon[0x4c01][3] == 0x2542
    print('RESULT:', 'PASS' if ok else 'FAIL')
    return ok


# ---------------------------------------------------------------------------------------------
#  GUI (E-Ink display)
# ---------------------------------------------------------------------------------------------
def run_gui(elf, binf, autoclose=0):
    import tkinter as tk
    from tkinter import ttk, messagebox

    # E-Ink paper palette
    BG, LIT, GHOST, FRAME = '#e8e7e0', '#181918', '#dcdbd3', '#cfcec6'
    try:
        fw = LYWSD02Firmware(elf, binf)
    except Exception as e:
        tk.Tk().withdraw()
        messagebox.showerror('LYWSD02MMC simulator', f'Cannot load firmware:\n{e}')
        return False

    root = tk.Tk()
    root.title('小米电子温湿度计 Pro 固件模拟器 — LYWSD02MMC (运行真实固件代码)')
    root.resizable(False, False)

    W, H = 720, 420
    cv = tk.Canvas(root, width=W, height=H, bg='#d8d8d4', highlightthickness=0)
    cv.grid(row=0, column=0, rowspan=2, padx=10, pady=10, sticky='n')
    cv.create_rectangle(14, 14, W - 14, H - 14, fill=FRAME, outline='#8a8a84', width=3)
    cv.create_rectangle(28, 28, W - 28, H - 28, fill=BG, outline='#b8b7b0', width=1)
    # Horizontal divider line like real LYWSD02MMC E-Ink panel
    cv.create_line(42, 232, W - 42, 232, fill='#b8b7b0', width=2)

    items = {}

    def add(bb, item, mode='fill'):
        items.setdefault(bb, []).append((item, mode))

    def hseg(x1, x2, y, t):
        h = t / 2
        return [x1, y, x1 + h, y - h, x2 - h, y - h, x2, y, x2 - h, y + h, x1 + h, y + h]

    def vseg(x, y1, y2, t):
        h = t / 2
        return [x, y1, x + h, y1 + h, x + h, y2 - h, x, y2, x - h, y2 - h, x - h, y1 + h]

    def digit(segmap, x, y, w, h, t):
        g = t * 0.55
        m = y + h / 2
        shapes = {
            'a': hseg(x + g, x + w - g, y, t),
            'g': hseg(x + g, x + w - g, m, t),
            'd': hseg(x + g, x + w - g, y + h, t),
            'f': vseg(x, y + g, m - g, t),
            'e': vseg(x, m + g, y + h - g, t),
            'b': vseg(x + w, y + g, m - g, t),
            'c': vseg(x + w, m + g, y + h - g, t),
        }
        for s, pts in shapes.items():
            add(segmap[s], cv.create_polygon(pts, outline=''))

    # --- Top row (S1): Clock HH:MM + 5th digit + BLE + Battery ---
    TY, TH, TW, TT = 56, 150, 78, 14
    digit(S1[0], 56, TY, TW, TH, TT)
    digit(S1[1], 162, TY, TW, TH, TT)
    add(BIT_COLON_TOP, cv.create_oval(260, TY + 40, 274, TY + 54, outline=''))
    add(BIT_COLON_BOT, cv.create_oval(260, TY + 96, 274, TY + 110, outline=''))
    add(BIT_S1_DP, cv.create_oval(260, TY + TH - 12, 274, TY + TH + 2, outline=''))
    digit(S1[2], 294, TY, TW, TH, TT)
    digit(S1[3], 400, TY, TW, TH, TT)
    # Top-right status icons: battery, BLE, %, °, S1[4]
    add(BIT_S1_BAT, cv.create_rectangle(526, 46, 566, 66, width=3), 'outline')
    add(BIT_S1_BAT, cv.create_rectangle(566, 51, 571, 61, width=0))
    add(BIT_S1_BAT_FULL, cv.create_rectangle(531, 51, 561, 61, width=0))
    add(BIT_S1_BLE, cv.create_text(608, 56, text='BT', font=('Segoe UI', 14, 'bold')))
    add(BIT_S1_PCT, cv.create_text(644, 82, text='%', font=('Segoe UI', 16, 'bold')))
    add(BIT_S1_DEG, cv.create_oval(524, 118, 536, 130, width=3, outline=''), 'outline')
    digit(S1[4], 552, 120, 48, 86, 9)

    # --- Bottom-left (S4): Temperature (-9.9 .. 199.9 °C/°F) ---
    BY, BH, BW, BT = 264, 96, 48, 10
    for (y1, y2) in ((BY + 6, BY + BH / 2 - 6), (BY + BH / 2 + 6, BY + BH - 6)):
        add(BIT_S4_ONE, cv.create_polygon(vseg(48, y1, y2, BT), outline=''))
    digit(S4[0], 68, BY, BW, BH, BT)
    digit(S4[1], 136, BY, BW, BH, BT)
    add(BIT_S4_DP, cv.create_oval(196, BY + BH - 8, 208, BY + BH + 4, outline=''))
    digit(S4[2], 218, BY, BW, BH, BT)
    add(BIT_S4_F, cv.create_text(294, BY + 20, text='°F', font=('Segoe UI', 16, 'bold')))
    add(BIT_S4_C, cv.create_text(294, BY + 76, text='°C', font=('Segoe UI', 16, 'bold')))

    # --- Bottom-center: Smiley face ---
    SX, SY = 374, 312
    add(BIT_SM_RING, cv.create_oval(SX - 40, SY - 40, SX + 40, SY + 40, width=4, outline=''), 'outline')
    add(BIT_SM_HAPPY_E1, cv.create_line(SX - 22, SY - 8, SX - 14, SY - 20, SX - 6, SY - 8, width=4))
    add(BIT_SM_HAPPY_E2, cv.create_line(SX + 6, SY - 8, SX + 14, SY - 20, SX + 22, SY - 8, width=4))
    add(BIT_SM_SAD_E, cv.create_line(SX - 22, SY - 12, SX - 6, SY - 12, width=4))
    add(BIT_SM_SAD_E, cv.create_line(SX + 6, SY - 12, SX + 22, SY - 12, width=4))
    add(BIT_SM_HAPPY_M, cv.create_arc(SX - 18, SY - 4, SX + 18, SY + 24, start=200, extent=140, style='arc', width=4), 'outline')
    add(BIT_SM_SAD_M, cv.create_arc(SX - 18, SY + 6, SX + 18, SY + 34, start=20, extent=140, style='arc', width=4), 'outline')

    # --- Bottom-right (S3): Humidity % ---
    digit(S3[0], 440, BY, BW, BH, BT)
    digit(S3[1], 508, BY, BW, BH, BT)
    add(BIT_S3_PCT, cv.create_text(584, BY + 76, text='%', font=('Segoe UI', 22, 'bold')))

    # --- Auxiliary (S2): Date MMDD or Battery % ---
    S2Y, S2H, S2W, S2T = 328, 34, 18, 4
    add(BIT_S2_ONE, cv.create_line(604, S2Y + 3, 604, S2Y + S2H - 3, width=3))
    digit(S2[0], 612, S2Y, S2W, S2H, S2T)
    digit(S2[1], 636, S2Y, S2W, S2H, S2T)
    digit(S2[2], 660, S2Y, S2W, S2H, S2T)
    add(BIT_S2_PCT, cv.create_text(672, S2Y - 14, text='%', font=('Segoe UI', 10, 'bold')))

    show_ghost = tk.BooleanVar(value=True)

    def paint(buf, off):
        for (byte, bit), ids in items.items():
            lit = not off and bool(buf[byte] >> bit & 1)
            col = LIT if lit else (GHOST if show_ghost.get() else BG)
            for i, mode in ids:
                cv.itemconfigure(i, **{mode: col})

    # ---------------- Controls ----------------
    panel = ttk.Frame(root)
    panel.grid(row=0, column=1, padx=(0, 10), pady=10, sticky='n')

    v_temp = tk.DoubleVar(value=25.19)
    v_humi = tk.DoubleVar(value=46.2)
    v_vbat = tk.IntVar(value=2950)
    v_conn = tk.BooleanVar(value=False)
    v_tz = tk.IntVar(value=8)
    v_offs = tk.IntVar(value=0)
    v_run = tk.BooleanVar(value=True)
    v_now = tk.BooleanVar(value=True)
    f0, f20, f30 = fw.cfg_flags()
    v_f = tk.BooleanVar(value=bool(f0 & F_FAHR))
    v_cmf = tk.BooleanVar(value=bool(f0 & F_COMFORT))
    v_bat = tk.BooleanVar(value=bool(f0 & F_SHOW_BAT))
    v_ampm = tk.BooleanVar(value=bool(f0 & F_AM_PM))
    v_dow = tk.BooleanVar(value=bool(f30 & F3_SHOW_DOW))
    v_off = tk.BooleanVar(value=bool(f20 & F2_SCREEN_OFF))
    v_sm = tk.IntVar(value=f20 & 7)
    v_rst = tk.BooleanVar(value=True)

    def row(parent, r, text, widget):
        ttk.Label(parent, text=text).grid(row=r, column=0, sticky='w', padx=4, pady=2)
        widget.grid(row=r, column=1, sticky='we', padx=4, pady=2)

    g1 = ttk.LabelFrame(panel, text='传感器 / 电池（模拟硬件输入）')
    g1.grid(row=0, column=0, sticky='we', pady=4)
    row(g1, 0, '温度 ℃', ttk.Spinbox(g1, from_=-40, to=125, increment=0.01, textvariable=v_temp, width=10,
                                      command=lambda: changed()))
    ttk.Scale(g1, from_=-20, to=60, variable=v_temp, length=240,
              command=lambda _v: (v_temp.set(round(v_temp.get(), 2)), changed())).grid(row=1, column=0, columnspan=2)
    row(g1, 2, '湿度 %', ttk.Spinbox(g1, from_=0, to=100, increment=0.01, textvariable=v_humi, width=10,
                                      command=lambda: changed()))
    ttk.Scale(g1, from_=0, to=100, variable=v_humi, length=240,
              command=lambda _v: (v_humi.set(round(v_humi.get(), 2)), changed())).grid(row=3, column=0, columnspan=2)
    row(g1, 4, '电池电压 mV', ttk.Spinbox(g1, from_=1800, to=3400, increment=10, textvariable=v_vbat, width=10,
                                        command=lambda: changed()))
    ttk.Scale(g1, from_=2000, to=3300, variable=v_vbat, length=240,
              command=lambda _v: (v_vbat.set(int(float(v_vbat.get()))), changed())).grid(row=5, column=0, columnspan=2)
    ttk.Checkbutton(g1, text='改动后立即测量', variable=v_now).grid(row=6, column=0, sticky='w', padx=4)
    ttk.Checkbutton(g1, text='改电压重置电池平均', variable=v_rst).grid(row=6, column=1, sticky='w', padx=4)

    g2 = ttk.LabelFrame(panel, text='显示设置（LYWSD02MMC）')
    g2.grid(row=1, column=0, sticky='we', pady=4)
    for i, (txt, var) in enumerate((('华氏度 ℉', v_f), ('舒适度笑脸', v_cmf), ('S2 显示电量%', v_bat),
                                    ('12 小时制', v_ampm), ('显示星期 (S1右)', v_dow), ('关闭屏幕', v_off))):
        ttk.Checkbutton(g2, text=txt, variable=var, command=lambda: settings()).grid(
            row=i // 2, column=i % 2, sticky='w', padx=4)
    row(g2, 3, '固定笑脸 0-7', ttk.Spinbox(g2, from_=0, to=7, textvariable=v_sm, width=6, command=lambda: settings()))

    g3 = ttk.LabelFrame(panel, text='连接 / 时钟 / 运行')
    g3.grid(row=2, column=0, sticky='we', pady=4)
    ttk.Checkbutton(g3, text='蓝牙已连接', variable=v_conn, command=lambda: changed(measure=False)).grid(
        row=0, column=0, sticky='w', padx=4)
    ttk.Checkbutton(g3, text='运行', variable=v_run).grid(row=0, column=1, sticky='w', padx=4)
    row(g3, 1, '时区 (UTC+h)', ttk.Spinbox(g3, from_=-12, to=14, increment=1, textvariable=v_tz, width=8,
                                          command=lambda: changed(measure=False)))
    row(g3, 2, '时钟偏移(分)', ttk.Spinbox(g3, from_=-100000, to=100000, increment=1, textvariable=v_offs, width=8,
                                          command=lambda: changed(measure=False)))
    btns = ttk.Frame(g3)
    btns.grid(row=3, column=0, columnspan=2, pady=2)
    ttk.Button(btns, text='立即测量', command=lambda: changed(force=True)).grid(row=0, column=0, padx=2)
    ttk.Checkbutton(btns, text='显示未点亮段', variable=show_ghost, command=lambda: redraw()).grid(row=0, column=1)

    info = tk.StringVar()
    ttk.Label(panel, textvariable=info, justify='left', font=('Consolas', 9)).grid(row=3, column=0, sticky='w')
    ttk.Label(root, text=f'固件: {fw.elf_path}', foreground='#666').grid(row=2, column=0, columnspan=2,
                                                                           sticky='w', padx=10, pady=(0, 6))

    state = {'t_lcd': time.monotonic(), 't_meas': time.monotonic()}

    def guard(fn):
        try:
            fn()
        except FwError as e:
            v_run.set(False)
            messagebox.showerror('固件执行错误', str(e))

    def push_inputs():
        try:
            mv = int(float(v_vbat.get()))
            if mv != fw.vbat_mv and v_rst.get():
                fw.reset_battery_average()
            fw.set_inputs(float(v_temp.get()), float(v_humi.get()), mv)
        except (tk.TclError, ValueError):
            pass
        fw.set_connected(v_conn.get())
        try:
            tz = int(v_tz.get())
            offs = int(v_offs.get())
        except (tk.TclError, ValueError):
            tz, offs = 8, 0
        fw.set_clock(time.time() + offs * 60, tz_hours=tz)

    def changed(measure=True, force=False):
        def go():
            push_inputs()
            if force or (measure and v_now.get()):
                fw.measure()
                state['t_meas'] = time.monotonic()
            fw.lcd_step()
            redraw()
        guard(go)

    def settings():
        fw.set_flag(0, F_FAHR, v_f.get())
        fw.set_flag(0, F_COMFORT, v_cmf.get())
        fw.set_flag(0, F_SHOW_BAT, v_bat.get())
        fw.set_flag(0, F_AM_PM, v_ampm.get())
        fw.set_flag(2, F3_SHOW_DOW, v_dow.get())
        fw.set_flag(1, F2_SCREEN_OFF, v_off.get())
        try:
            fw.set_smiley(int(v_sm.get()))
        except (tk.TclError, ValueError):
            pass
        changed(measure=False)

    def redraw():
        buf = fw.display()
        paint(buf, fw.screen_off())
        v = fw.values()
        c1 = v['c1']
        bc = fw.beacon
        bt = f'{bc[0x4c01][0]:.1f}℃' if 0x4c01 in bc else '-'
        bh = f'{bc[0x4c02][0]}%' if 0x4c02 in bc else '-'
        bb = f'{bc[0x4803][0]}%' if 0x4803 in bc else '-'
        h, m, s, wd, mo, dy, yr = fw.rtc_tuple()
        info.set(
            f'固件内部值（真实固件代码计算）\n'
            f'  EPD 字节   {buf[:8].hex(" ")}\n'
            f'             {buf[8:].hex(" ")}\n'
            f'  温度 x0.1  {v["temp_x01"]}    湿度 {v["humi_x1"]}%\n'
            f'  电池       {v["mv"]} mV (平均 {v["avg_mv"]}) → {v["batt"]}%'
            f'{"  低电压!" if fw.low_vbat else ""}\n'
            f'  RTC 本地   20{yr:02d}-{mo:02d}-{dy:02d} {h:02d}:{m:02d}:{s:02d} (周{wd})\n'
            + (f'米家读取 ebe0ccc1: {c1.hex(" ")}\n'
               f'  = {int.from_bytes(c1[:2], "little", signed=True) / 100:.2f}℃  {c1[2]}%  '
               f'{int.from_bytes(c1[3:], "little")} mV\n' if c1 is not None else '米家读取: (此固件无米家服务)\n')
            + (f'网关加密广播 (PID 0x2542):\n  温度 {bt}  湿度 {bh}  电量 {bb}\n' if fw.has_beacon else '')
            + f'测量 {fw.sensor_reads} 次  记录 {fw.logger_records} 条  刷屏 {fw.lcd_frames} 次')

    def tick():
        if v_run.get():
            now = time.monotonic()

            def go():
                push_inputs()
                if (now - state['t_meas']) * 1000 >= fw.measure_interval_ms():
                    state['t_meas'] = now
                    fw.measure()
                    state['measured'] = True  # wrk.msc.b.update_lcd
                # as main_loop(): the clock minute forces an update (SET_LCD_UPDATE), otherwise only after a new
                # measurement, or every lcd step while the firmware keeps lcd_flg.update_next_measure = 0
                minute = fw.clock() // 60
                if minute != state.get('minute'):
                    state['minute'] = minute
                    state['t_lcd'] = now
                    fw.lcd_step(force=True)
                elif (now - state['t_lcd']) * 1000 >= fw.lcd_step_ms() and (
                        state.get('measured') or not fw.read8('lcd_flg', LCDF_UPDATE_NEXT)):
                    state['t_lcd'] = now
                    state['measured'] = False
                    fw.lcd_step(force=False)
                redraw()
            guard(go)
        root.after(200, tick)

    errors = []

    def report(exc, val, tb):
        import traceback
        errors.append(''.join(traceback.format_exception(exc, val, tb)))
        print(errors[-1], file=sys.stderr)
    root.report_callback_exception = report

    guard(lambda: (push_inputs(), fw.measure(), fw.lcd_step(), redraw()))
    root.after(200, tick)

    if autoclose:
        script = [
            lambda: (v_temp.set(-12.34), changed()),
            lambda: (v_f.set(True), settings()),
            lambda: (v_f.set(False), v_dow.set(True), settings()),
            lambda: (v_ampm.set(True), settings()),
            lambda: (v_vbat.set(2350), v_bat.set(True), changed()),
            lambda: (v_conn.set(True), changed(measure=False)),
            lambda: (v_off.set(True), settings()),
            lambda: (v_off.set(False), settings()),
            lambda: (show_ghost.set(False), redraw()),
        ]
        for i, act in enumerate(script):
            root.after(250 + i * 150, act)
        root.after(int(autoclose * 1000), root.destroy)

        root.update_idletasks()
        boxes = [(bb, cv.bbox(i)) for bb, ids in items.items() for i, _m in ids]
        outside = [bb for bb, b in boxes if b[0] < 28 or b[1] < 28 or b[2] > W - 28 or b[3] > H - 28]
        smiley_bits = {BIT_SM_RING, BIT_SM_HAPPY_M, BIT_SM_SAD_M, BIT_SM_SAD_E, BIT_SM_HAPPY_E1, BIT_SM_HAPPY_E2}
        bat_bits = {BIT_S1_BAT, BIT_S1_BAT_FULL}
        overlap = set()
        for i, (b1, r1) in enumerate(boxes):
            for b2, r2 in boxes[i + 1:]:
                if b1 == b2 or (b1 in smiley_bits and b2 in smiley_bits) or (b1 in bat_bits and b2 in bat_bits):
                    continue
                ix = min(r1[2], r2[2]) - max(r1[0], r2[0])
                iy = min(r1[3], r2[3]) - max(r1[1], r2[1])
                if ix > 3 and iy > 3:
                    overlap.add(tuple(sorted((b1, b2))))
        print(f'layout: {len(items)} EPD bits, {len(boxes)} shapes, outside glass {outside}, overlaps {sorted(overlap)}')
        if outside or overlap:
            errors.append('layout')

    root.mainloop()
    if autoclose:
        print(f'GUI smoke test: {fw.lcd_frames} EPD frames, {fw.sensor_reads} measurements, '
              f'last screen "{decode(fw.display())}", {len(errors)} errors')
        return not errors
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--elf', default=DEF_ELF, help='firmware ELF with symbols (default: %(default)s)')
    ap.add_argument('--bin', default=None, help='optional OTA image of the same build, compared with the ELF')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--autoclose', type=float, default=0, help='GUI smoke test: close after N seconds')
    a = ap.parse_args()
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    if a.selftest:
        try:
            sys.exit(0 if selftest(a.elf, a.bin) else 1)
        except FwError as e:
            print(f'ERROR: {e}')
            sys.exit(2)
    sys.exit(0 if run_gui(a.elf, a.bin, a.autoclose) else 1)


if __name__ == '__main__':
    main()
