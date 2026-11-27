"""Run the REAL compiled MJWSD06MMC firmware (TC32 code from the build ELF) on the PC.

TC32 is Thumb-1 with remapped opcode high bytes, so the reachable code is translated to ARMv4T Thumb
(tc32thumb.py) and executed with Unicorn. Only hardware is replaced:
  - temperature / humidity sensor (read_sensor_cb) and battery ADC (get_adc_mv) return the GUI values,
  - the LCD driver (send_to_lcd) captures display_buff, I2C / GPIO / sleep calls do nothing,
  - the hardware divider and AES block are computed in Python.
Display logic (lcd(), show_*), rounding, battery %, MiHome characteristic and MiBeacon are firmware code.
The structure offsets below are those of the MJWSD06MMC build of this repository (packed structs).
"""
import os
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_EXEC, UC_PROT_ALL
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_SP, UC_ARM_REG_LR, \
    UC_ARM_REG_PC

from tc32thumb import Translator

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, '..'))
DEF_ELF = os.path.join(REPO, 'out', 'MJ6_v60_mesh.elf')  # build output (make / MakeAll.cmd)

FLASH, SRAM, REG, STOP = 0x0, 0x840000, 0x800000, 0x1ff000
STACK_TOP = 0x84ff00

# structure offsets of this build (packed structs, app.h / lcd.h / sensor.h / ble.h)
CFG_FLG, CFG_FLG2, CFG_ADV_INT, CFG_MEAS_INT, CFG_LCD_STEP = 0, 1, 4, 5, 8
MD_TEMP = 2
WRK_UTC, WRK_CONN = 0, 28
LCDF_STAGE = 12
SENS_TIME_MEASURE = 26
ADVB_COUNT = 0
# adv_buf size -> offset of data[]: with SERVICE_LE_LR (ext_adv_init, 59-byte buffer) / without (28-byte buffer)
ADVB_DATA = {71: 12, 39: 11}

# cfg.flg bits
F_COMFORT, F_CLOCK, F_FAHR, F_BATT = 0x04, 0x08, 0x10, 0x20
# cfg.flg2 bits
F2_SMILEY, F2_CRYPTO, F2_SCREEN_OFF = 0x07, 0x08, 0x80

ENTRIES = ['lcd', 'update_lcd', 'WakeupLowPowerCb', 'check_battery', 'get_battery_level', 'mi_th_update',
           'mi_beacon_init', 'mi_encrypt_data_beacon']
STUBS = ['send_to_lcd', 'send_i2c_byte', 'send_i2c_buf', 'read_sensor_cb', 'get_adc_mv', 'low_vbat', 'go_sleep',
         'write_memo', 'set_trigger_out', 'bls_pm_setAppWakeupLowPower',
         '__divsi3', '__modsi3', '__udivsi3', '__umodsi3', 'aes_encrypt']

BINDKEY = bytes(range(0x10, 0x20))  # simulator key for the encrypted MiBeacon
MAC = bytes.fromhex('a72ca438c1a4')  # mac_public (little endian) of the simulated device


class FwError(Exception):
    pass


class Firmware:
    def __init__(self, elf_path=DEF_ELF, bin_path=None):
        """elf_path: firmware ELF with symbols; bin_path: optional OTA image, checked against the ELF"""
        self.elf_path, self.bin_path = elf_path, bin_path
        if not os.path.isfile(elf_path):
            raise FwError(f'{elf_path} not found: build the firmware first (make / MakeAll.cmd) or use --elf')
        elf = ELFFile(open(elf_path, 'rb'))
        self.sym = {s.name: (s['st_value'], s['st_size']) for s in elf.get_section_by_name('.symtab').iter_symbols()
                    if s.name}
        missing = [n for n in ('lcd', 'update_lcd', 'WakeupLowPowerCb', 'check_battery', 'display_buff')
                   if n not in self.sym]
        if missing:
            raise FwError(f'{os.path.basename(elf_path)} is not an MJWSD06MMC build of this repository '
                          f'(missing {", ".join(missing)})')
        # flash image = loadable sections below SRAM (as written by OTA)
        secs = [s for s in elf.iter_sections() if s['sh_type'] == 'SHT_PROGBITS' and 0 < s['sh_size']
                and s['sh_addr'] < SRAM and s['sh_flags'] & 2]  # SHF_ALLOC
        fw = bytearray(max(s['sh_addr'] + s['sh_size'] for s in secs))
        for s in secs:
            fw[s['sh_addr']:s['sh_addr'] + s['sh_size']] = s.data()
        if bin_path:  # code and constants must be identical (the header in .vectors is patched by the build)
            if not os.path.isfile(bin_path):
                raise FwError(f'{bin_path} not found')
            img = open(bin_path, 'rb').read()
            for s in secs:
                if s.name in ('.ram_code', '.text', '.rodata') and \
                        img[s['sh_addr']:s['sh_addr'] + s['sh_size']] != s.data():
                    raise FwError(f'{os.path.basename(bin_path)} does not match {os.path.basename(elf_path)} '
                                  f'({s.name})')
        self.has_mi = 'mi_th_update' in self.sym  # MiHome build (USE_MI_AUTH)
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
        self.image_size = len(fw)
        uc.mem_map(SRAM, 0x10000, UC_PROT_ALL)
        for s in elf.iter_sections():
            if s['sh_addr'] >= SRAM and s['sh_type'] == 'SHT_PROGBITS':
                uc.mem_write(s['sh_addr'], s.data())
        uc.mem_map(REG, 0x10000, UC_PROT_ALL)  # MMIO: GPIO / analog writes are harmless here
        uc.mem_map(STOP, 0x1000, UC_PROT_ALL)
        for n in STUBS:
            if n in self.sym:
                a = self.sym[n][0] & ~1
                uc.hook_add(UC_HOOK_CODE, self._stub, user_data=n, begin=a, end=a)

        # inputs (as the hardware would deliver them)
        self.temp_x100, self.humi_x100, self.vbat_mv = 2519, 4620, 2780
        self.lcd_frames = 0
        self.sensor_reads = 0
        self.logger_records = 0
        self.low_vbat = False
        self.beacon = {}  # object id -> (value, counter, frame control)

        # power-on state: config / comfort defaults of the firmware, Mi beacon
        self.write('cfg', 0, self.read('def_cfg', 0, self.sym['def_cfg'][1]))
        self.write('cmf', 0, self.read('def_cmf', 0, self.sym['def_cmf'][1]))
        self.write('mac_public', 0, MAC)
        self.has_tz = 'mi_tz' in self.sym  # MiHome build: LCD clock = UTC clock + timezone
        if self.has_tz:
            self.set_tz(8, 0)  # power-on default of mi_time_load() (EEP_ID_MTZ not written)
        if self.has_beacon:
            self.write('bindkey', 0, BINDKEY)
            self.call('mi_beacon_init')
            self.write32('adv_buf', ADVB_COUNT, 0x10000)

    # ---------------- memory helpers ----------------
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

    # ---------------- execution ----------------
    def _ret(self, v=0):
        self.uc.reg_write(UC_ARM_REG_R0, v & 0xffffffff)
        self.uc.reg_write(UC_ARM_REG_PC, self.uc.reg_read(UC_ARM_REG_LR))

    def _stub(self, uc, address, size, name):
        r0, r1, r2 = (uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
        if name == 'read_sensor_cb':  # sensor delivers calibrated temperature / humidity (x0.01)
            self.write('measured_data', MD_TEMP, struct.pack('<hH', self.temp_x100, self.humi_x100))
            self.sensor_reads += 1
            self._ret(1)
        elif name == 'get_adc_mv':
            self._ret(self.vbat_mv)
        elif name == 'send_to_lcd':
            self.lcd_frames += 1
            self._ret(0)
        elif name in ('low_vbat', 'go_sleep'):
            self.low_vbat = True
            self._ret(0)
        elif name == 'write_memo':
            self.logger_records += 1
            self._ret(0)
        elif name in ('__udivsi3', '__umodsi3'):
            q, m = divmod(r0, r1) if r1 else (0xffffffff, r0)
            self._ret(q if name == '__udivsi3' else m)
        elif name in ('__divsi3', '__modsi3'):
            a = r0 - (1 << 32) if r0 & 0x80000000 else r0
            b = r1 - (1 << 32) if r1 & 0x80000000 else r1
            q = int(a / b) if b else -1
            self._ret(q if name == '__divsi3' else a - q * b)
        elif name == 'aes_encrypt':  # (key, in, out) TLSR8258 hardware AES-128
            key, blk = bytes(uc.mem_read(r0, 16)), bytes(uc.mem_read(r1, 16))
            enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
            uc.mem_write(r2, enc.update(blk) + enc.finalize())
            self._ret(0)
        else:  # I2C, GPIO trigger output, sleep timer: no hardware
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

    # ---------------- device behaviour ----------------
    def set_inputs(self, temp_c=None, humi=None, vbat_mv=None):
        if temp_c is not None:
            self.temp_x100 = max(-32768, min(32767, int(round(temp_c * 100))))
        if humi is not None:
            self.humi_x100 = max(0, min(10000, int(round(humi * 100))))
        if vbat_mv is not None:
            self.vbat_mv = int(vbat_mv)

    def reset_battery_average(self):
        """as after inserting a battery (RAM cleared): the next measurement starts a new running average
        (the firmware averages 512 measurements, about 2.8 hours at 20 s)"""
        self.write('bat_average', 0, bytes(self.sym['bat_average'][1]))

    def set_clock(self, utc):
        self.write32('wrk', WRK_UTC, int(utc))

    def set_tz(self, hours, quarters=0):
        self.write('mi_tz', 0, bytes([hours & 0xff, quarters & 0xff]))

    def tz_offset(self):
        if not self.has_tz:
            return 0
        h, q = (b - 256 if b > 127 else b for b in self.read('mi_tz', 0, 2))
        return (h * 60 + q * 15) * 60

    def clock(self):
        return self.read32('wrk', WRK_UTC)

    def set_connected(self, on):
        v = self.read8('wrk', WRK_CONN)
        self.write8('wrk', WRK_CONN, (v | 1) if on else (v & ~1))

    def cfg_flags(self):
        return self.read8('cfg', CFG_FLG), self.read8('cfg', CFG_FLG2)

    def set_flag(self, flg2, mask, on):
        off = CFG_FLG2 if flg2 else CFG_FLG
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
        """one measurement cycle as the firmware: battery ADC, sensor read + rounding, logger, beacon data"""
        self.call('check_battery')
        before = self.sensor_reads
        self.write32('sensor_cfg', SENS_TIME_MEASURE, 1)
        self.call('WakeupLowPowerCb', 0)
        if self.sensor_reads == before:
            raise FwError('WakeupLowPowerCb did not read the sensor (sensor_cfg layout differs from this build)')
        self.write32('adv_buf', ADVB_COUNT, self.read32('adv_buf', ADVB_COUNT) + 1)
        if self.has_beacon and (self.read8('cfg', CFG_FLG) & 3) == 2 and self.read8('cfg', CFG_FLG2) & F2_CRYPTO:
            self.call('mi_encrypt_data_beacon')  # Mi advertising, encrypted: one object per measurement
            self._decode_beacon()

    def lcd_step(self, advance=True):
        """one display refresh of the main loop: next stage, lcd(), update_lcd()"""
        if advance:
            self.write8('lcd_flg', LCDF_STAGE, self.read8('lcd_flg', LCDF_STAGE) + 1)
        self.call('lcd')
        self.call('update_lcd')
        return self.display()

    def display(self):
        return self.read('display_buff', 0, 6)

    def screen_off(self):
        return bool(self.read8('cfg', CFG_FLG2) & F2_SCREEN_OFF)

    def stage(self):
        return self.read8('lcd_flg', LCDF_STAGE)

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
        v = d[4:1 + d[0]]  # service data after the 0xFE95 UUID
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
        val = struct.unpack('<f', raw)[0] if obj == 0x4801 else raw[0]
        self.beacon[obj] = (val, cnt | int.from_bytes(ext, 'little') << 8, fc)
