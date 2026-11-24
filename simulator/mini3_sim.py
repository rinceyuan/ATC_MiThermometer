"""Xiaomi MJWSD06MMC (Thermometer 3 mini) firmware simulator for Windows.

Runs the real compiled firmware (lcd(), measurement, battery %, MiHome value, encrypted MiBeacon)
with fwcore.Firmware and draws the LCD segments of display_buff.

  python mini3_sim.py                       GUI, firmware ../out/MJ6_v60_mesh.elf
  python mini3_sim.py --selftest            headless checks, screen decoded as text
  python mini3_sim.py --elf X.elf [--bin X.bin]   other build (the OTA image is only compared with the ELF)
"""
import argparse
import datetime as dt
import sys
import time

from fwcore import Firmware, FwError, F_COMFORT, F_CLOCK, F_FAHR, F_BATT, F2_SCREEN_OFF, DEF_ELF

# ---------------------------------------------------------------------------------------------
#  LCD segment map (lcd_mjwsd06mmc.c): (byte, bit)
# ---------------------------------------------------------------------------------------------
BIG = {'a': 4, 'f': 0, 'b': 5, 'g': 1, 'e': 2, 'c': 6, 'd': 7}    # big digits in bytes 5, 4, 3
SMALL = {'a': 7, 'f': 3, 'b': 6, 'g': 2, 'e': 1, 'c': 5, 'd': 4}  # small digits in bytes 1, 0
BIT_ONE, BIT_DP, BIT_BLE = (5, 3), (3, 3), (4, 3)
BIT_BAT, BIT_PLUS, BIT_PCT, BIT_PAREN = (2, 0), (2, 5), (0, 0), (1, 0)
BIT_DEG, BIT_MID, BIT_LOW = (2, 2), (2, 1), (2, 3)                # "°Г", "-", "_"
BIT_HAPPY, BIT_SAD = (2, 4), (2, 7)                               # " ^_^ " eyes+mouth, " -^- "

SEVEN = {  # segments a..g of characters
    '0': 'abcdef', '1': 'bc', '2': 'abged', '3': 'abgcd', '4': 'fgbc', '5': 'afgcd', '6': 'afgedc', '7': 'abc',
    '8': 'abcdefg', '9': 'abcdfg', 'A': 'abcefg', 'b': 'fgecd', 'C': 'afed', 'd': 'bgecd', 'E': 'afged',
    'F': 'afge', 'H': 'fbgec', 'h': 'fgec', 'i': 'c', 'L': 'fed', 'o': 'gecd', 't': 'fged', 'a': 'abgecd',
    'P': 'abfge', '-': 'g', ' ': ''}


def on(buf, bb):
    return bool(buf[bb[0]] >> bb[1] & 1)


def digit_char(byte, segmap, ignore=()):
    segs = ''.join(s for s, bit in segmap.items() if byte >> bit & 1 and bit not in ignore)
    for ch, pat in SEVEN.items():
        if sorted(pat) == sorted(segs):
            return ch
    return '?'


def decode(buf, screen_off=False):
    """display_buff -> readable text"""
    if screen_off:
        return '(screen off)'
    big = ('1' if on(buf, BIT_ONE) else '') + digit_char(buf[5], BIG, (3,)) + digit_char(buf[4], BIG, (3,)) + \
        ('.' if on(buf, BIT_DP) else '') + digit_char(buf[3], BIG, (3,))
    unit = {(1, 0, 1): '°C', (1, 1, 0): '°F', (1, 0, 0): '°Г', (0, 0, 0): ''}.get(
        (on(buf, BIT_DEG), on(buf, BIT_MID), on(buf, BIT_LOW)), '?')
    small = digit_char(buf[1], SMALL, (0,)) + digit_char(buf[0], SMALL, (0,)) + ('%' if on(buf, BIT_PCT) else '')
    face = {(0, 0): '   ', (1, 0): '^_^', (0, 1): '-^-', (1, 1): 'ooo'}[(on(buf, BIT_HAPPY), on(buf, BIT_SAD))]
    face = f'({face})' if on(buf, BIT_PAREN) else f' {face} '
    syms = [n for n, b in (('BLE', BIT_BLE), ('BAT', BIT_BAT), ('/+', BIT_PLUS)) if on(buf, b)]
    return f'{big.strip():>6}{unit:<2} {face} {small.strip():>4}  {" ".join(syms)}'.rstrip()


# ---------------------------------------------------------------------------------------------
#  headless self test
# ---------------------------------------------------------------------------------------------
def selftest(elf, binf):
    f = Firmware(elf, binf)
    f.set_clock(1795450000)  # 2026-11-23 16:06:40 UTC
    ok = True

    def show(title, stages=1, settle=1, expect=None):
        nonlocal ok
        for _ in range(settle):
            f.measure()
        texts = [decode(f.lcd_step(i > 0), f.screen_off()) for i in range(stages)]
        good = expect is None or all(e is None or e in t for e, t in zip(expect, texts))
        ok &= good
        print(f'  [{"OK" if good else "FAIL"}] {title:<44} ' + ' | '.join(texts))
        return texts

    print(f'firmware: {f.elf_path}' + (f' (= {f.bin_path})' if f.bin_path else ''))
    f.set_flag(False, F_COMFORT, False)
    f.set_smiley(0)
    show('25.19 C 46.2 %', expect=['25.2°C', ])
    for t, e in ((25.15, '25.2°C'), (25.14, '25.1°C'), (-3.44, '-3.4°C'), (-3.45, '-3.5°C'), (-12.34, '-12°C'),
                 (-12.5, '-13°C'), (199.94, '199.9°C')):
        f.set_inputs(temp_c=t)
        show(f'temperature {t} C', expect=[e])
    f.set_inputs(temp_c=25.19, humi=46.2)
    f.set_flag(False, F_FAHR, True)
    show('Fahrenheit (25.19 C)', expect=['77.3°F'])
    f.set_flag(False, F_FAHR, False)
    f.set_inputs(vbat_mv=2350)
    f.reset_battery_average()
    show('battery 2350 mV (<=10%: battery shown)', stages=2, expect=[None, ' 8%  BAT'])
    v = f.values()
    ok &= v['batt'] == 8
    print(f'         battery level {v["batt"]}% (curve: 2300->5, 2400->10)')
    f.set_inputs(vbat_mv=2780)
    f.reset_battery_average()
    show('battery 2780 mV (100%: humidity only)', stages=2, expect=['46%', '46%'])
    f.set_flag(False, F_BATT, True)
    show('show battery on', stages=2, expect=[None, '99%  BAT'])
    f.set_flag(False, F_BATT, False)
    f.set_flag(False, F_COMFORT, True)
    show('comfort smiley', stages=1)
    f.set_flag(False, F_CLOCK, True)
    texts = show('clock on (UTC 16:06, alternates with temperature)', stages=4)
    clk = any(t.split()[:2] == ['16', '06'] for t in texts) and any('25.2°C' in t for t in texts)
    ok &= clk
    print(f'         clock stage 16:06 and temperature stage both shown: {clk}')
    f.set_flag(False, F_CLOCK, False)
    f.set_connected(True)
    show('BLE connected', expect=['BLE'])
    f.set_connected(False)
    v = f.values()
    if v['c1'] is not None:
        print(f'  MiHome ebe0ccc1: {v["c1"].hex()}  (temp x0.01 '
              f'{int.from_bytes(v["c1"][:2], "little", signed=True)}, humi {v["c1"][2]} %, '
              f'{int.from_bytes(v["c1"][3:], "little")} mV)')
    for _ in range(3):
        f.measure()
    if 0x4801 in f.beacon:
        print('  MiBeacon (decrypted):', {hex(k): (round(a, 2) if isinstance(a, float) else a)
                                         for k, (a, c, fc) in f.beacon.items()})
        ok &= abs(f.beacon[0x4801][0] - 25.2) < 0.01 and f.beacon[0x4802][0] == 46
    print('RESULT:', 'PASS' if ok else 'FAIL')
    return ok


# ---------------------------------------------------------------------------------------------
#  GUI
# ---------------------------------------------------------------------------------------------
def run_gui(elf, binf, autoclose=0):
    import tkinter as tk
    from tkinter import ttk, messagebox

    BG, LIT, GHOST, GLASS = '#c3cbb8', '#1b1d1a', '#b6bfab', '#8d9785'
    try:
        fw = Firmware(elf, binf)
    except Exception as e:  # noqa: BLE001
        tk.Tk().withdraw()
        messagebox.showerror('MJWSD06MMC simulator', f'Cannot load firmware:\n{e}')
        return

    root = tk.Tk()
    root.title('温湿度计3 mini 固件模拟器 — MJWSD06MMC (运行真实固件代码)')
    root.resizable(False, False)

    W, H = 660, 380
    cv = tk.Canvas(root, width=W, height=H, bg='#e9ebe4', highlightthickness=0)
    cv.grid(row=0, column=0, rowspan=2, padx=10, pady=10, sticky='n')
    cv.create_rectangle(14, 14, W - 14, H - 14, fill=GLASS, outline='#6f7868', width=3)
    cv.create_rectangle(30, 30, W - 30, H - 30, fill=BG, outline='')
    items = {}  # (byte, bit) -> [(canvas item id, 'fill' | 'outline')]

    def add(bb, item, mode='fill'):
        items.setdefault(bb, []).append((item, mode))

    def skewed(pts, x0, y0, k=0.10):
        out = []
        for i in range(0, len(pts), 2):
            out += [pts[i] + k * (y0 - pts[i + 1]), pts[i + 1]]
        return out

    def hseg(x1, x2, y, t):
        h = t / 2
        return [x1, y, x1 + h, y - h, x2 - h, y - h, x2, y, x2 - h, y + h, x1 + h, y + h]

    def vseg(x, y1, y2, t):
        h = t / 2
        return [x, y1, x + h, y1 + h, x + h, y2 - h, x, y2, x - h, y2 - h, x - h, y1 + h]

    def digit(byte, segmap, x, y, w, h, t):
        g = t * 0.6
        m = y + h / 2
        shapes = {'a': hseg(x + g, x + w - g, y, t), 'g': hseg(x + g, x + w - g, m, t),
                  'd': hseg(x + g, x + w - g, y + h, t), 'f': vseg(x, y + g, m - g, t),
                  'e': vseg(x, m + g, y + h - g, t), 'b': vseg(x + w, y + g, m - g, t),
                  'c': vseg(x + w, m + g, y + h - g, t)}
        for s, pts in shapes.items():
            add((byte, segmap[s]), cv.create_polygon(skewed(pts, x, y + h), outline=''))

    # big digits: "1" (5.3), 5, 4, point (3.3), 3
    BY, BH, BW, BT = 72, 158, 80, 15
    for (y1, y2) in ((BY + 9, BY + BH / 2 - 9), (BY + BH / 2 + 9, BY + BH - 9)):
        add(BIT_ONE, cv.create_polygon(skewed(vseg(62, y1, y2, BT), 62, BY + BH), outline=''))
    digit(5, BIG, 92, BY, BW, BH, BT)
    digit(4, BIG, 205, BY, BW, BH, BT)
    add(BIT_DP, cv.create_oval(306, BY + BH - 9, 324, BY + BH + 9, outline=''))
    digit(3, BIG, 340, BY, BW, BH, BT)
    # unit block: "°" + "Г" (2.2), middle bar (2.1), bottom bar (2.3)
    UX, UY, UW, UH, UT = 478, 86, 48, 104, 11
    add(BIT_DEG, cv.create_oval(450, UY - 6, 468, UY + 12, width=5, outline=''), 'outline')
    add(BIT_DEG, cv.create_polygon(hseg(UX + 6, UX + UW, UY, UT), outline=''))
    add(BIT_DEG, cv.create_polygon(vseg(UX, UY + 6, UY + UH / 2 - 6, UT), outline=''))
    add(BIT_DEG, cv.create_polygon(vseg(UX, UY + UH / 2 + 6, UY + UH - 6, UT), outline=''))
    add(BIT_MID, cv.create_polygon(hseg(UX + 6, UX + UW, UY + UH / 2, UT), outline=''))
    add(BIT_LOW, cv.create_polygon(hseg(UX + 6, UX + UW, UY + UH, UT), outline=''))
    # top symbols: BLE "OO" (4.3), "/+" (2.5), battery (2.0)
    add(BIT_BLE, cv.create_oval(240, 36, 260, 56, width=5, outline=''), 'outline')
    add(BIT_BLE, cv.create_oval(256, 36, 276, 56, width=5, outline=''), 'outline')
    add(BIT_PLUS, cv.create_line(512, 60, 524, 38, width=4))
    add(BIT_PLUS, cv.create_line(530, 49, 550, 49, width=4))
    add(BIT_PLUS, cv.create_line(540, 39, 540, 59, width=4))
    add(BIT_BAT, cv.create_rectangle(568, 38, 612, 60, width=4), 'outline')
    add(BIT_BAT, cv.create_rectangle(612, 44, 618, 54, width=0))
    # smiley: "(" ")" (1.0), " ^_^ " (2.4), " -^- " (2.7)
    SY = 300
    add(BIT_PAREN, cv.create_arc(60, SY - 40, 110, SY + 40, start=110, extent=140, style='arc', width=5), 'outline')
    add(BIT_PAREN, cv.create_arc(240, SY - 40, 290, SY + 40, start=-70, extent=140, style='arc', width=5),
        'outline')
    for ex in (125, 215):
        add(BIT_HAPPY, cv.create_line(ex - 16, SY - 14, ex, SY - 30, ex + 16, SY - 14, width=5))  # "^" eye
        add(BIT_SAD, cv.create_line(ex - 16, SY - 8, ex + 16, SY - 8, width=5))                  # "_" eye
    add(BIT_SAD, cv.create_line(155, SY + 18, 170, SY + 4, 185, SY + 18, width=5))              # "^" mouth
    add(BIT_HAPPY, cv.create_line(150, SY + 28, 190, SY + 28, width=5))                         # "_" mouth
    # small digits 1, 0 and "%" (0.0)
    digit(1, SMALL, 392, 268, 40, 74, 9)
    digit(0, SMALL, 458, 268, 40, 74, 9)
    add(BIT_PCT, cv.create_oval(522, 270, 538, 286, width=4, outline=''), 'outline')
    add(BIT_PCT, cv.create_line(548, 268, 520, 342, width=4))
    add(BIT_PCT, cv.create_oval(532, 324, 548, 340, width=4, outline=''), 'outline')

    show_ghost = tk.BooleanVar(value=True)

    def paint(buf, off):
        for (byte, bit), ids in items.items():
            lit = not off and bool(buf[byte] >> bit & 1)
            col = LIT if lit else (GHOST if show_ghost.get() else BG)
            for i, mode in ids:
                cv.itemconfigure(i, **{mode: col})

    # ---------------- controls ----------------
    panel = ttk.Frame(root)
    panel.grid(row=0, column=1, padx=(0, 10), pady=10, sticky='n')

    v_temp = tk.DoubleVar(value=25.19)
    v_humi = tk.DoubleVar(value=46.2)
    v_vbat = tk.IntVar(value=2780)
    v_conn = tk.BooleanVar(value=False)
    v_offs = tk.IntVar(value=0)
    v_run = tk.BooleanVar(value=True)
    v_now = tk.BooleanVar(value=True)
    f0, f20 = fw.cfg_flags()
    v_f = tk.BooleanVar(value=bool(f0 & F_FAHR))
    v_cmf = tk.BooleanVar(value=bool(f0 & F_COMFORT))
    v_bat = tk.BooleanVar(value=bool(f0 & F_BATT))
    v_clk = tk.BooleanVar(value=bool(f0 & F_CLOCK))
    v_off = tk.BooleanVar(value=bool(f20 & F2_SCREEN_OFF))
    v_sm = tk.IntVar(value=f20 & 7)
    v_step = tk.DoubleVar(value=fw.lcd_step_ms() / 1000)

    def row(parent, r, text, widget):
        ttk.Label(parent, text=text).grid(row=r, column=0, sticky='w', padx=4, pady=2)
        widget.grid(row=r, column=1, sticky='we', padx=4, pady=2)

    g1 = ttk.LabelFrame(panel, text='传感器 / 电池（模拟硬件输入）')
    g1.grid(row=0, column=0, sticky='we', pady=4)
    row(g1, 0, '温度 ℃', ttk.Spinbox(g1, from_=-40, to=125, increment=0.01, textvariable=v_temp, width=10,
                                      command=lambda: changed()))
    ttk.Scale(g1, from_=-20, to=60, variable=v_temp, length=230,
              command=lambda _v: (v_temp.set(round(v_temp.get(), 2)), changed())).grid(row=1, column=0, columnspan=2)
    row(g1, 2, '湿度 %', ttk.Spinbox(g1, from_=0, to=100, increment=0.01, textvariable=v_humi, width=10,
                                      command=lambda: changed()))
    ttk.Scale(g1, from_=0, to=100, variable=v_humi, length=230,
              command=lambda _v: (v_humi.set(round(v_humi.get(), 2)), changed())).grid(row=3, column=0, columnspan=2)
    row(g1, 4, '电池电压 mV', ttk.Spinbox(g1, from_=1800, to=3400, increment=10, textvariable=v_vbat, width=10,
                                        command=lambda: changed()))
    ttk.Scale(g1, from_=2000, to=3300, variable=v_vbat, length=230,
              command=lambda _v: (v_vbat.set(int(float(v_vbat.get()))), changed())).grid(row=5, column=0, columnspan=2)
    ttk.Checkbutton(g1, text='改动后立即测量（否则按固件测量周期）', variable=v_now).grid(
        row=6, column=0, columnspan=2, sticky='w', padx=4)
    v_rst = tk.BooleanVar(value=True)
    ttk.Checkbutton(g1, text='电压改动后重置电池平均（相当于刚装电池；\n不勾选 = 固件真实的 512 次滑动平均）',
                    variable=v_rst).grid(row=7, column=0, columnspan=2, sticky='w', padx=4)

    g2 = ttk.LabelFrame(panel, text='显示设置（对应刷机网页的设置）')
    g2.grid(row=1, column=0, sticky='we', pady=4)
    for i, (txt, var) in enumerate((('华氏度 ℉', v_f), ('舒适度笑脸', v_cmf), ('总是显示电量', v_bat),
                                    ('显示时钟（UTC）', v_clk), ('关闭屏幕', v_off))):
        ttk.Checkbutton(g2, text=txt, variable=var, command=lambda: settings()).grid(
            row=i // 2, column=i % 2, sticky='w', padx=4)
    row(g2, 3, '固定笑脸 0-7', ttk.Spinbox(g2, from_=0, to=7, textvariable=v_sm, width=6, command=lambda: settings()))
    row(g2, 4, '屏幕刷新间隔 s', ttk.Spinbox(g2, from_=0.5, to=12.75, increment=0.05, textvariable=v_step, width=6,
                                       command=lambda: settings()))

    g3 = ttk.LabelFrame(panel, text='连接 / 时钟 / 运行')
    g3.grid(row=2, column=0, sticky='we', pady=4)
    ttk.Checkbutton(g3, text='蓝牙已连接', variable=v_conn, command=lambda: changed(measure=False)).grid(
        row=0, column=0, sticky='w', padx=4)
    ttk.Checkbutton(g3, text='运行', variable=v_run).grid(row=0, column=1, sticky='w', padx=4)
    row(g3, 1, '时钟偏移（分钟）', ttk.Spinbox(g3, from_=-100000, to=100000, increment=1, textvariable=v_offs,
                                       width=8))
    btns = ttk.Frame(g3)
    btns.grid(row=2, column=0, columnspan=2, pady=2)
    ttk.Button(btns, text='下一显示阶段', command=lambda: step(True)).grid(row=0, column=0, padx=2)
    ttk.Button(btns, text='立即测量', command=lambda: changed(force=True)).grid(row=0, column=1, padx=2)
    ttk.Checkbutton(btns, text='显示未点亮段', variable=show_ghost, command=lambda: redraw()).grid(row=0, column=2)

    info = tk.StringVar()
    ttk.Label(panel, textvariable=info, justify='left', font=('Consolas', 9)).grid(row=3, column=0, sticky='w')
    ttk.Label(root, text=f'固件: {fw.elf_path}', foreground='#666').grid(row=2, column=0, columnspan=2,
                                                                           sticky='w', padx=10, pady=(0, 6))

    state = {'t_lcd': time.monotonic(), 't_meas': time.monotonic(), 'buf': None}

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
            fw.set_clock(time.time() + int(v_offs.get()) * 60)
        except (tk.TclError, ValueError):
            fw.set_clock(time.time())

    def step(advance):
        def go():
            push_inputs()
            fw.lcd_step(advance)
            state['t_lcd'] = time.monotonic()
            redraw()
        guard(go)

    def changed(measure=True, force=False):
        def go():
            push_inputs()
            if force or (measure and v_now.get()):
                fw.measure()
                state['t_meas'] = time.monotonic()
            fw.lcd_step(False)
            redraw()
        guard(go)

    def settings():
        fw.set_flag(False, F_FAHR, v_f.get())
        fw.set_flag(False, F_COMFORT, v_cmf.get())
        fw.set_flag(False, F_BATT, v_bat.get())
        fw.set_flag(False, F_CLOCK, v_clk.get())
        fw.set_flag(True, F2_SCREEN_OFF, v_off.get())
        try:
            fw.set_smiley(int(v_sm.get()))
            fw.set_lcd_step_ms(float(v_step.get()) * 1000)
        except (tk.TclError, ValueError):
            pass
        changed(measure=False)

    def redraw():
        buf = fw.display()
        paint(buf, fw.screen_off())
        v = fw.values()
        c1 = v['c1']
        bc = fw.beacon
        bt = f'{bc[0x4801][0]:.1f}℃' if 0x4801 in bc else '-'
        bh = f'{bc[0x4802][0]}%' if 0x4802 in bc else '-'
        bb = f'{bc[0x4c03][0]}%' if 0x4c03 in bc else '-'
        clk = dt.datetime.fromtimestamp(fw.clock(), dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        info.set(
            f'固件内部值（真实固件代码计算）\n'
            f'  屏幕字节   {buf.hex(" ")}   阶段 {fw.stage()}\n'
            f'  屏幕内容   {decode(buf, fw.screen_off()).strip()}\n'
            f'  温度 x0.1  {v["temp_x01"]}    湿度 {v["humi_x1"]}%\n'
            f'  电池       {v["mv"]} mV (平均 {v["avg_mv"]}) → {v["batt"]}%'
            f'{"  低电压!" if fw.low_vbat else ""}\n'
            f'  设备时钟   {clk} UTC\n'
            + (f'米家读取 ebe0ccc1: {c1.hex(" ")}\n'
               f'  = {int.from_bytes(c1[:2], "little", signed=True) / 100:.2f}℃  {c1[2]}%  '
               f'{int.from_bytes(c1[3:], "little")} mV\n' if c1 is not None else '米家读取: (此固件无米家服务)\n')
            + (f'网关收到的加密广播（模拟密钥解密）:\n  温度 {bt}  湿度 {bh}  电量 {bb}\n' if fw.has_beacon else '')
            + f'测量 {fw.sensor_reads} 次  记录 {fw.logger_records} 条  刷屏 {fw.lcd_frames} 次')

    def tick():
        if v_run.get():
            now = time.monotonic()

            def go():
                push_inputs()
                if (now - state['t_meas']) * 1000 >= fw.measure_interval_ms():
                    state['t_meas'] = now
                    fw.measure()
                if (now - state['t_lcd']) * 1000 >= fw.lcd_step_ms():
                    state['t_lcd'] = now
                    fw.lcd_step(True)
                redraw()
            guard(go)
        root.after(200, tick)

    errors = []

    def report(exc, val, tb):
        import traceback
        errors.append(''.join(traceback.format_exception(exc, val, tb)))
        print(errors[-1], file=sys.stderr)
    root.report_callback_exception = report

    guard(lambda: (push_inputs(), fw.measure(), fw.lcd_step(False), redraw()))
    root.after(200, tick)
    if autoclose:  # GUI smoke test: drive the controls, then close
        script = [lambda: (v_temp.set(-12.34), changed()), lambda: (v_f.set(True), settings()),
                  lambda: (v_f.set(False), v_clk.set(True), settings()), lambda: step(True),
                  lambda: (v_vbat.set(2350), changed()), lambda: (v_bat.set(True), settings()),
                  lambda: (v_conn.set(True), changed(measure=False)), lambda: (v_off.set(True), settings()),
                  lambda: (v_off.set(False), settings()), lambda: (show_ghost.set(False), redraw())]
        for i, act in enumerate(script):
            root.after(300 + i * 150, act)
        root.after(int(autoclose * 1000), root.destroy)
    if autoclose:  # layout check: every segment inside the glass, segments of different bits do not overlap
        root.update_idletasks()
        boxes = [(bb, cv.bbox(i)) for bb, ids in items.items() for i, _m in ids]
        outside = [bb for bb, b in boxes if b[0] < 30 or b[1] < 30 or b[2] > W - 30 or b[3] > H - 30]
        overlap = set()
        for i, (b1, r1) in enumerate(boxes):
            for b2, r2 in boxes[i + 1:]:
                if b1 != b2 and {b1, b2} != {BIT_HAPPY, BIT_SAD}:  # smiley eyes / mouth share their place
                    ix = min(r1[2], r2[2]) - max(r1[0], r2[0])
                    iy = min(r1[3], r2[3]) - max(r1[1], r2[1])
                    if ix > 3 and iy > 3:
                        overlap.add(tuple(sorted((b1, b2))))
        print(f'layout: {len(items)} LCD bits, {len(boxes)} shapes, outside glass {outside}, overlaps {sorted(overlap)}')
        if outside or overlap:
            errors.append('layout')
    root.mainloop()
    if autoclose:
        print(f'GUI smoke test: {fw.lcd_frames} LCD frames, {fw.sensor_reads} measurements, '
              f'last screen "{decode(fw.display()).strip()}", {len(errors)} errors')
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
