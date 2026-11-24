# MJWSD06MMC firmware simulator (Windows)

A desktop simulator of the Xiaomi Thermometer 3 mini (MJWSD06MMC) that runs the **real compiled firmware
code** of this repository and draws its LCD segment by segment.

The firmware is not re-implemented. The TC32 machine code from the build ELF is translated to ARMv4T Thumb
(`tc32thumb.py`; TC32 is Thumb-1 with remapped opcode high bytes) and executed with
[Unicorn](https://www.unicorn-engine.org/). Only the hardware is replaced:

| Firmware part | In the simulator |
|---|---|
| `lcd()`, `show_*()`, display stages, comfort smiley, clock, °C/°F | real firmware code |
| measurement cycle `WakeupLowPowerCb()`: rounding, logger call, beacon averaging | real firmware code |
| `check_battery()`: 512-sample running average, battery % curve, low-battery icon | real firmware code |
| MiHome value `ebe0ccc1` (`mi_th_update`), encrypted MiBeacon (`mi_encrypt_data_beacon`) | real firmware code (MiHome build) |
| sensor `read_sensor_cb()`, battery ADC `get_adc_mv()` | values from the GUI |
| LCD driver `send_to_lcd()`, I2C, GPIO, sleep, logger flash write | captured / ignored |
| hardware divider, hardware AES | computed in Python |

The display refresh (`min_step_time_update_lcd`, 2.45 s by default) and the measurement interval
(20 s by default) follow the firmware configuration.

## Requirements

- Windows with Python 3.10+ (tkinter is included in the python.org installer)
- `pip install unicorn capstone pyelftools cryptography`
- the firmware ELF with symbols: build the firmware first (`make` / `MakeAll.cmd`), which writes
  `out/MJ6_v60_mesh.elf`. Released `.bin` files alone cannot be used (no symbols).

## Usage

```
run_sim.cmd                                  (or: python mini3_sim.py)
python mini3_sim.py --elf ..\out\MJ6_v60_mesh.elf --bin ..\bin\MJ6_v60_mesh.bin
python mini3_sim.py --selftest
```

- `--elf` selects another MJWSD06MMC build of this repository (the structure offsets in `fwcore.py`
  are those of this source tree). Builds without the MiHome features (`USE_MI_AUTH=0`) also run; the
  MiHome value and beacon panels are then hidden.
- `--bin` optionally checks that an OTA image is the same build as the ELF.
- `--selftest` runs headless checks and prints the decoded screen as text, e.g.
  `-3.45 C -> -3.5°C`, `2350 mV -> 8% + battery icon`, clock / temperature alternation.
  It is also part of the verification of the MiHome build.
- `--autoclose N` drives the GUI controls, checks the segment layout and closes after N seconds.

## Window

- **LCD**: big digits with the "1" and decimal point, °C/°F, BLE, battery, "/+", smiley, small digits
  and "%", drawn from `display_buff` with the segment map of `src/lcd_mjwsd06mmc.c`. Unlit segments
  can be shown faintly.
- **Inputs**: temperature, humidity, battery voltage. "Reset battery average" emulates inserting a
  battery; without it the firmware's 512-sample running average (about 2.8 hours on the device) applies.
- **Display settings** (as in TelinkMiFlasher): Fahrenheit, comfort smiley, always show battery,
  clock (UTC in the MiHome build), screen off, fixed smiley, refresh interval.
- **Connection / run**: BLE connected (BLE symbol), clock offset, pause, next display stage, measure now.
- **Internal values**: LCD bytes and decoded text, temperature x0.1, humidity, battery mV / average / %,
  device clock, the MiHome `ebe0ccc1` value and the MiBeacon objects decrypted with the simulator key.

Not simulated: BLE advertising / connections, MiHome login, history transfer, OTA. Those parts are
covered by the emulator tests of the MiHome build.
