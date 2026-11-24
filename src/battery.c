#include "tl_common.h"
#include "drivers.h"
#include "stack/ble/ble.h"

#include "battery.h"

#ifndef ADC_BAT_VREF_MV
#define ADC_BAT_VREF_MV		1175 // default ADC ref voltage (unit:mV)
#endif

u8 adc_hw_initialized = 0;
u32 adc_average;

#define ADC_BUF_COUNT	8

// Process takes about 120 μs at CPU CLK 24Mhz.
_attribute_ram_code_
static void adc_channel_init(ADC_InputPchTypeDef p_ain) {
	adc_power_on_sar_adc(0);
	//adc_reset_adc_module(); // reset whole digital adc module
	//dfifo_disable_dfifo2(); // disable misc channel data dfifo
	adc_set_sample_clk(5);
	//adc_enable_clk_24m_to_sar_adc(1); // enable signal of 24M clock to sar adc
	adc_set_left_right_gain_bias(GAIN_STAGE_BIAS_PER100, GAIN_STAGE_BIAS_PER100);
	adc_set_chn_enable_and_max_state_cnt(ADC_MISC_CHN, 2);
	adc_set_state_length(240, 0, 10);
	analog_write(anareg_adc_res_m, RES14 | FLD_ADC_EN_DIFF_CHN_M);
	adc_set_ain_chn_misc(p_ain, GND);
	adc_set_ref_voltage(ADC_MISC_CHN, ADC_VREF_1P2V);
	adc_set_tsample_cycle_chn_misc(SAMPLING_CYCLES_6);
	adc_set_ain_pre_scaler(ADC_PRESCALER_1F8);
}

// Process takes about 260 μs at CPU CLK 24Mhz.
_attribute_ram_code_
u16 get_adc_mv(u32 p_ain) { // ADC_InputPchTypeDef
	volatile unsigned int adc_dat_buf[ADC_BUF_COUNT];
	u16 adc_sample[ADC_BUF_COUNT]; // = { 0 };
	u16 temp;
	u16 rp = 0;
	int i, j;
	if (adc_hw_initialized != p_ain) {
		adc_hw_initialized = p_ain;
#if 0 // gpio set in app_config.h
		if(p_ain == SHL_ADC_VBAT) {
			// Set missing pin on case TLSR8251F512ET24/TLSR8253F512ET32
			gpio_set_output_en(GPIO_VBAT, 1);
			gpio_set_input_en(GPIO_VBAT, 0);
			gpio_write(GPIO_VBAT, 1);
		}
#endif
		adc_channel_init(p_ain);
	}
	adc_power_on_sar_adc(1); // + 0.4 mA
	adc_reset_adc_module();
	for (i = 0; i < ADC_BUF_COUNT; i++) {
		adc_dat_buf[i] = 0;
	}
	adc_config_misc_channel_buf((u16 *) adc_dat_buf, sizeof(adc_dat_buf));
	dfifo_enable_dfifo2();
	for (i = 0; i < ADC_BUF_COUNT; i++) {
		while(rp == reg_dfifo2_wptr);
		rp = reg_dfifo2_wptr; // 0,4,8,c,10,14,18,1c
		if (adc_dat_buf[i] & BIT(13)) {
			/* 14 bit resolution, BIT(13) is sign bit,
			 * 1 means negative voltage in differential_mode  */
			adc_sample[i] = 0;
		} else {
			adc_sample[i] = ((u16) adc_dat_buf[i] & 0x1FFF);
		}
		if (i) {
			if (adc_sample[i] < adc_sample[i - 1]) {
				temp = adc_sample[i];
				adc_sample[i] = adc_sample[i - 1];
				for (j = i - 1; j >= 0 && adc_sample[j] > temp; j--) {
					adc_sample[j + 1] = adc_sample[j];
				}
				adc_sample[j + 1] = temp;
			}
		}
	}
	dfifo_disable_dfifo2();
	adc_power_on_sar_adc(0); // - 0.4 mA
	adc_average = (adc_sample[2] + adc_sample[3] + adc_sample[4]
				+ adc_sample[5]);
#if (DEV_SERVICES & SERVICE_PLM)
	if(p_ain != SHL_ADC_VBAT) {
		return adc_average;
	} else
#endif
	return (adc_average * ADC_BAT_VREF_MV) >> 12; // adc_vref default: 1175 (mV)
}

#define VBAT2LEVEL_SHL		(32-8) // max level = 256
#define VBAT2LEVEL_COEF	    ((100 << VBAT2LEVEL_SHL)/(MAX_VBAT_MV - MIN_VBAT_MV))

#if USE_MI_BATTERY_CURVE
/* Above 2700 mV 100% as the original Xiaomi MJWSD06MMC firmware 2.1.1_0009 (FUN_00009a20: step table
 * 2700/2600/2500/2400/2300 mV -> 100/70/40/10/5%, CR2032 plateau); below, linear between its levels:
 * 2200 mV 0%, 2300 5%, 2400 10%, 2500 40%, 2600 70%, 2700 100% (rounded to nearest %). */
_attribute_ram_code_
u8 get_battery_level(u16 battery_mv) {
	u32 mv = battery_mv;
	if (mv >= 2700) return 100;
	if (mv > 2600) return 70 + ((mv - 2600) * 30 + 50) / 100;
	if (mv > 2500) return 40 + ((mv - 2500) * 30 + 50) / 100;
	if (mv > 2400) return 10 + ((mv - 2400) * 30 + 50) / 100;
	if (mv > 2300) return 5 + ((mv - 2300) * 5 + 50) / 100;
	if (mv > 2200) return ((mv - 2200) * 5 + 50) / 100;
	return 0;
}
#else
// 2200..3000 mv - 0..100%
_attribute_ram_code_
u8 get_battery_level(u16 battery_mv) {
	u8 battery_level = 100;
	if (battery_mv < MAX_VBAT_MV) {
		if (battery_mv > MIN_VBAT_MV) {
			battery_level = (u8)((u32)((((u32)battery_mv - (u32)MIN_VBAT_MV)
				* (u32)VBAT2LEVEL_COEF) >> VBAT2LEVEL_SHL));
		} else {
			battery_level = 0;
		}
	}
	return battery_level;
}
#endif // USE_MI_BATTERY_CURVE
