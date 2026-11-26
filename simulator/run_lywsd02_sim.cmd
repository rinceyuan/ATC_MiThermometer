@echo off
rem LYWSD02MMC (Clock / E-Ink Thermometer) firmware simulator: runs the real compiled firmware (..\out\LYWSD02MMC_v60.elf)
rem and draws its 16-byte E-Ink display. Requires python with unicorn, capstone, pyelftools, cryptography.
cd /d "%~dp0"
python lywsd02_sim.py %*
if errorlevel 1 pause
