@echo off
rem MJWSD06MMC (Thermometer 3 mini) firmware simulator: runs the real compiled firmware (..\out\MJ6_v60_mesh.elf)
rem and shows its LCD. Requires python with unicorn, capstone, pyelftools, cryptography (see README.md).
cd /d "%~dp0"
python mini3_sim.py %*
if errorlevel 1 pause
