@echo off
REM Step 2 one-click — vivo Y75 V2117 MT6781 4.14.186 paranoid -1
REM Run from Windows: double-click this file
set ADB=C:\Users\LOQ\platform-tools\adb.exe
set CLEAN=C:\Users\LOQ\.zcode\workspace\default\..\..\
echo === Step 2: Y75 live oracle ===
%ADB% shell "uname -r; echo ---PARANOID---; cat /proc/sys/kernel/perf_event_paranoid; echo ---SELINUX---; getprop ro.product.model; getenforce"
echo --- pushing perf_leak ---
%ADB% push C:\Users\LOQ\Downloads\perf_leak_y75 /data/local/tmp/perf_leak_y75
%ADB% shell "chmod 755 /data/local/tmp/perf_leak_y75; /data/local/tmp/perf_leak_y75 2>&1 | tee /data/local/tmp/perf_leak_out.txt; echo ---KASLR_DONE---; cat /data/local/tmp/perf_leak_out.txt | grep KASLR"
echo --- pushing race_oracle ---
%ADB% push C:\Users\LOQ\Downloads\race_oracle /data/local/tmp/race_oracle
%ADB% shell "chmod 755 /data/local/tmp/race_oracle; /data/local/tmp/race_oracle 2>&1"
pause
