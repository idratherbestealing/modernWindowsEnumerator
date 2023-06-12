cls
@echo off
cls
mode con:cols=160 lines=9999
cd %SystemDrive%
mkdir %LOCALAPPDATA%\helper >nul
set helper=%LOCALAPPDATA%\helper
copy functions.ps1 %helper%
copy helper.bat %helper%
color 0b
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo ==============================
echo MODERN WINDOWS ENUMERATOR 2023
echo ==============================
echo.
echo.
echo.
echo.
echo YOU'RE LOGGED IN AS %USERNAME%
echo.
echo.
date /T && time /T
echo.
echo.
echo HOSTNAME:		%COMPUTERNAME%
for /f "delims=: tokens=2" %%a in ('ipconfig ^| findstr /R /C:"IPv4 Address"') do (set tempip=%%a)  
set tempip=%tempip: =%  
echo IP ADDRESS: 		%tempip%
for /f "delims=: tokens=2" %%a in ('ipconfig ^| findstr /R /C:"Default Gateway"') do (set tempip=%%a)  
set tempip=%tempip: =%  
echo DEFAULT GATEWAY: 	%tempip%
echo.
echo.
echo ==============================================
echo RUNNING WINDOWS ENUMERATION TOOL - PLEASE WAIT
echo ==============================================
echo.
echo.
echo.
echo.
echo [+] %USERNAME% POWERSHELL HISTORY SAVE PATH
echo.
echo.
powershell.exe /c (Get-PSReadlineOption).HistorySavePath
echo.
echo.
echo [+] INTERESTING FILES %USERNAME% HAS ACCESS TO
echo.
echo.
powershell gci -Recurse -filter "*.txt" c:\users  -ErrorAction SilentlyContinue
powershell gci -Recurse -filter "*.docx" c:\users  -ErrorAction SilentlyContinue
powershell gci -Recurse -filter "*.xlsx" c:\users  -ErrorAction SilentlyContinue
echo.
echo.
echo [+] %USERNAME% PRIVILEGES
echo.
echo.
whoami /priv
echo.
echo.
echo [+] %USERNAME% PROFILE FOLDER
echo.
echo.
dir /a %USERPROFILE%
echo.
echo.
echo [+] %USERNAME% DESKTOP
echo.
dir %USERPROFILE%\Desktop
echo.
echo.
echo [+] %USERNAME% DOCUMENTS
echo.
dir %USERPROFILE%\Documents
echo.
echo.
echo [+] %USERNAME% DOWNLOADS
echo.
dir %USERPROFILE%\Downloads
echo.
echo.
echo DIRECTORY PERMISSIONS
echo =====================
powershell -exec bypass -command "& { . .\functions.ps1; dirPerms }"
echo.
echo.
echo ALL USERS DIRECTORIES AND SUBDIRECTORIES
echo ========================================
echo.
echo.
tree /a /f c:\users
echo.
echo.
echo OTHER USERS OF THIS SYSTEM
echo ==========================
echo.
echo.
powershell -exec bypass -command "& { . .\functions.ps1; listUSers }"
echo.
echo.
echo LOCAL ADMINISTRATORS
echo ====================
echo.
echo.
net localgroup administrators
echo.
echo.
echo CURRENTLY LOGGED IN USERS
echo =========================
echo.
echo.
qwinsta 
echo.
echo.
echo LOCAL GROUPS
echo ============
echo.
echo.
net localgroup
echo.
echo.
echo =========================
echo LOCATING STORED PASSWORDS
echo =========================
echo.
echo.
echo.
echo.
echo LOCAL PASSWORD POLICY
echo =====================
echo.
echo.
net accounts
echo.
echo.
echo STORED PASSWORDS
echo ================
echo.
echo.
cmdkey /list
echo.
echo.
echo VIEW WIFI ACCESSPOINTS AND STORED PASSWORDS
echo ===========================================
echo.
echo.
powershell -exec bypass -command "& { . .\functions.ps1; WiFi }"
echo.
echo.
echo SEARCHING SAM / SYSTEM FILES
echo ============================
echo.
echo.
dir %SYSTEMROOT%\repair\SAM 2>nul
dir %SYSTEMROOT%\System32\config\RegBack\SAM 2>nul
dir %SYSTEMROOT%\System32\config\SAM 2>nul
dir %SYSTEMROOT%\repair\system 2>nul
dir %SYSTEMROOT%\System32\config\SYSTEM 2>nul
dir %SYSTEMROOT%\System32\config\RegBack\system 2>nul
echo.
echo.
echo REG QUERY WINLOGON 64-BIT
echo =========================
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /reg:64
echo.
echo.
echo REG QUERY WINLOGON 32-BIT
echo =========================
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /reg:32
echo.
echo.
echo.
echo.
echo ================================
echo LOCATING WEB CONFIGURATION FILES
echo ================================
echo.
echo.
echo.
echo.
echo CONFIG FILES 
echo ============
echo.
echo.
powershell gci -Recurse -filter "*.web.config" c:\  -ErrorAction SilentlyContinue
powershell gci -Recurse -filter "*.wp-config.php" c:\  -ErrorAction SilentlyContinue
powershell gci -Recurse -filter "*.httpd-xampp.conf" c:\  -ErrorAction SilentlyContinue
powershell gci -Recurse -filter "*.httpd.conf" c:\  -ErrorAction SilentlyContinue
echo.
echo.
echo AUNQUOTED SERVICE PATHS
echo =======================
echo.
echo.
powershell -exec bypass -command "& { . .\functions.ps1; unquotedServices }"
echo.
echo.
echo HIJACK EXE DLL PATHS
echo ====================
echo.
echo.
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO. )
echo.
echo.
echo INETPUB DIRECTORY 
echo =================
echo.
echo.
dir /a /b C:\inetpub\
echo.
echo.ONFIG FILES 
echo ============
echo.
echo.
dir /s /b php.ini httpd.conf httpd-xampp.conf my.ini my.cnf web.config
echo.
echo.
echo SYSPREP FILES
echo =============
echo.
echo.
dir /b /s unattended.xml* sysprep.xml* sysprep.inf* unattend.xml*
echo.
echo.
echo KEEPASS FILES
echo =============
echo.
echo.
dir /a /s /b *.kdbx
echo.
echo.
echo PROGRAM FILES X64
echo =================
echo.
echo.
dir /a "%ProgramFiles%"
echo.
echo.
echo PROGRAM FILES X86
echo =================
echo.
echo.
dir /a "%ProgramFiles(x86)%"
echo.
echo.
echo INETPUB DIRECTORY 
echo =================
echo.
echo.
dir /a /b C:\inetpub\
echo.
echo.
echo ===========================================
echo ACTIVE DIRECTORY USERS GROUPS AND COMPUTERS
echo ===========================================
echo.
echo.
echo.
echo.
echo LOCATING THE ACTIVE DIRECTORY SERVER
echo =====================================
echo.
echo.
powershell -exec bypass -command "& { . .\functions.ps1; findADServer }"
echo.
echo.
echo FINDING ACTIVE DIRECTORY MEMBERS
echo ================================
echo.
echo.
powershell -exec bypass -command "& { . .\functions.ps1; findADUSers }"
echo.
echo.
PAUSE
