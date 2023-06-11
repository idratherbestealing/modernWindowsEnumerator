@echo off
cls
mode con:cols=160 lines=9999
cd %SystemDrive%
mkdir %LOCALAPPDATA%\helper >nul
set helper=%LOCALAPPDATA%\helper
color 0b
echo.
echo.
echo.
echo.
echo.
echo =======================
echo WINDOWS ENUMERATOR 2023
echo =======================
echo.
echo.
date /T && time /T
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
echo.
echo YOU'RE LOGGED IN AS %USERNAME%
echo ==============================
echo.
echo.
echo SYSTEM INFO
echo ===========
echo.
echo.
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
echo.
echo.
echo LAST BOOTUP TIME
echo ================
powershell.exe /c "Get-CimInstance -ClassName Win32_OperatingSystem |select CSName, LastBootUpTime"
echo PHYSICAL DRIVES
echo ===============
echo.
powershell -Command "& {Get-PSDrive | where {$_.Provider -like 'Microsoft.PowerShell.Core\FileSystem'}| ft Name,Root}"
echo WINDOWS VOLUME
echo ==============
echo.
dir %SystemDrive%
@rem dir %HOMEDRIVE%
echo.
echo.
echo.
echo THIS PROFILE BELONGS TO: %USERNAME%
echo ===================================
echo.
echo USERNAME:		%USERNAME%
echo PROFILE:		%USERPROFILE%
echo DESKTOP DIRECTORY	%dsk%
echo ONEDRIVE FOLDER:	%OneDrive%
echo TEMP DIRECTORY:		%TEMP%
echo LOGON SERVER:		%LOGONSERVER%
echo APPDATA DIRECTORY:	%LOCALAPPDATA%
echo HOMEDRIVE LOCATION:	%LOCALAPPDATA%
echo HELPER DIRECTORY:		%helper%
echo.
echo.
echo.
echo.
echo %USERNAME% POWERSHELL HISTORY SAVE PATH
echo =======================================
echo.
powershell.exe /c (Get-PSReadlineOption).HistorySavePath
echo.
echo.
echo.
echo.
echo.
echo INTERESTING FILES %USERNAME% HAS ACCESS TO
echo ==========================================
echo.
powershell gci -Recurse -filter "*.txt" c:\users  -ErrorAction SilentlyContinue
powershell gci -Recurse -filter "*.docx" c:\users  -ErrorAction SilentlyContinue
powershell gci -Recurse -filter "*.xlsx" c:\users  -ErrorAction SilentlyContinue
echo.
echo BASH.EXE
echo ========
where /R c:\ bash.exe
echo.
echo NETCAT
echo ======
where /R c:\ nc.exe
where /R c:\ netcat.exe
echo.
echo PYTHON
echo ======
where /R c:\ python2.7.exe
where /R c:\ python3.exe
echo.
echo POR TFORWARDING AND TUNNELING TOOLS
echo ===================================
echo.
where /R c:\ socat.exe
where /R c:\ chisel.exe
echo.
echo.
echo.
echo ======================
echo %USERNAME% DIRECTORIES
echo ======================
echo.
echo.
echo %USERNAME% PROFILE FOLDER
echo =========================
echo.
dir /a %USERPROFILE%
echo.
echo.
echo %USERNAME% DESKTOP
echo ==================
echo.
dir %dsk%
echo.
echo.
echo %USERNAME% DOCUMENTS
echo ====================
echo.
dir %USERPROFILE%\Documents
echo.
echo.
echo %USERNAME% DOWNLOADS
echo ====================
echo.
dir %USERPROFILE%\Downloads
echo.
echo.
echo.
echo.
echo ==========================
echo OTHER USERS OF THIS SYSTEM
echo ==========================
echo.
echo.
echo.
echo OTHER USERS
echo ===========
echo.
powershell -exec bypass -command "& { . c:\functions.ps1; listUSers }"
echo.
echo.
echo.
echo USERS SIDS
echo ==========
echo.
powershell -exec bypass -command "& { . c:\functions.ps1; userSids }"
echo.
echo.
echo.
echo CHECKING THE C:\USERS DIRECTORY PERMISSIONS 
echo ===========================================
echo.
powershell -exec bypass -command "& { . c:\functions.ps1; dirPerms }"
echo.
echo.
echo.
echo LOCAL ADMINISTRATORS
echo ====================
echo.
net localgroup administrators
@rem dir "C:\Documents and Settings\Administrator"
echo.
echo.
echo.
echo ==========================================
echo CHECKING ADMINISTRATOR DRIVE ACCESSIBILITY
echo ==========================================
echo.
echo.
echo.
dir "C:\Users\Administrator"
dir "C:\Documents and Settings\Administrator"
echo.
echo.
echo.
echo.
echo CURRENTLY LOGGED IN USERS
echo =========================
echo.
qwinsta 
echo.
echo.
echo.
echo SAVE ALL USERS DIRECTORY HIERARCHY TO DISK
echo ==========================================
echo.
tree /a /f c:\users > user_directories.txt
echo saved: %dsk%\user_directories.txt
echo.
echo.
echo.
echo LOCAL USER GROUPS
echo =================
echo.
net localgroup
echo.
echo.
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
powershell -exec bypass -command "& { . c:\functions.ps1; findADServer }"
echo.
echo.

echo FINDING ACTIVE DIRECTORY MEMBERS
echo ================================
echo.
powershell -exec bypass -command "& { . c:\functions.ps1; findADUSers }"
echo.
echo.

echo VIEW ACTIVE DIRECTORY USERS LAST PASSWORD SET DATE
echo ==================================================
echo.
powershell -exec bypass -command "& { . c:\functions.ps1; passwordsLastset }"
echo.
echo.

echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo ===================================
echo ATTEMPTING TO LOCATE PASSWORD FILES
echo ===================================
echo.
echo.
echo.
echo VIEW WIFI ACCESSPOINTS AND STORED PASSWORDS
echo ===========================================
echo.
powershell -exec bypass -command "& { . c:\functions.ps1; WiFi }"
echo.
echo.
echo LOCAL PASSWORD POLICY
echo =====================
echo.
net accounts
echo.
echo.
echo.
echo ENUMERATING STORED PASSWORDS
echo ============================
echo.
cmdkey /list
echo.
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
dir /a /b /s SAM.b*
echo.
echo.
echo.
echo SEARCHING REGISTRY
echo ==================
echo.
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" | findstr "DefaultUserName DefaultDomainName DefaultPassword"
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential
echo.
echo.
echo.
echo LIST WINDOWS VAULTS
echo ===================
echo.
vaultcmd /listcreds:"Windows Credentials" /all
echo.
echo.
echo.
echo TOKENS
echo ======
echo.
klist
echo.
echo.
echo SEARCH .INI .CONFIG .BAK FILES CONTAING PASSWORDS (disabled)
echo ============================================================
echo.
@rem start /b findstr /sim password *.ini *.config *.bak *.ps1 2>nul
echo.
echo.
echo.
echo =================================================
echo PROGRAM FILES, CONFIG FILES AND UNQUOTED SERVICES
echo =================================================
echo.
echo.
echo.
echo.
echo UNQUOTED SERVICE PATHS TEST
echo ===========================
echo.
echo.
echo.
echo SUPERSEDED WMIC. FOR USE WITH OLDER OPERATING SYSTEMS
echo =====================================================
wmic service get name,pathname,displayname,startmode **|** findstr **/**i auto **|** findstr **/**i **/**v "C:\Windows\\"
echo.
echo.
echo.
powershell -exec bypass -command "& { . c:\functions.ps1; unquotedServices }"
echo.
echo.
echo HIJACK EXE DLL PATHS
echo ====================
echo.
echo.
echo.
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO. )
echo.
echo.
echo PROGRAM FILES X64
echo =================
echo.
dir /a "%ProgramFiles%"
echo.
echo.
echo.
echo PROGRAM FILES X86
echo =================
echo.
dir /a "%ProgramFiles(x86)%"
echo.
echo.
echo.
echo INETPUB DIRECTORY 
echo =================
echo.
dir /a /b C:\inetpub\
echo.
echo.
echo.
echo CONFIG FILES 
echo ============
echo.
dir /s /b php.ini httpd.conf httpd-xampp.conf my.ini my.cnf web.config
echo.
echo.
echo.
echo SYSPREP FILES
echo =============
echo.
dir /b /s unattended.xml* sysprep.xml* sysprep.inf* unattend.xml*
echo.
echo.
echo.
echo KEEPASS FILES
echo =============
echo.
dir /a /s /b *.kdbx
echo.
echo.
echo.
echo =====================
echo NETWORK AND FIREWALLS
echo =====================
echo.
echo.
echo.
echo WINDOWS FIREWALL SETTINGS
echo =========================
echo.
@rem netsh firewall show state
@rem netsh firewall show config
@rem netsh advfirewall firewall dump
echo.
echo.
echo.
echo ESTABLISHED AND LISTENING PROCESSES
echo ===================================
echo.
powershell -exec bypass -command "& { . c:\functions.ps1; processesListenEstablish }"
echo.
echo.
echo.
echo PERFORMING AN NSLOOKUP ON ESTABLISHED CONNECTIONS
echo =================================================
echo.
powershell -exec bypass -command "& { . c:\functions.ps1; connectedNslookups }"
echo.
echo.
echo.
echo ESTABLISHED PROCESSORS ID AND RESOURCE USAGE
echo ============================================
echo.
powershell -exec bypass -command "& { . c:\functions.ps1; establishedProcessIds }"
echo.
echo.
echo.
echo LISTENING PROCESSORS ID AND RESOURCE USAGE
echo ==========================================
echo.
powershell -exec bypass -command "& { . c:\functions.ps1; listeningProcessIds }"
echo.
echo.
echo.


echo FULL NETWORK PROBE
echo ==================
echo.
powershell -exec bypass -command "& { . c:\functions.ps1; probingConnections }"
echo.
echo.
