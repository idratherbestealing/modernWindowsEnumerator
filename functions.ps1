#dirPerms
#--------
#Path       : C:\
#Owner      : NT SERVICE\TrustedInstaller
#Group      : NT AUTHORITY\Authenticated Users
#AccessType : Allow
#Rights     : -536805376
function dirPerms {  
$PATH = "C:\USERS"
$DIRECTORY = Get-Acl -Path $PATH  
  
ForEach ($DIR in $DIRECTORY.Access){  
    [PSCustomObject]@{  
    Path = $PATH  
    Owner = $DIRECTORY.Owner  
    Group = $DIR.IdentityReference  
    AccessType = $DIR.AccessControlType  
    Rights = $DIR.FileSystemRights  
    }#EndPSCustomObject  
}#EndForEach  
}


#list users
#----------
#Default User
#Massi
#Public
function listUSers 
{
Get-ChildItem C:\Users -Force | select Name, LastWriteTime | FT
}


# SIDS
#-----
#Caption     : ELEVEN\Administrator
#Domain      : ELEVEN
#SID         : S-1-5-21-1283207480-1007434991-2872014766-500
#FullName    :
#Name        : Administrator
function userSids 
{
	Get-WmiObject -Class Win32_UserAccount
}

#
function WiFi 
{  
(netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)}  | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table -AutoSize 
}

#
function unquotedServices 
{  
$svclist = Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\services | ForEach-Object {Get-ItemProperty $_.PsPath}

#Ignore anything after .exe, filter for vulnerable services
ForEach ($svc in $svclist) {
    $svcpath = $svc.ImagePath -split ".exe"
    if(($svcpath[0] -like "* *") -and ($svcpath[0] -notlike '"*') -and ($svcpath[0] -notlike "\*")) {
        $svc | fl -Property DisplayName,ImagePath,PsPath

        #Check service permissions (Full Control or Modify is BAD!!)
        Get-Acl $svc.ImagePath | fl
    }
}
}

#cloud-drive-daemon Established 192.168.50.101 192.168.50.58
function processesListenEstablish 
{
Get-NetTCPConnection |where {$_.RemoteAddress -gt  "0" -and $_.LocalAddress -gt  "0" -and $_.State -ne "TimeWait"} | Select-Object -Property *,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}}| Select-Object  ProcessName, State,LocalAddress,RemoteAddress |ft
}


#Name:  	ec2-34-214-245-32.us-west-2.compute.amazonaws.com
#Address:  	34.214.245.32
function connectedNslookups 
{
$WANIP=Get-NetTCPConnection -State  Established|where{$_.RemoteAddress-gt"127.1.1.1"}|%{$_.RemoteAddress};  foreach($WAN in $WANIP) {nslookup $WAN }
}

#	Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
#	-------  ------    -----      -----     ------     --  -- -----------
#    348      26    25160      39284       1.19   8856   1 brave

function establishedProcessIds
{
$A=Get-NetTCPConnection -State Established |where {$_.RemoteAddress -gt  "0"} |%{$_.OwningProcess}; ForEach ($Z in $A) {gps -ID $Z}
}


function listeningProcessIds{
$A=Get-NetTCPConnection -State Established |where {$_.RemoteAddress -gt  "0"} |%{$_.OwningProcess}; ForEach ($Z in $A) {gps -ID $Z }
}


#####################
#  ACTIVE DIRECTORY #
#####################

function getDC 
{
Get-ADGroupMember 'Domain Controllers'
}

#	DC     6/12/2023 9:00:57 AM 133310598886299318 10.10.11.175
#	CLIENT 6/12/2023 9:03:50 AM 133310676323795708 172.16.20.20
function getClientServerIp 
{
Get-AdComputer -Filter * -Properties * | select Name, LastLogonDate, lastLogon, IPv4Address
}

function getDomainUsers 
{
Get-AdUser -Filter * | ?{ $_.Enabled -eq "true" } | select SamAccountName, Name, ObjectClass, UserPrincipalName
}


#####################
#       USERS       #
#####################

#SamAccountName    : smorgan
#Name              : Sally Morgan
#Surname           : Morgan
#ObjectClass       : user
#UserPrincipalName : smorgan@MEGABANK.LOCAL
#Enabled           : True
#SID               : S-1-5-21-391775091-850290835-3566037492-2615

function getAdUsers
{
Get-AdUser -Filter * | ?{ $_.Enabled -eq "true" -and $_.enabled -eq "false"}  | Select SamAccountName, Name, Surname, ObjectClass, UserPrincipalName, Enabled, SID
}


#####################
#      GROUPS       #
#####################


#SamAccountName    : Administrator
#Name              : Administrator
#GivenName         :
#UserPrincipalName :
#Enabled           : True
#Modified          : 6/12/2023 5:48:19 AM
#LastLogonDate     : 6/12/2023 5:48:19 AM
#PasswordLastSet   : 1/2/2020 2:18:38 PM
#Description       : Built-in account for administering the computer/domain
function getGroupsAndAttr
{
$Groups = Get-ADUser -Filter { Name -Like "*" -or  Name -like "Enterprise*" -or Name -like "*Schema*" -or  Name -like "*admin*"}  -properties * |select SamAccountName,Name, GivenName, UserPrincipalName, Enabled, Modified, LastLogonDate, PasswordLastSet, Description; echo $Groups
}

#Domain Users        Administrator       Administrator
#Domain Users        krbtgt              krbtgt
#Domain Users        Bobby Tables        btables
#Domain Users        Susan Flowers       sflowers
function getGroupMembers 
{
ForEach ($Group in (Get-ADGroup -Filter *))  { Get-ADGroupMember $Group | Select @{Label="Group";Expression={$Group.Name}},Name,SamAccountName } 
}








