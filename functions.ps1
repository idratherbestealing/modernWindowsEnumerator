#
# dirPerms
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
#Default
#Default User
#Massi
#Public
#desktop.ini
function listUSers {
Get-ChildItem C:\Users -Force | select Name, LastWriteTime | FT
}


# more user accounts
#Caption     : ELEVEN\Administrator
#Domain      : ELEVEN
#SID         : S-1-5-21-1283207480-1007434991-2872014766-500
#FullName    :
#Name        : Administrator
function userSids {
	Get-WmiObject -Class Win32_UserAccount
}


function WiFi {  
(netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)}  | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table -AutoSize 
}

function unquotedServices {  
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
function processesListenEstablish {
Get-NetTCPConnection |where {$_.RemoteAddress -gt  "0" -and $_.LocalAddress -gt  "0" -and $_.State -ne "TimeWait"} | Select-Object -Property *,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}}| Select-Object  ProcessName, State,LocalAddress,RemoteAddress |ft
}


#Name:  	ec2-34-214-245-32.us-west-2.compute.amazonaws.com
#Address:  	34.214.245.32
function connectedNslookups {
$WANIP=Get-NetTCPConnection -State  Established|where{$_.RemoteAddress-gt"127.1.1.1"}|%{$_.RemoteAddress};  foreach($WAN in $WANIP) {nslookup $WAN }
}

#	Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
#	-------  ------    -----      -----     ------     --  -- -----------
#    348      26    25160      39284       1.19   8856   1 brave

function establishedProcessIds{
$A=Get-NetTCPConnection -State Established |where {$_.RemoteAddress -gt  "0"} |%{$_.OwningProcess}; ForEach ($Z in $A) {gps -ID $Z}
}

function listeningProcessIds{
$A=Get-NetTCPConnection -State Established |where {$_.RemoteAddress -gt  "0"} |%{$_.OwningProcess}; ForEach ($Z in $A) {gps -ID $Z }
}


function probingConnections {
$(Get-NetIPAddress | where-object {$_.PrefixLength -eq "24"}).IPAddress | Where-Object {$_ -like "*.*"} | % { 
    $netip="$($([IPAddress]$_).GetAddressBytes()[0]).$($([IPAddress]$_).GetAddressBytes()[1]).$($([IPAddress]$_).GetAddressBytes()[2])"
    write-host "`n`nping C-Subnet $netip.1-254 ...`n"
    1..254 | % { 
        (New-Object System.Net.NetworkInformation.Ping).SendPingAsync("$netip.$_","1000") | Out-Null
    }
}
#wait until arp-cache: complete
while ($(Get-NetNeighbor).state -eq "incomplete") {write-host "waiting";timeout 1 | out-null}
#add the Hostname and present the result
Get-NetNeighbor | Where-Object -Property state -ne Unreachable | where-object -property state -ne Permanent | select IPaddress,LinkLayerAddress,State, @{n="Hostname"; e={(Resolve-DnsName $_.IPaddress).NameHost}} }





function findADServer {
Get-ADDomain | Select-Object NetBIOSName, DNSRoot, InfrastructureMaster
}


function findADUSers {
Get-ADUser -Filter {Enabled -eq $TRUE} |ft samaccountname
}


function passwordsLastset {
$users = Get-ADUser -filter {enabled -eq $True -and PasswordNeverExpires -eq $False -and PasswordLastSet -gt 0 } `

-Properties "Name", "EmailAddress", "msDS-UserPasswordExpiryTimeComputed" | Select-Object -Property "Name", "EmailAddress", `

@{Name = "PasswordExpiry"; Expression = {[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed").tolongdatestring() }}

}





