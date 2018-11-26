function Get-NetAdapterAlias {
    param (
        [Parameter(Mandatory = $false, HelpMessage = "the ip for the alias lookup")]
        [string]$ip,

        [Parameter(Mandatory = $false)]
        [switch]$abso
    )
    if (!($abso)) {
        $ip += "*"
    }
    
    $netstuff = Get-NetIPAddress
    foreach ($adapter in $netstuff) {
        if ([string]$adapter.IPv4Address -like $ip) {
            return $adapter.InterfaceAlias
        }
    }
}

function Replace-IcelandicCharactersInString {
    param (
        [Parameter(Mandatory= $true)]
        [string]$str
    )
    $str = $str.toLower() -replace 'ö','o' -replace 'á','a' -replace 'ó','o' -replace 'ð','d' -replace 'þ','th' -replace 'æ','ae' -replace 'é','e' -replace 'í','i'  -replace 'ú','u' -replace 'ý','y'
    return $str.Replace('.','')
}
function Make-NemName {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    $fName = Get-Name -name $Name -first
    $lName = Get-Name -name $Name -last
    $returnName = $($fName.substring(0,2)+ $lName.substring(0,2) + 1)
    return $returnName

}

function Get-Name {
    param(
        [Parameter(Mandatory=$true)]
        [string]$name,

        [Parameter(Mandatory = $false)]
        [switch]$first,

        [Parameter(Mandatory = $false)]
        [switch]$last,

        [Parameter(Mandatory = $false)]
        [switch]$full
    )
    $name = Replace-IcelandicCharactersInString -str $name 
    $x = $name.Split(" ")
    if($x[2].Length -eq 0){
        $fla = $true;
    }
    if($first){
        return $($x[0]+ " "+ $x[1])
    } 
    if ($last) {
        return $x[-1]
        }
        
    } 
    if ($full) {
        if($x[0].Length + $x[-1].Length -ge 19){
            return $($x[0][0]+"."+ $x[-1])
        }elseif($x[0].Length + $x[1].Length + $x[2].Length -ge 19){
            return $($x[0] +"."+  $x[2])
        } else {
            if($fla){
                return $($x[0] +"."+  $x[1])
            } else {
                return $($x[0] + "." + $x[1] + "." + $x[2])
            }
        }
        
    }
}

#*******************************************************
#==================Remeber to change====================
#*******************************************************
$domainname = "tskoli.local"
$networkAddress = "10.0.0.0"
$mainDCIp = "10.0.0.1"
$routerIp = "10.0.0.2"
$dnsServerIp = "10.0.0.1"
$webserverip = "10.0.0.2"
$prefixlen = 21
$subnetMask = "255.255.248.0"
$startRangeDHCP ="10.0.0.50"
$endRangeDHCP = "10.10.7.250"
$webdomain = "tskoli.is"

$lanAdapterName = Get-NetAdapterAlias -ip "169.254"
$wanAdapterName = Get-NetAdapterAlias -ip "10"

$lanAlias = "LAN"
$wanAlias = "WAN"

#=======================================================

Rename-NetAdapter -name $lanAdapterName -NewName $lanAlias
Rename-NetAdapter -Name $wanAdapterName -NewName $wanAlias

New-NetIPAddress -InterfaceAlias $lanAlias -IPAddress $mainDCIp -PrefixLength $prefixlen #Fix later

Set-DnsClientServerAddress -InterfaceAlias $lanAlias -ServerAddresses 127.0.0.1

Install-WindowsFeature -Name ad-domain-services -IncludeManagementTools

# THIS IS THE FISRTS
Install-ADDSForest -DomainName $domainname -InstallDns -SafeModeAdministratorPassword (ConvertTo-SecureString -AsPlainText "pass.123" -Force)

# =================|AFTER REBOOT|=================

Add-DnsServerPrimaryZone -Name $webdomain -ReplicationScope Domain

Add-DnsServerResourceRecordA -ZoneName $webdomain -Name "www" -IPv4Address $webserverip
Add-DnsServerResourceRecordA -ZoneName $webdomain -Name "*" -IPv4Address $webserverip

$dcpath = $(",dc=" + $env:USERDOMAIN + ",dc=" + $env:USERDNSDOMAIN.Split('.')[1])

Install-WindowsFeature -Name DHCP -IncludeManagementTools
Install-WindowsFeature web-server -IncludeManagementTools

# ====|DHCP SCOPE|====
Add-DhcpServerv4Scope -Name "LAN - 1" -StartRange $startRangeDHCP -EndRange $endRangeDHCP -SubnetMask $subnetMask

Set-DhcpServerv4OptionValue -DnsServer $dnsServerIp  -Router $routerIp
Add-DhcpServerInDC $($env:COMPUTERNAME + "." + $env:USERDNSDOMAIN)

# ====|IIS|====
New-Item $("C:\inetpub\wwwroot\www." + $webdomain) -ItemType Directory
New-Item $("C:\inetpub\wwwroot\www." + $webdomain + "\index.html") -ItemType File -Value $("Vefsíðan www."+ $webdomain)
New-Website -Name $("www." + $webdomain) -HostHeader $("www." + $webdomain) -PhysicalPath $("C:\inetpub\wwwroot\www." + $webdomain + "\")
New-WebBinding -Name $("www." + $webdomain) -HostHeader $webdomain

# ====|JOIN WIN8 PC TO DOMAIN|====
$passwd = ConvertTo-SecureString -AsPlainText "2015P@ssword" -Force
$win8user = New-Object System.Management.Automation.PSCredential -ArgumentList $("win3a-w81-10\administrator"), $passwd
$SeverUsser = New-Object System.Management.Automation.PSCredential -ArgumentList $($env:USERDOMAIN + "\administrator"), $passwd

Add-Computer -ComputerName "win3a-w81-10" -LocalCredential $win8user -DomainName $env:USERDNSDOMAIN -Credential $SeverUsser -Restart -Force

# ======|MAKE OU|======
New-ADOrganizationalUnit -Name Comput -ProtectedFromAccidentalDeletion $false
# ===|MOVE PC TO OU|===
# Check Get-AdComputer for path to computer
Move-ADObject -Identity $("CN=win3a-w81-10,CN=Computers"+ $dcpath) -TargetPath $("OU=Comput" + $dcpath )
# =====================






Add-PrinterDriver -Name "HP LaserJet 2300L PCL6 Class Driver"
$users = Import-Csv .\notendur.csv

New-ADOrganizationalUnit Notendur -ProtectedFromAccidentalDeletion $false
New-ADGroup Allir -Path $("ou=Notendur" + $dcpath) -GroupScope Global
foreach ($u in $users){
    $u.Skrifstofa
}
foreach ($u in $users) {
    $hlutverk = $u.Hlutverk
    if((Get-ADOrganizationalUnit -Filter {name -eq $hlutverk}).name -ne $hlutverk){
        New-ADOrganizationalUnit $hlutverk -Path $("ou=Notendur" + $dcpath) -ProtectedFromAccidentalDeletion $false
        New-ADGroup $hlutverk  -Path $("ou=" + $hlutverk + ",ou=notendur" + $dcpath) -GroupScope Global
        Add-ADGroupMember -Identity Allir -Members $hlutverk
    }
    $skoli = $u.skoli
    if ((Get-ADOrganizationalUnit -SearchBase $("ou=" + $hlutverk + ",ou=notendur" + $dcpath)  -Filter {name -eq $skoli}).name -ne $skoli) {
        New-ADOrganizationalUnit $skoli -Path $("ou=" + $hlutverk + ",ou=Notendur" + $dcpath) -ProtectedFromAccidentalDeletion $false
        New-ADGroup $($skoli+"_"+$hlutverk)  -Path $("ou=" + $skoli + ",ou=" + $hlutverk + ",ou=notendur" + $dcpath) -GroupScope Global
        Add-ADGroupMember -Identity $hlutverk -Members $($skoli+"_"+$hlutverk)
    }

    $braut = $u.braut
    if ((Get-ADOrganizationalUnit -SearchBase $("ou=" + $skoli + "ou=" + $hlutverk + ",ou=notendur" + $dcpath)  -Filter {name -eq $braut}).name -ne $braut) {
        New-ADOrganizationalUnit $skoli -Path $("ou=" + $skoli + "ou=" + $hlutverk + ",ou=Notendur" + $dcpath) -ProtectedFromAccidentalDeletion $false
        New-ADGroup $($braut+"_"+$skoli+"_"+$hlutverk)  -Path $("ou=" + $braut +"ou=" + $skoli + ",ou=" + $hlutverk + ",ou=notendur" + $dcpath) -GroupScope Global
        Add-ADGroupMember -Identity $($skoli+"_"+$hlutverk) -Members $($skoli+"_"+$hlutverk)
    

       # New-Item c:\DATA\$($skrifstofa + "_" + $deild) -ItemType Directory

        #$rettindi = Get-Acl -Path C:\DATA\$($skrifstofa + "_" + $deild)
        #$nyRettindi = New-Object System.Security.AccessControl.FileSystemAccessRule( $($env:USERDOMAIN + "\" + $deild + "_" + $skrifstofa), "Modify", "Allow")
        #$rettindi.AddAccessRule($nyRettindi)

        #Set-Acl -Path C:\DATA\$($skrifstofa + "_" + $deild) $rettindi

        #New-SmbShare -name $($skrifstofa + "_" + $deild) -Path C:\DATA\$($skrifstofa + "_" + $deild) -FullAccess Everyone

        #Add-Printer -Name $($deild + "_Prentari") -DriverName "HP LaserJet 2300L PCL6 Class Driver" -PortName "LPT1:" -Shared -ShareName $($deild + "_PRINT") -Published
    }
    if($u.Hlutverk -eq "Kennarar"){
        $nm = Get-Name -name $u.nafn -full;
    } else {
        $nm = Make-NemName -Name $u.Nafn
    }
    
    $splat = @{
        "Name" = $u.Nafn;
        "DisplayName" = $nm;
        "GivenName" = Get-Name -name $u.nafn -first;
        "Surname" = Get-Name -name $u.nafn -last;
        "SamAccountName" = $nm;
        "UserPrincipalName" = $($nm + "@" + $env:USERDNSDOMAIN);
        "AccountPassword" = (ConvertTo-SecureString -AsPlainText "pass.123" -Force); 
        "Path" = $("ou=" + $braut + "ou=" + $skoli + ",ou=" + $hlutverk + ",ou=notendur" + $dcpath); 
        "Enabled" = $true;
    }
    New-ADUser @splat # -Name $u.nafn -DisplayName $u.nafn -GivenName $u.fornafn -Surname $u.eftirnafn -SamAccountName $u.notendanafn -UserPrincipalName $($u.notendanafn + "@" + $env:USERDNSDOMAIN) -AccountPassword (ConvertTo-SecureString -AsPlainText "pass.123" -Force) -Path $("ou=" + $deild + ",ou=notendur" + $dcpath) -Enabled $true
    Add-ADGroupMember -Identity $($deild+"_"+$skrifstofa) -Members $(Get-Name -name $u.nafn -full)
    #$tmp = Replace-IcelandicCharactersInString -str Get-Name -name $u.nafn -full
    #New-Item $("C:\inetpub\wwwroot\" + $tmp) -ItemType Directory
    #New-Item $("C:\inetpub\wwwroot\" + $tmp + "\index.html") -ItemType File -Value $("Vefsíðan " + $tmp + ".eep.is")
    #New-Website -Name $($tmp +"." + $webdomain) -HostHeader $($tmp +"." + $webdomain) -PhysicalPath $("C:\inetpub\wwwroot\" + $tmp)
}


#==========|MAKE FOLDER|============#
$deild = "Allir"

New-Item c:\DATA\$deild -ItemType Directory
#==========|MODIFY ACCESS|#
$rettindi = Get-Acl -Path C:\DATA\$deild
$nyRettindi = New-Object System.Security.AccessControl.FileSystemAccessRule( $($env:USERDOMAIN + "\" + $deild), "Modify", "Allow")
$rettindi.AddAccessRule($nyRettindi)

Set-Acl -Path C:\DATA\$deild $rettindi

New-SmbShare -name $deild -Path C:\DATA\$deild -FullAccess Everyone
#===================================#

#============|PRINTER|==============#

#-- Add Printer driver
Add-PrinterDriver -Name "HP LaserJet 2300L PCL6 Class Driver"
#-- The Printer
Add-Printer -Name $($deild + "_Prentari") -DriverName "HP LaserJet 2300L PCL6 Class Driver" -PortName "LPT1:" -Shared -ShareName $($deild + "_PRINT") -Published
#===================================#