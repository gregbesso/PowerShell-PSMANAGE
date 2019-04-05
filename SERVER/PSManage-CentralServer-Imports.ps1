####################################################################################################################
#
# No new changes in 2019, just testing git. :P
#
####################################################################################################################

# loads AD module
function Get-ModuleAD() {
<# 
.SYNOPSIS 
Imports the Active Directory PowerShell module for use on remote systems.
.DESCRIPTION 
This function will create a copy of the Active Directory PowerShell module, renamed so any -AD commands are -RemAD on the remote system. The session is 
created, the module loaded, and then the session is exported out. Then that exported session is imported as a new module on the remote system.
.EXAMPLE 
Get-ModuleAD
#>
    If ((Get-Module -Name RemAD | Measure-Object).Count -lt 1) {
        # Adding Active Directory connection...
        # https://technet.microsoft.com/en-us/magazine/ff720181.aspx
        If ((Get-Module -ListAvailable -Name RemAD | Measure-Object).Count -lt 1) {
            Write-Output "Active Directory Module needs to be exported..."
            $sessionActiveDirectory = New-PSSession -ComputerName $global:impDomainController
            Invoke-Command { Import-Module ActiveDirectory } -Session $sessionActiveDirectory
            Export-PSSession -Session $sessionActiveDirectory -CommandName *-AD* -OutputModule RemAD -AllowClobber -Force | Out-Null
            Remove-PSSession -Session $sessionActiveDirectory
        } Else { Write-Output "Active Directory Module is already exported..." }
        Write-Output "Active Directory Module is now being initialized..."
        Import-Module RemAD -Prefix Rem -DisableNameChecking
    }
}

# loads Exchange module
function Get-ModuleExchange() { 
<# 
.SYNOPSIS 
Imports the Exchange Server PowerShell module for use on remote systems.
.DESCRIPTION 
This function will ccreate a new PowerShell session on an Exchange server using the ConnectionUri to that server.
.EXAMPLE 
Get-ModuleExchange
#>   
    $checkSessions = (Get-PSSession).ConfigurationName
    $thereAlready = $false
    ForEach ($session in $checkSessions) {
        If ($session -eq 'Microsoft.Exchange') { $thereAlready = $true }
    }

    If ($thereAlready -eq $false) {
        # Adding Exchange connection...
        # https://technet.microsoft.com/en-us/library/Dd335083(v=EXCHG.150).aspx
        # once done, call Remove-PSSession $SessionExchange
        Write-Output "Exchange Server Module is now being initialized..."
        $sessionExchange = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$global:impExchangeServer/PowerShell/" -Authentication Kerberos
        Import-PSSession $sessionExchange -DisableNameChecking | Out-Null
    }
}

# gets last logon date of a specified AD user
function Get-ADUserLastLogon() {
<# 
.SYNOPSIS 
Find out the last time an AD user account logged into any domain controller
.DESCRIPTION 
Get-ADUserLastLogon queries every domain controller for a specified user and returns the lastLogon and lastLogonTimestamp to find out the most recent value for that account.
.PARAMETER SamAccountName
The unique name for the account, typically first initial and last name
.EXAMPLE 
Get-ADUserLastLogon -SamAccountName jyoung
#>
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$SamAccountName
    )

    $dcs = Get-RemADDomainController -Filter {Name -like "*"}
    $time = 0
    $timestamp = 0
    foreach($dc in $dcs)
    { 
        $hostname = $dc.HostName
        $filter = [scriptblock]::Create("SamAccountName -eq `"$SamAccountName`"")
        $user = Get-ADUser -Filter $filter -Properties *
        if($user.LastLogon -gt $time) 
        {
            $time = $user.LastLogon
        }
        if($user.LastLogonTimestamp -gt $timestamp) 
        {
            $timestamp = $user.LastLogonTimestamp
        }
    }
    $dt = [DateTime]::FromFileTime($time)
    $dts = [DateTime]::FromFileTime($timestamp)
    # return the more recent of the two values. sometimes one is older than another for some reason...
    If ($dt -gt $dts) { Return $dt } Else { Return $dts }
}

# gets last bad password attempt of a specified AD user
function Get-ADUserLastBadPasswordAttempt() {
<# 
.SYNOPSIS 
Find out the last time an AD user had a failed logon attempt
.DESCRIPTION 
Get-ADUserLastLogon queries every domain controller for a specified user and returns the lastLogon and lastLogonTimestamp to find out the most recent value for that account.
.PARAMETER SamAccountName
The unique name for the account, typically first initial and last name
.EXAMPLE 
Get-ADUserLastLogon -SamAccountName jyoung
#>
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$SamAccountName
    )

    $dcs = Get-RemADDomainController -Filter {Name -like "*"}

    foreach($dc in $dcs)
    { 
        $hostname = $dc.HostName
        $filter = [scriptblock]::Create("SamAccountName -eq `"$SamAccountName`"")
        $user = Get-ADUser -Filter $filter -Properties *

        $timestamp = $user.LastBadPasswordAttempt

    }

    Return $timestamp 
}

# copy of Update-PSManageInfoGatherLocal from client-side PSManage scripts to scan XP computers that can't get task created or scan themselves...
function Update-PSManageInfoGatherRemote() {
Param (
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
    [string]$computerName
)

    BEGIN{}
    PROCESS{
        Try {
            #
            # create folders to store cached info that is gathered...            
            #
            If (!(Test-Path "$global:psmServerLocalPath\Local")) { New-Item -ItemType Directory -Path "$global:psmServerLocalPath\Local" }
            If (!(Test-Path "$global:psmServerLocalPath\SP")) { New-Item -ItemType Directory -Path "$global:psmServerLocalPath\SP" }

            #
            # get all info gathered and store in variables...            
            #           
            $getCS = Get-WmiObject Win32_ComputerSystem -ComputerName $computerName | Select-Object -Property PSComputerName, BootupState, ThermalState, Status, Domain, CurrentTImeZone, NumberOfLogicalProcessors, NumberOfProcessors, PrimaryOwnerName, Manufacturer, Model, SystemFamily, SystemSKUNumber, SystemType, TotalPhysicalMemory, UserName
            $getOS = Get-WmiObject Win32_OperatingSystem -ComputerName $computerName | Select-Object -Property PSComputerName, FreePhysicalMemory, FreeSpaceInPagingFiles, FreeVirtualMemory, BuildNumber, BuildType, Caption, CodeSet, CountryCode, CurrentTimeZone, InstallDate, LastBootUpTime, LocalDateTime, Manufacturer, NumberOFProcesses, NumberOfUsers, OperatingSystemSKU, OSArchitecture, OSLanguage, OSType, SerialNumber, TotalVirtualMemorySize, TotalVisibleMemorySize, Version
            $getBIOS = Get-WmiObject Win32_BIOS -ComputerName $computerName | Select-Object -Property PSComputerName, BIOSVersion, CurrentLanguage, Manufacturer, ReleaseDate, SerialNumber, SMBIOSBIOSVersion, Version
            $getDisks = Get-WmiObject Win32_LogicalDisk -ComputerName $computerName | Select-Object -Property DeviceID, DriveType, Description, FileSystem, FreeSpace, Size, VolumeName
            $getProducts = Get-WmiObject Win32_Product -ComputerName $computerName | Select-Object -Property @{Name="ProductName";Expression={$_."Name"}},@{Name="ProductVersion";Expression={$_."Version"}},Vendor,InstallDate,InstallSource,LocalPackage,PackageName,IdentifyingNumber
            $getCerts = Get-ComputerCerts



            #
            # cycle through CS, OS, BIOS objects and combine them into one getAll object with renamed column names and formatted values...           
            #            
            $getAll = New-Object -TypeName PSObject
            $getAll | Add-Member -MemberType NoteProperty -Name 'PSComputerName' -Value $computerName
            $getPSVersion = $PSVersionTable.PSVersion.Major
            $getAll | Add-Member -MemberType NoteProperty -Name 'PSVersion' -Value $getPSVersion           

            #add CS items to getAll...
            $getCS.PSObject.properties | ForEach-Object {
                If ($_.Name -ne 'PSComputerName') { 
                    $newName = "CS-" + $_.Name                 
                    If (($_.Name -eq 'InstallDate') -Or ($_.Name -eq 'LastBootUpTime') -Or ($_.Name -eq 'LocalDateTime') -Or ($_.Name -like '*Date*')) {       
                        If ($_.Value.Length -lt 1) { $tempValue = '19500101000000.000000-240' } Else { $tempValue = $_.Value }
                        $newValue = [System.Management.ManagementDateTimeConverter]::ToDateTime($tempValue)
                    } Else {
                        $newValue = $_.Value
                    }
                    $getAll | Add-Member -MemberType NoteProperty -Name $newName -Value $newValue -Force
                }
            }
            #add OS items to getAll...
            $getOS.PSObject.properties | ForEach-Object {
                If ($_.Name -ne 'PSComputerName') { 
                    $newName = "OS-" + $_.Name
                    If (($_.Name -eq 'InstallDate') -Or ($_.Name -eq 'LastBootUpTime') -Or ($_.Name -eq 'LocalDateTime') -Or ($_.Name -like '*Date*')) {
                        If ($_.Value.Length -lt 1) { $tempValue = '19500101000000.000000-240' } Else { $tempValue = $_.Value }
                        $newValue = [System.Management.ManagementDateTimeConverter]::ToDateTime($tempValue)
                    } Else {
                        $newValue = $_.Value
                    }                
                    $getAll | Add-Member -MemberType NoteProperty -Name $newName -Value $newValue
                }

            }
            #add BIOS items to getAll...
            $getBIOS.PSObject.properties | ForEach-Object {
                If ($_.Name -ne 'PSComputerName') { 
                    $newName = "BIOS-" + $_.Name
                    If (($_.Name -eq 'InstallDate') -Or ($_.Name -eq 'LastBootUpTime') -Or ($_.Name -eq 'LocalDateTime') -Or ($_.Name -like '*Date*')) {
                        If ($_.Value.Length -lt 1) { $tempValue = '19500101000000.000000-240' } Else { $tempValue = $_.Value }
                        $newValue = [System.Management.ManagementDateTimeConverter]::ToDateTime($tempValue)
                    } Else {
                        $newValue = $_.Value
                    }                
                    $getAll | Add-Member -MemberType NoteProperty -Name $newName -Value $newValue
                }

            }
            $getAll | Export-Clixml "$global:psmServerLocalPath\Local\getAll-$computerName.xml"


            #
            # repeat similar steps but for each disk found on the the system...          
            #
            $getDisks | Export-Clixml "$global:psmServerLocalPath\Local\getDisks-$computerName.xml"
            $getDisks | ForEach {
                #exclude network drives, include all others...
                If ($_.DriveType -ne 4) {
                    #$getDisk = New-Object -TypeName PSObject
                    $_.PSObject.properties | ForEach-Object {
                        If (($_.Name -eq 'InstallDate') -Or ($_.Name -eq 'LastBootUpTime') -Or ($_.Name -eq 'LocalDateTime') -Or ($_.Name -like '*Date*')) {       
                            If ($_.Value.Length -lt 1) { $tempValue = '19500101000000.000000-240' } Else { $tempValue = $_.Value }
                            $newValue = [System.Management.ManagementDateTimeConverter]::ToDateTime($tempValue)
                            $_.Value = $newValue
                        }                        
                    }
                    $deviceID = $_.DeviceID[0]                                        
                    #If ($_.PSComputerName) { $getDisk.PSObject.Properties.Remove('PSComputerName') }
                    $_ | Add-Member -MemberType NoteProperty -Name 'PSComputerName' -Value $computerName
                    $_ | Export-Clixml "$global:psmServerLocalPath\Local\getDisk-$computerName-$deviceID.xml"
                }
            }

            #
            # repeat similar steps but for each installed product found on the system...           
            #
            $getProducts | ForEach {
                $_.PSObject.properties | ForEach-Object {            
                    If (($_.Name -eq 'InstallDate') -Or ($_.Name -eq 'LastBootUpTime') -Or ($_.Name -eq 'LocalDateTime') -Or ($_.Name -like '*Date*')) {                  
                        If ($_.Value.Length -lt 1) { $tempValue = '19500101000000.000000-240' } Else { $tempValue = $_.Value }
                        If ($tempValue.Length -eq 8) { $tempValue += '000000.000000-240' }
                        $newValue = [System.Management.ManagementDateTimeConverter]::ToDateTime($tempValue)
                        $_.Value = $newValue
                    }
                } 
                $_ | Add-Member -MemberType NoteProperty -Name 'PSComputerName' -Value $computerName               
            }
            $getProducts | Export-Clixml "$global:psmServerLocalPath\Local\getProducts-$computerName.xml"



            #
            # repeat similar steps but for each certificate in the local computer store...          
            #
            $getCerts | Export-Clixml "$global:psmServerLocalPath\Local\getCerts-$computerName.xml"

                       
        } Catch {
                    Write-Warning "Error occurred: $_.Exception.Message"
        }
    }
    End {}
}

# function that compares the gathered information and decides if SharePoint needs to get updated with anything...
function Update-PSManageInfoCompareRemote() {
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$spWeb,

        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$computerName
    )

    BEGIN{}
    PROCESS{
        Try {
            #
            # get all info gathered and store in variables...            
            #            
            $compareAll = 0
            $compareDisks = 0
            $compareProductsAdd = 0
            $compareProductsRemove = 0
            $compareCertsAdd = 0
            $compareCertsRemove = 0

            #
            # cycle through CS, OS, BIOS objects and combine them into one getAll object with renamed column names and formatted values...           
            #            
            $getAll = Import-Clixml "$global:psmServerLocalPath\Local\getAll-$computerName.xml"
            If (!(Test-Path "$global:psmServerLocalPath\SP\getAll-$computerName.xml")) { $getAllSP = New-Object -TypeName PSObject } Else { $getAllSP = Import-Clixml "$global:psmServerLocalPath\SP\getAll-$computerName.xml" }
     
            $getAll.PSObject.properties | ForEach-Object {
                If (($_.Name -NotLike '*LocalDateTime*') -And ($_.Name -NotLike '*Memory*') -And ($_.Name -NotLike '*Paging*') -And ($_.Name -NotLike '*NumberOfProcesses*' )) {
                    If (Compare-Object $getAll $getAllSP -Property $_.Name) { 
                        $compareAll++
                    }
                }
            }

            #
            # repeat similar steps but for each disk found on the the system...          
            # 
            $getDisks = Import-Clixml "$global:psmServerLocalPath\Local\getDisks-$computerName.xml"         
            $getDisks | ForEach {                
                #exclude network drives, include all others...
                If ($_.DriveType -ne 4) {
                    $deviceID = $_.DeviceID[0]
                    $getDisk = Import-Clixml "$global:psmServerLocalPath\Local\getDisk-$computerName-$deviceID.xml"

                    If (!(Test-Path "$global:psmServerLocalPath\SP\getDisk-$computerName-$deviceID.xml")) { $getDiskSP = New-Object -TypeName PSObject } Else { $getDiskSP = Import-Clixml "$global:psmServerLocalPath\SP\getDisk-$computerName-$deviceID.xml" }
                    $getDisk.PSObject.properties | ForEach-Object {
                        If (($_.Name -NotLike '*Memory*') -And ($_.Name -NotLike '*Paging*') -And ($_.Name -NotLike '*NumberOfProcesses*' )) {
                            If (Compare-Object $getDisk $getDiskSP -Property $_.Name) { 
                                $compareDisks++ 
                            }
                        }
                    }
                }
            }

            #
            # repeat similar steps but for each installed product found on the system...           
            #            
            $getProducts = Import-Clixml "$global:psmServerLocalPath\Local\getProducts-$computerName.xml"

            If (!(Test-Path "$global:psmServerLocalPath\SP\getProducts-$computerName.xml")) { $getProductsSP = New-Object -TypeName PSObject } Else { $getProductsSP = Import-Clixml "$global:psmServerLocalPath\SP\getProducts-$computerName.xml" }

            $getProductsAdd = @()
            $getProductsRemove = @()
            # get list of newly installed products...
            $getProducts | ForEach {
                $isNew = $True
                $idLocal = $_.IdentifyingNumber
                $getProductsSP | ForEach {
                    $idSP = $_.IdentifyingNumber
                    If ($idLocal -eq $idSP) { $isNew = $False }
                }
                If ($isNew -eq $True) { 
                    $object1 = New-Object PSObject -Property @{
                        PSComputerName=$_.PSComputerName
                        ProductName=$_.ProductName
                        ProductVersion=$_.ProductVersion
                        Vendor=$_.Vendor
                        InstallDate=$_.InstallDate
                        InstallSource=$_.InstallSource
                        LocalPackage=$_.LocalPackage
                        PackageName=$_.PackageName
                        IdentifyingNumber=$_.IdentifyingNumber         
                    }
                    $getProductsAdd += $object1
                    $compareProductsAdd++
                }
            }
            # get list of recently removed products...
            $getProductsSP | ForEach {
                $isNew = $True
                $idLocal = $_.IdentifyingNumber
                $getProducts | ForEach {
                    $idSP = $_.IdentifyingNumber
                    If ($idLocal -eq $idSP) { $isNew = $False }

                }
                If ($isNew -eq $True) { 
                    $object1 = New-Object PSObject -Property @{
                        PSComputerName=$_.PSComputerName
                        ProductName=$_.ProductName
                        ProductVersion=$_.ProductVersion
                        Vendor=$_.Vendor
                        InstallDate=$_.InstallDate
                        InstallSource=$_.InstallSource
                        LocalPackage=$_.LocalPackage
                        PackageName=$_.PackageName
                        IdentifyingNumber=$_.IdentifyingNumber         
                    }
                    $getProductsRemove += $object1
                    $compareProductsRemove++
                }
            }



            #
            # repeat similar steps but for each certificate on the system         
            #            
            $getCerts = Import-Clixml "$global:psmServerLocalPath\Local\getCerts-$computerName.xml"

            If (!(Test-Path "$global:psmServerLocalPath\SP\getCerts-$computerName.xml")) { $getCertsSP = New-Object -TypeName PSObject } Else { $getCertsSP = Import-Clixml "$global:psmServerLocalPath\SP\getCerts-$computerName.xml" }

            $getCertsAdd = @()
            $getCertsRemove = @()
            # get list of newly installed Certs...
            $getCerts | ForEach {
                $isNew = $True
                $idLocal = $_.Thumbprint
                $getCertsSP | ForEach {
                    $idSP = $_.Thumbprint
                    If ($idLocal -eq $idSP) { $isNew = $False }
                }
                If ($isNew -eq $True) { 
                    $object1 = New-Object PSObject -Property @{
                        PSComputerName=$_.PSComputerName;
                        DnsNameList=$_.DnsNameList;
                        FriendlyName=$_.FriendlyName;
                        NotAfter=$_.NotAfter;
                        NotBefore=$_.NotBefore;
                        HasPrivateKey=$_.HasPrivateKey;
                        SerialNumber=$_.SerialNumber;
                        Thumbprint=$_.Thumbprint;
                        CertVersion=$_.Version;
                        Handle=$_.Handle;
                        Issuer=$_.Issuer;
                        Subject=$_.Subject;         
                    }
                    $getCertsAdd += $object1
                    $compareCertsAdd++
                }
            }
            # get list of recently removed Certs...
            $getCertsSP | ForEach {
                $isNew = $True
                $idLocal = $_.Thumbprint
                $getCerts | ForEach {
                    $idSP = $_.Thumbprint
                    If ($idLocal -eq $idSP) { $isNew = $False }

                }
                If ($isNew -eq $True) { 



                    $object1 = New-Object PSObject -Property @{
                        DnsNameList=$_.DnsNameList;
                        FriendlyName=$_.FriendlyName;
                        NotAfter=$_.NotAfter;
                        NotBefore=$_.NotBefore;
                        HasPrivateKey=$_.HasPrivateKey;
                        SerialNumber=$_.SerialNumber;
                        Thumbprint=$_.Thumbprint;
                        CertVersion=$_.Version;
                        Handle=$_.Handle;
                        Issuer=$_.Issuer;
                        Subject=$_.Subject;       
                    }
                    $getCertsRemove += $object1
                    $compareCertsRemove++
                }
            }



            #
            # If comparisons found anything, update SharePoint for each object...
            #
            If (($compareAll -gt 0) -Or ($compareDisks -gt 0) -Or ($compareProductsAdd -gt 0) -Or ($compareProductsRemove -gt 0) -Or ($compareCertsAdd -gt 0) -Or ($compareCertsRemove -gt 0)) {
                #open SP session so updates can be made...
                $sessionSharePoint = New-PSSession -ComputerName $global:psmSharePointServer

                If ($compareAll -gt 0) {
                    $spListName = 'PSMANAGE-COMPUTERS'
                    #Update-PSManageInfoSharePoint -getAll $getAll -spWeb $spWeb -spListName $spListName -computerName $computerName
                    Update-PSManageInfoSharePoint -getAll $getAll -spWeb $spWeb -spListName $spListName
                    Copy-Item -Path "$global:psmServerLocalPath\Local\getAll-$computerName.xml" -Destination "$global:psmServerLocalPath\SP\getAll-$computerName.xml" -Force
                }

                If ($compareDisks -gt 0) {
                    $spListName = 'PSMANAGE-DISKS'
                    $getDisks | ForEach {
                        #exclude network drives, include all others...
                        If ($_.DriveType -ne 4) {
                            $deviceID = $_.DeviceID[0]
                            $getDisk = Import-Clixml "$global:psmServerLocalPath\Local\getDisk-$computerName-$deviceID.xml"
                            $compareDisk = 0
                            #if different than last time, upload to SharePoint
                            If (!(Test-Path "$global:psmServerLocalPath\SP\getDisk-$computerName-$deviceID.xml")) { $getDiskSP = New-Object -TypeName PSObject } Else { $getDiskSP = Import-Clixml "$global:psmServerLocalPath\SP\getDisk-$computerName-$deviceID.xml" }
                            $getDisk.PSObject.properties | ForEach-Object {
                                If (($_.Name -NotLike '*Memory*') -And ($_.Name -NotLike '*Paging*') -And ($_.Name -NotLike '*NumberOfProcesses*' )) {
                                    If (Compare-Object $getDisk $getDiskSP -Property $_.Name) { $compareDisk++ }
                                }
                            }
                            If ($compareDisk -gt 0) {
                                Update-PSManageInfoSharePoint -getAll $getDisk -spWeb $spWeb -spListName $spListName
                                Copy-Item -Path "$global:psmServerLocalPath\Local\getDisk-$computerName-$deviceID.xml" -Destination "$global:psmServerLocalPath\SP\getDisk-$computerName-$deviceID.xml" -Force
                            }
                        }
                    }
                }


                If ($compareProductsAdd -gt 0) {
                    $spListName = 'PSMANAGE-PRODUCTS'                 
                    Update-PSManageInfoSharePoint -getAll $getProductsAdd -spWeb $spWeb -spListName $spListName
                }

                # Remove-PSManageInfoSharePointLocal
                If ($compareProductsRemove -gt 0) {
                    $spListName = 'PSMANAGE-PRODUCTS'
                    Remove-PSManageInfoSharePoint -getAll $getProductsRemove -spWeb $spWeb -spListName $spListName -spColumnName 'IdentifyingNumber' -computerName $computerName                    
                }


                If ($compareCertsAdd -gt 0) {
                    $spListName = 'PSMANAGE-CERTIFICATES'                 
                    Update-PSManageInfoSharePoint -getAll $getCertsAdd -spWeb $spWeb -spListName $spListName
                }

                If ($compareCertsRemove -gt 0) {
                    $spListName = 'PSMANAGE-CERTIFICATES'
                    Remove-PSManageInfoSharePoint -getAll $getCertsRemove -spWeb $spWeb -spListName $spListName -spColumnName 'Thumbprint' -computerName $computerName                    
                }


                If (($compareProductsAdd -gt 0) -Or ($compareProductsRemove -gt 0)) {
                    Copy-Item -Path "$global:psmServerLocalPathe\Local\getProducts-$computerName.xml" -Destination "$global:psmServerLocalPath\SP\getProducts-$computerName.xml" -Force
                }

                If (($compareCertsAdd -gt 0) -Or ($compareCertsRemove -gt 0)) {
                    Copy-Item -Path "$global:psmServerLocalPath\Local\getCerts-$computerName.xml" -Destination "$global:psmServerLocalPath\SP\getCerts-$computerName.xml" -Force
                }

                # close SP session once done using...
                If ($sessionSharePoint) { $sessionSharePoint | Remove-PSSession }
            }

        } Catch {
                    Write-Warning $_.Exception.Message
        }
    }
    End {}


}

# function to remove things from SharePoint, copied from PSManageImport from client scripts...
# updates SharePoint with various information about users and computers...
function Remove-PSManageInfoSharePoint() {
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [object]$getAll,
        [string]$spListName,
        [string]$spWeb,
        [string]$spColumnName,
        [string]$computerName
    )

    BEGIN{}
    PROCESS{
        Try {            
            #connect to sharepoint and send data over...
            If (!($sessionSharePoint)) { $sessionSharePoint = New-PSSession -ComputerName $global:psmSharePointServer}

            Invoke-Command -Session $sessionSharePoint -ScriptBlock {
                # get input from function calling remote session
                Param ($getAll, $spWeb, $spListName, $spColumnName, $computerName)

                Add-PSSnapin Microsoft.SharePoint.PowerShell
                #send the list information over to the session
                $spWeb = Get-SPWeb $spWeb
                $spListCheck = $spWeb.Lists.TryGetList("$spListName")

                #if list not existing, create it...
                If ($spListCheck -eq $null) {
                    # do nothing        
                } Else {
                    #get list info...
                    $spList = $spWeb.Lists[$spListName]
                    $getAllIDs = $getAll.IdentifyingNumber

                    ForEach ($getAllID in $getAllIDs) {                        
                        If ($spColumnName -eq 'IdentifyingNumber') { 
                            $spList = $spWeb.Lists[$spListName]
                            $spListItem = $spList.Items | Where {($_["$spColumnName"] -eq $getAllID) -And ($_["PSComputerName"] -eq $computerName)}
                            $spListItem.Delete()
                        }
                    }
                }
            } -ArgumentList $getAll, $spWeb, $spListName, $spColumnName, $computerName

        } Catch {
            Write-Warning "Error occurred: $_.Exception.Message"
        }
    }
    End {}
}

# updates SharePoint with various information about users and computers...
function Update-PSManageInfoSharePoint() {
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [object]$getAll,
        [string]$spListName,
        [string]$spWeb
    )

    BEGIN{}
    PROCESS{
        Try {

            #connect to sharepoint and send data over...
            $sessionSharePoint = New-PSSession -ComputerName $global:psmSharePointServer
            Invoke-Command -Session $sessionSharePoint -ScriptBlock {
                # get input from function calling remote session
                Param ($getAll, $spWeb, $spListName)

                Add-PSSnapin Microsoft.SharePoint.PowerShell
                #send the list information over to the session
                $rightNow = Get-Date
                $spWeb = Get-SPWeb $spWeb
                $spListCheck = $spWeb.Lists.TryGetList("$spListName")
                $spListTemplate = $spWeb.ListTemplates["Custom List"]

                #if list not existing, create it...
                If ($spListCheck -eq $null) {
                    $spListCollection = $spWeb.Lists
                    $spListCollection.Add($spListName, $spListName, $spListTemplate) | Out-Null        
                }

                #get list info...
                $path = $spWeb.Url.Trim()
                $spList = $spWeb.Lists["$spListName"]
                $spFieldType = [Microsoft.SharePoint.SPFieldType]::Text
                $PSComputerName = ""

                #start loop for array...
                $getAll | ForEach {
                    #get computer name for this item being added/updated...
                    $compareDeviceID = $_.DeviceID
                    $compareIdentifyingNumber = $_.IdentifyingNumber
                    $compareSamAccountName = $_.'AD-SamAccountName'
                    $compareObjectClass = $_.'AD-ObjectClass'

                    $_.PSObject.properties | ForEach-Object {
                        If ($_.Name -Like '*PSComputerName*') { $comparePSComputerName = $_.Value }
                    }

                    If ($spList.Fields.ContainsField("DeviceID") -eq $True) {
                        $newItem = $spList.Items | ?{($_["Title"] -eq "$comparePSComputerName") -And ($_["DeviceID"] -eq "$compareDeviceID")}
                    } ElseIf ($spList.Fields.ContainsField("ProductName") -eq $True) {
                        $newItem = $spList.Items | ?{($_["Title"] -eq "$comparePSComputerName") -And ($_["IdentifyingNumber"] -eq "$compareIdentifyingNumber")}
                    } ElseIf (($spList.Fields.ContainsField("AD-SamAccountName") -eq $True) -And ($compareObjectClass -eq 'user')) {
                        $newItem = $spList.Items | ?{($_["Title"] -eq "$compareSamAccountName")}
                    } Else {
                        $newItem = $spList.Items | ?{$_["Title"] -eq "$comparePSComputerName"}
                    }

                    #add new item if existing list entry not found for this computer...
                    If ($newItem.Count -lt 1) { $newItem = $spList.AddItem() }

                    #loop through all properties and update the item for ComputerSystem...
                    $_.PSObject.properties | ForEach-Object {
                            Try {
                            #get the name of the computer for the sharepoint list item's title column...
                            If ($spListName -eq 'PSMANAGE-USERS') {
                                If ($_.Name -Like '*SamAccountName*') { 
                                    $newItem["Title"] = $compareSamAccountName
                                    $newItem.Update()
                                }
                            } Else {
                                If ($_.Name -Like '*PSComputerName*') { 
                                    $PSComputerName = $_.Value 
                                    $newItem["Title"] = $PSComputerName
                                    $newItem.Update()
                                }
                            }
                            $thisName = $_.Name
                            $thisValue = $_.Value


                            $thisType = $_.TypeNameOfValue
                            $thisLength = $thisValue.Length

                            # trim string if not multi-line so it fits in the standard sharepoint 255 text fields...
                            If (($_.TypeNameOfValue -eq 'System.String') -And ($thisValue.Length -gt 255) -And ($thisName -NotLike '*Description*')) {
                                $thisValue = $thisValue.Substring(0,255)
                            }

                            If ($spList.Fields.ContainsField("$thisName") -eq $False) {
                                #find out what data type the field needs to be that is not yet created...
                                If ($_.TypeNameOfValue -eq 'System.Boolean') { 
                                    $thisFieldType = [Microsoft.SharePoint.SPFieldType]::Boolean 
                                } ElseIf ($_.TypeNameOfValue -eq 'System.Int16') {
                                    $thisFieldType = [Microsoft.SharePoint.SPFieldType]::Integer
                                } ElseIf ($_.TypeNameOfValue -eq 'System.Int32') {
                                    $thisFieldType = [Microsoft.SharePoint.SPFieldType]::Integer
                                } ElseIf ($_.TypeNameOfValue -eq 'System.UInt64') {
                                    $thisFieldType = [Microsoft.SharePoint.SPFieldType]::Number
                                } ElseIf ($_.TypeNameOfValue -eq 'System.Double') {
                                    $thisFieldType = [Microsoft.SharePoint.SPFieldType]::Number
                                } ElseIf ($_.TypeNameOfValue -eq 'System.DateTime') {
                                    $thisFieldType = [Microsoft.SharePoint.SPFieldType]::DateTime
                                } ElseIf (($_.TypeNameOfValue -eq 'System.String') -And (($thisName -Like '*Description*') -Or ($thisValue.Length -gt 255))) {
                                    $thisFieldType = [Microsoft.SharePoint.SPFieldType]::Note
                                } Else {
                                    $thisFieldType = $spFieldType
                                }
                                #add the field to the list...
                                If ($_.TypeNameOfValue -NotLike "*Deserialized.System.Management*") { 
                                    $spList.Fields.Add("$thisName", $thisFieldType, $false) | Out-Null
                                }
                            }

                            #update sharepoint list item as long as data type is not one of those objects that error it up...
                            If (($_.TypeNameOfValue -NotLike "*Deserialized.System.Management*") -And ($_.TypeNameOfValue -NotLike "*Deserialized.Microsoft.ActiveDirectory.Management.ADPropertyValueCollection*")) {
                                $newItem["$thisName"] = $thisValue
                                $newItem.Update()
                            }
                        } Catch{}
                    } 

                    #
                    # check for, and add if necessary, the PSLastPhoneHome column
                    #
                    If ($spList.Fields.ContainsField('PSLastPhoneHome') -eq $False) {
                        $thisFieldType = [Microsoft.SharePoint.SPFieldType]::DateTime
                        $spList.Fields.Add('PSLastPhoneHome', $thisFieldType, $false)
                    }
                    $newItem.Update()
                    #
                    # check for, and add if necessary, the PSLastUpdate column
                    #
                    If ($spList.Fields.ContainsField('PSLastUpdate') -eq $False) {
                        $thisFieldType = [Microsoft.SharePoint.SPFieldType]::DateTime
                        $spList.Fields.Add('PSLastUpdate', $thisFieldType, $false)
                    }
                    $newItem['PSLastUpdate'] = $rightNow
                    $newItem.Update()

                    #once done adding fields...
                    $spList.Update()
                #END loop for array
                }
            } -ArgumentList $getAll, $spWeb, $spListName

            #close session once done...
            $sessionSharePoint | Remove-PSSession
        } Catch {
            Write-Warning "Error occurred: $_.Exception.Message"
        }
    }
    End {}
}

# updates SharePoint with various information about users and computers...
function Remove-PSManageItemsFromSharePoint() {
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [object]$getAll,
        [string]$remove,
        [string]$spWeb
    )

    BEGIN{}
    PROCESS{
        Try {            
            #connect to sharepoint and send data over...
            If (!($sessionSharePoint)) { $sessionSharePoint = New-PSSession -ComputerName $global:psmSharePointServer}

            Invoke-Command -Session $sessionSharePoint -ScriptBlock {
                # get input from function calling remote session
                Param ($getAll, $spWeb, $remove)

                Add-PSSnapin Microsoft.SharePoint.PowerShell
                #send the list information over to the session
                $spWeb = Get-SPWeb $spWeb
                
                #get list info...
                $spList = $spWeb.Lists[$spListName]

                If ($remove -eq 'computers') { 
                    $lists = 'PSMANAGE-COMPUTERS','PSMANAGE-CERTIFICATES','PSMANAGE-DISKS','PSMANAGE-PRODUCTS','PSMANAGE-TASKS' 
                    $getAllIDs = $getAll.PSComputerName
                    $spColumnName = 'PSComputerName'
                } ElseIf ($remove -eq 'users') {
                    $lists = 'PSMANAGE-USERS'
                    $getAllIDs = $getAll.SamAccountName 
                    $spColumnName = 'SamAccountName'
                }
                ForEach ($getAllID in $getAllIDs) {                                                  
                    $lists | ForEach {
                        $spListName = $_
                        $spList = $spWeb.Lists[$spListName]
                        Try {
                            $spListItem = $spList.Items | Where {($_["$spColumnName"] -eq $getAllID)}
                            $spListItem.Delete()
                        } Catch {}
                    }
                }

            } -ArgumentList $getAll, $spWeb, $remove

        } Catch {
            Write-Warning "Error occurred: $_.Exception.Message"
        }
    }
    End {}
}

# function that takes a computer name and gathers various information about it FROM AD, and prepares for entry to SharePoint
function Get-ADComputerDetails() {
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$computerName
    )

    BEGIN{}
    PROCESS{
        Try {
            $filter = [scriptblock]::Create("Name -eq `"$computerName`"")
            $getAD = Get-RemADComputer  -Filter $filter -Property CN, Created, DistinguishedName, DNSHostName, Enabled, InstanceType, IPv4Address, IPv6Address, KerberosEncryptionType, LastLogonDate, localPolicyFlags, LockedOut, logonCount, Modified, Name, ObjectCategory, ObjectClass, OBjectGUID, OperatingSystem, OperatingSystemServicePack, OperatingSystemVersion, PasswordExpired, PasswordLastSet, PrimaryGroup, PrimaryGroupID, SamAccountName, ServicePrincipalNames, SID, TrustedForDelegation, UserAccountControl     

            #create and load getAll object with CS, OS and BIOS contents...
            $getAll = New-Object -TypeName PSObject

            # replace DC  name with computer name, so weird that this is needed :P
            $getAD.PSComputerName = $getAD.CN

            $getAD.PSObject.properties | ForEach-Object {
                If ($_.Name -ne 'PSComputerName') { $newName = "AD-" + $_.Name } Else { $newName = $_.Name } 
                If (($_.Name -eq 'InstallDate') -Or ($_.Name -eq 'LastBootUpTime') -Or ($_.Name -eq 'LocalDateTime')) {       
                    If ($_.Value.Length -lt 1) { $tempValue = '19500101000000.000000-240' } Else { $tempValue = $_.Value }
                    $newValue = [System.Management.ManagementDateTimeConverter]::ToDateTime($tempValue)
                } Else {
                    $newValue = $_.Value
                }
                $getAll | Add-Member -MemberType NoteProperty -Name $newName -Value $newValue
            }
            $getAll.PSObject.Properties.Remove('AD-RunspaceId')
            $getAll.PSObject.Properties.Remove('AD-PSShowComputerName')

            # Next, send over the computer information...
            Return $getAll
        } Catch {
                    Write-Warning "Error occurred: $_.Exception.Message"
        }
    }
    End {}
}

# gets the local computer stores personal certificates...
# COPIED from PSManageImport.ps1 file used on workstations, as is used for remote XP machines within this script too.
function Get-ComputerCerts() {
<# 
.SYNOPSIS 
Gathers info about any certificates in the local computer certificates store.
.DESCRIPTION 
Certificates are one of several local computer details gathered by this PowerShell tool, this function gets the certificate details and sends them to the 
function that is calling it. That function will then do something with the information.
.EXAMPLE 
Get-ComputerCerts
#>

    $compName = gc env:computername
    $getCertsNew = @()

    Try {
        $locationOrig = Get-Location
        Set-Location Cert:\
        Set-Location LocalMachine
        Set-Location My
        Get-Location
        $getCerts = Get-ChildItem
        Set-Location $locationOrig

    
        # get list of newly installed products...
        $getCerts | ForEach {
            $DnsNameList = $_.DnsNameList
            $FriendlyName = $_.FriendlyName
            $NotAfter = $_.NotAfter
            $NotBefore = $_.NotBefore
            $HasPrivateKey = $_.HasPrivateKey
            $SerialNumber = $_.SerialNumber
            $Thumbprint = $_.Thumbprint
            $CertVersion = $_.Version
            $Handle = $_.Handle
            $Issuer = $_.Issuer
            $Subject = $_.Subject

            $object1 = New-Object PSObject -Property @{
                PSComputerName=$compName;
                DnsNameList=$DnsNameList;
                FriendlyName=$FriendlyName;
                NotAfter=$NotAfter;
                NotBefore=$NotBefore;
                HasPrivateKey=$HasPrivateKey;
                SerialNumber=$SerialNumber;
                Thumbprint=$Thumbprint;
                CertVersion=$CertVersion;
                Handle=$Handle;
                Issuer=$Issuer;
                Subject=$Subject;                    
            }
            $getCertsNew += $object1
        }
    } Catch {}

    Return $getCertsNew
}

# parent function for updating users...
function Update-PSManageUsers() {

<#
update SP with any new users not yet existing in SP

DONE 1) get the ad users, get the SP users, and compare them to make an "add these users to SP" list
DONE 2) save the list of new users to email out later
DONE 3) get the users AD details
DONE 4) get the users EXCH details
5) add the users to SharePoint


DONE 6) get the ad users, get the SP users, and compare modified dates for each existing SP user to make an "update these user in SP" list
DONE 7) get the users AD details
DONE 8) get the users EXCH details
9) add the users to SharePoint


FIRST change: combine steps 1 and 6 to avoid doing double work later
SECOND change: make functions to add AD details to an object, and to add EXCH details to an object. no more looping, just single object update

#>

    $spListName = 'PSMANAGE-USERS'
    # load AD module if not already...
    Get-ModuleAD

    # step 1, get the AD users list
    $usersAD = Get-RemADUser -Filter * -Property Modified, SamAccountName | Select-Object -Property Modified, SamAccountName | Sort-Object SamAccountName

    # step 1, get the SP users list
    $usersSP = Get-PSManageUsersListDetailed

    # step 1, get the new users by comparing these two...
    $usersAdd = @()
    $usersAddEmail = @()
    ForEach ($userAD in $usersAD) {
        $alreadyExists = $False
        $ModifiedAD = $userAD.Modified
        $SamAccountNameAD = $userAD.SamAccountName
        ForEach ($userSP in $usersSP) {
            $SamAccountNameSP = $userSP.SamAccountName
            
            # if it exists, only add if modified date is different
            If ($SamAccountNameAD -eq $SamAccountNameSP) { 
                $alreadyExists = $True 
                $ModifiedSP = $userSP.Modified
                If ($ModifiedAD -gt $ModifiedSP) { 
                    $object1a = [pscustomobject]@{
                        Modified=$ModifiedAD;
                        SamAccountName=$SamAccountNameAD;              
                    }
                    $usersAdd += $object1a 
                }

            }
        }

        If ($alreadyExists -eq $False) {
            $object1 = [pscustomobject]@{
                Modified=$ModifiedAD;
                SamAccountName=$SamAccountNameAD;              
            }
            $usersAdd += $object1 
            $usersAddEmail += $object1
        }
    }


    # step 2, export new users to XML for later...
    If (!(Test-Path "$global:psmServerLocalPath\Server\Tracking")) { New-Item -ItemType Directory -Path "$global:psmServerLocalPath\Server\Tracking" }
    If (Test-Path "$global:psmServerLocalPath\Server\Tracking\addingToSPUsers.xml") { 
        $gotXML = Import-Clixml "$global:psmServerLocalPath\Server\Tracking\addingToSPUsers.xml"
    } Else { 
        $gotXML = @() 
    }
    $gotXML += $usersAddEmail
    $gotXML | Export-Clixml "$global:psmServerLocalPath\Server\Tracking\addingToSPUsers.xml"


    # step 3, get AD attributes for the users
    ForEach ($userAdd in $usersAdd) {
        $SamAccountName = $userAdd.SamAccountName
        $getADInfo = Get-ADUserDetails -SamAccountName $SamAccountName
        $getADInfo.PSObject.properties | ForEach-Object {
            $newName = $_.Name
            $newValue = $_.Value
            $userAdd | Add-Member -MemberType NoteProperty -Name $newName -Value $newValue -Force
        }


        $getEXCHInfo = Get-EXCHUserDetails -getAll $SamAccountName
        $getEXCHInfo.PSObject.properties | ForEach-Object {
            $newName = $_.Name
            $newValue = $_.Value
            $userAdd | Add-Member -MemberType NoteProperty -Name $newName -Value $newValue -Force
        }  

        # fix some values before sending...
        $userAdd.PSObject.properties | ForEach-Object {
            $TypeNameOfValue = $_.TypeNameOfValue
            If ($TypeNameOfValue -Like '*ProxyAddressCollection*') {
                $fixExchAddresses = ""
                $something = $_.Value
                $something | ForEach { $fixExchAddresses += $_ + "`n" }
                $_.Value = $fixExchAddresses
            }
        }

        # remove any values not needed
        $userAdd.PSObject.Properties.Remove('Length')


    }
    # steps 5 and 9, add users to SharePoint
    Update-PSManageInfoSharePoint -getAll $usersAdd -spWeb $spWeb -spListName $spListName


    #
    # once users added, check for any users deleted from AD that should be removed from SP too...
    #
    $usersRemove = @()
    ForEach ($userSP in $usersSP) {
        $stillExists = $False
        $samSP = $userSP.SamAccountName
        ForEach ($userAD in $usersAD) {
            $samAD = $userAD.SamAccountName
            If ($samSP -eq $samAD) { $stillExists = $True }
        }

        If ($stillExists -eq $False) {
            $object1 = [pscustomobject]@{
                SamAccountName=$samSP;              
            }
            $usersRemove += $object1
        }
    }
    #
    # Any users to be removed from SP, let's get it done...
    #
    If (!(Test-Path "$global:psmServerLocalPath\Server\Tracking")) { New-Item -ItemType Directory -Path "$global:psmServerLocalPath\Server\Tracking" }
    If (Test-Path "$global:psmServerLocalPath\Server\Tracking\removingFromSPUsers.xml") { 
        $gotXML = Import-Clixml "$global:psmServerLocalPath\Server\Tracking\removingFromSPUsers.xml"
    } Else { 
        $gotXML = @() 
    }
    $gotXML += $usersRemove
    $gotXML | Export-Clixml "$global:psmServerLocalPath\Server\Tracking\removingFromSPUsers.xml"

    If ($usersRemove.Count -gt 0) {
        Remove-PSManageItemsFromSharePoint -getAll $usersRemove -spWeb $spWeb -remove 'users'                       
    }
}

# function that takes a user's SamAccountName and gathers various information about it FROM AD, and prepares for entry to SharePoint
function Get-ADUserDetails() {
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$SamAccountName
    )

    BEGIN{}
    PROCESS{
        Try {            

            $filter = [scriptblock]::Create("SamAccountName -eq `"$SamAccountName`"")
            $getAD = Get-RemADUser  -Filter $filter -Properties * | Select AccountExpires,CanonicalName,City,CN,co,Company,Country,countryCode,Created,Department,Description,DisplayName,EmailAddress,Enabled,GivenName,HomeDirectory,HomeDrive,Initials,isDeleted,LockedOut,lockoutTime,logonCount,mail,MobilePhone,Modified,msExchWhenMailboxCreated,msRTCSIP-Line,msRTCSIP-PrimaryUserAddress,msRTCSIP-UserEnabled,Name,ObjectClass,Office,OfficePhone,@{n="PersonalEmail";e={$_.otherIPPhone}},@{n="AIM";e={$_.ipPhone}},PasswordExpired,PasswordLastSet,PasswordNeverExpires,PostalCode,ProtectedFromAccidentalDeletion,pwdLastSet,SamAccountName,sAMAccountType,ServicePrincipalNames,SID,Surname,telephoneNumber,Title,TrustedForDelegation,TrustedToAuthForDelegation,UserPrincipalName

            #create and load getAll object with CS, OS and BIOS contents...
            $getAll = New-Object -TypeName PSObject

            $getAD.PSObject.properties | ForEach-Object {
                $newName = "AD-" + $_.Name  
                If (($_.Name -eq 'InstallDate') -Or ($_.Name -eq 'LastBootUpTime') -Or ($_.Name -eq 'LocalDateTime')) {       
                    If ($_.Value.Length -lt 1) { $tempValue = '19500101000000.000000-240' } Else { $tempValue = $_.Value }
                    $newValue = [System.Management.ManagementDateTimeConverter]::ToDateTime($tempValue)
                } Else {
                    $newValue = $_.Value
                }
                $getAll | Add-Member -MemberType NoteProperty -Name $newName -Value $newValue
            }

            # get the users last logon date by scanning all domain controllers...
            $thisUsersLastLogonDate = Get-ADUserLastLogon -SamAccountName $SamAccountName
            $getAll | Add-Member -MemberType NoteProperty -Name 'AD-LastLogonDate' -Value $thisUsersLastLogonDate
            $thisUsersLastBadPasswordAttempt = Get-ADUserLastBadPasswordAttempt -SamAccountName $SamAccountName
            $getAll | Add-Member -MemberType NoteProperty -Name 'AD-LastBadPasswordAttempt' -Value $thisUsersLastBadPasswordAttempt
            # get the users passwordWillExpire date...
            $maxPasswordAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
            $pwlast = $getAD.PasswordLastSet
            If ($pwlast.Length -lt 1) { $pwlast = $getAD.Created }
            $thisUsersPasswordExpireDate = $pwlast.AddDays($maxPasswordAge)
            $getAll | Add-Member -MemberType NoteProperty -Name 'AD-PasswordExpirationDate' -Value $thisUsersPasswordExpireDate
            # get the users OU...
            $UserOU = $getAD.CanonicalName.ToString().Split('/')

            $userOUNew = ""
            For ($i =0; $i -lt $UserOU.COunt-1; $i++) {
                $userOUNew += $userOU[$i]
                If ($i+2 -lt $UserOU.Count) { $userOUNew += "/" }
            }

            $getAll | Add-Member -MemberType NoteProperty -Name 'AD-OU' -Value $userOUNew



            # remove some unwanted properties that got added somehow...
            $getAll.PSObject.Properties.Remove('AD-PSComputerName')
            $getAll.PSObject.Properties.Remove('AD-RunspaceId')
            $getAll.PSObject.Properties.Remove('AD-PSShowComputerName')


            # Next, send over the computer information...
            #Update-PSManageInfoSharePoint -getAll $getAll -spWeb $spWeb -spListName $spListName

            Return $getAll

        } Catch {
                    Write-Warning "($SamAccountName) - Error occurred: $_.Exception.Message"
        }
    }
    End {}
}

# function that gets current list of computers from PSMANAGE-COMPUTERS list in SharePoint...
function Get-PSManageComputersList() {
    #create a new session and load the SharePoint plugins...
    $sessionSharePoint = New-PSSession -ComputerName $global:psmSharePointServer
    Invoke-Command -Session $sessionSharePoint -ScriptBlock {
        Add-PSSnapin Microsoft.SharePoint.PowerShell

        #send the list information over to the session and get the spare DIDs
        $sourceWebURL = "https://sharepoint/sites/PSMANAGE"
        $sourceListName = "PSMANAGE-COMPUTERS"
        $spSourceWeb = Get-SPWeb "$sourceWebURL"
        $spSourceList = $spSourceWeb.Lists[$sourceListName]
        $spSourceItems = $spSourceList.Items        
        $output = @() 

        ForEach ($computer in $spSourceItems) {
            $PSComputerName = $computer['PSComputerName']
            $output += $PSComputerName
        } 
    }
    $spSourceItems = Invoke-Command -Session $sessionSharePoint -ScriptBlock { $output }

    #close session once information is obtained... $global:existingTemplates = Get-RemADUser -Filter{(Name -Like '*_Template*') -And (ObjectClass -eq 'user')} | Sort-Object Name | Select Name
    $sessionSharePoint | Remove-PSSession

    #give output
    Return $spSourceItems

}

# function that gets current list of users from PSMANAGE-USERS list in SharePoint...
function Get-PSManageUsersList() {
    #create a new session and load the SharePoint plugins...
    $sessionSharePoint = New-PSSession -ComputerName $global:psmSharePointServer
    Invoke-Command -Session $sessionSharePoint -ScriptBlock {
        Add-PSSnapin Microsoft.SharePoint.PowerShell

        #send the list information over to the session and get the spare DIDs
        $sourceWebURL = "https://sharepoint/sites/PSMANAGE"
        $sourceListName = "PSMANAGE-USERS"
        $spSourceWeb = Get-SPWeb "$sourceWebURL"
        $spSourceList = $spSourceWeb.Lists[$sourceListName]
        $spSourceItems = $spSourceList.Items        
        $output = @() 

        ForEach ($user in $spSourceItems) {
            $SamAccountName = $user['AD-SamAccountName']
            $output += $SamAccountName
        } 
    }
    $spSourceItems = Invoke-Command -Session $sessionSharePoint -ScriptBlock { $output }
    $sessionSharePoint | Remove-PSSession

    #give output
    Return $spSourceItems

}

# function that gets current list of computers from PSMANAGE-COMPUTERS list in SharePoint, with more details...
function Get-PSManageComputersListDetailed() {
    #create a new session and load the SharePoint plugins...
    $sessionSharePoint = New-PSSession -ComputerName $global:psmSharePointServer
    Invoke-Command -Session $sessionSharePoint -ScriptBlock {
        Add-PSSnapin Microsoft.SharePoint.PowerShell

        #send the list information over to the session and get the spare DIDs
        $sourceWebURL = "https://sharepoint/sites/PSMANAGE"
        $sourceListName = "PSMANAGE-COMPUTERS"
        $spSourceWeb = Get-SPWeb "$sourceWebURL"
        $spSourceList = $spSourceWeb.Lists[$sourceListName]
        $spSourceItems = $spSourceList.Items        
        $output = @() 
        
        ForEach ($computer in $spSourceItems) {
            $ComputerName = $computer['PSComputerName']
            #$output += $PSComputerName
            $LastPhoneHome = $computer['PSLastPhoneHome']
            $LastUpdate = $computer['PSLastUpdate']            
            $OperatingSystem = $computer['AD-OperatingSystem']
            $Modified = $computer['AD-Modified']

            $object1 = [pscustomobject]@{
                ComputerName=$ComputerName;
                OperatingSystem=$OperatingSystem;
                LastPhoneHome=$LastPhoneHome;
                LastUpdate=$LastUpdate; 
                Modified=$Modified             
            }
            $output += $object1 


        }
    }
    $spSourceItems = Invoke-Command -Session $sessionSharePoint -ScriptBlock { $output }

    #close session once information is obtained... $global:existingTemplates = Get-RemADUser -Filter{(Name -Like '*_Template*') -And (ObjectClass -eq 'user')} | Sort-Object Name | Select Name
    $sessionSharePoint | Remove-PSSession

    #give output
    Return $spSourceItems

}

# function that gets current list of users, with some other details included, from PSMANAGE-USERS list in SharePoint...
function Get-PSManageUsersListDetailed() {
    #create a new session and load the SharePoint plugins...
    $sessionSharePoint = New-PSSession -ComputerName $global:psmSharePointServer
    Invoke-Command -Session $sessionSharePoint -ScriptBlock {
        Add-PSSnapin Microsoft.SharePoint.PowerShell

        #send the list information over to the session and get the spare DIDs
        $sourceWebURL = "https://sharepoint/sites/PSMANAGE"
        $sourceListName = "PSMANAGE-USERS"
        $spSourceWeb = Get-SPWeb "$sourceWebURL"
        $spSourceList = $spSourceWeb.Lists[$sourceListName]
        $spSourceItems = $spSourceList.Items        
        $output = @() 

        ForEach ($user in $spSourceItems) {
            $SamAccountName = $user['AD-SamAccountName']
            $Modified = $user['AD-Modified']

            $object1 = [pscustomobject]@{
                SamAccountName = $SamAccountName; 
                Modified=$Modified;            
            }
            $output += $object1
        } 
    }
    $spSourceItems = Invoke-Command -Session $sessionSharePoint -ScriptBlock { $output }
    $sessionSharePoint | Remove-PSSession

    #give output
    Return $spSourceItems
}

# function run by PSMANAGE server to catch-up SP with computers that exist in AD
function Update-PSManageComputersFromAD(){
<# 
.SYNOPSIS 
Ensure SharePoint PSMANAGE-COMPUTERS list is kept up to date.
.DESCRIPTION 
Compares all computer objects in AD to those already in SharePoint, and adds any missing computers to SP if needed.
.PARAMETER spWeb
The URL to the SharePoint site collection that the PSManage content will be updated in
.EXAMPLE 
Update-PSManageComputersFromAD -spWeb 'https://sharepoint/sites/psmanage'
#>
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$spWeb
    )

    BEGIN{}
    PROCESS{
        Try {
            
            # specify which SP list to update
            $spListName = 'PSMANAGE-COMPUTERS'

            # load AD module if not already
            Get-ModuleAD

            # get some computers from AD to work with
            # $computers = Get-RemADComputer  -Filter{(Name -Like 'H*') -And (OperatingSystem -Like '*Windows*') -And (OperatingSystem -NotLike '*Server*')} -Property * | Select-Object -Property Name
            # $computers = Get-RemADComputer  -Filter{(OperatingSystem -Like '*Server*')} -Property * | Select-Object -Property Name
            #$computersAD = Get-RemADComputer -Filter * -Property Name | Select-Object -Property Name | Sort-Object Name
            $computersAD = Get-RemADComputer -Filter * -Property Name, LastLogonDate, Modified | Select-Object -Property Name, LastLogonDate, Modified | Sort-Object Name
            $computersSP = Get-PSManageComputersListDetailed            

            #
            # compare every AD computer to every SP computer to make a list of computers that still need to be added to SharePoint...
            #
            $computersAdd = @()
            $computersUpdate = @()
            ForEach ($compAD in $computersAD) {
                $alreadyExists = $False
                $computerNameAD = $compAD.Name
                ForEach ($compSP in $computersSP) {
                    #$computerNameSP = $compSP
                    $computerNameSP = $compSP.ComputerName
                    If ($computerNameAD -eq $computerNameSP) { 
                        $alreadyExists = $True 

                        # also see if not a phone-home computer and needs to get AD info updated in SP...
                        $lastPhoneHome = $compSP.LastPhoneHome
                        $lastUpdate = $compSP.LastUpdate
                        $lastModified = $compAD.Modified
                        If ($lastModified -gt $lastUpdate) {
                            Write-Host "for computer $computerNameAD, lastMod is $lastModified and lastUpdate is $lastUpdate"
                            $object1a = [pscustomobject]@{
                                PSComputerName=$computerNameAD;              
                            }
                            $computersUpdate += $object1a
                        }
                    }
                }

                If ($alreadyExists -eq $False) {
                    $object1 = [pscustomobject]@{
                        PSComputerName=$computerNameAD;              
                    }
                    $computersAdd += $object1 
                } 
            }
            #
            # Any computers not yet in SP, let's get it done...
            #
            If (!(Test-Path "$global:psmServerLocalPath\Server\Tracking")) { New-Item -ItemType Directory -Path "$global:psmServerLocalPath\Server\Tracking" }
            If (Test-Path "$global:psmServerLocalPath\Server\Tracking\addingToSP.xml") { 
                $gotXML = Import-Clixml "$global:psmServerLocalPath\Server\Tracking\addingToSP.xml"
            } Else { 
                $gotXML = @() 
            }
            $gotXML += $computersAdd
            $gotXML | Export-Clixml "$global:psmServerLocalPath\Server\Tracking\addingToSP.xml"
            # for new computers...
            ForEach ($compNew in $computersAdd) {
                $computerName = $compNew.PSComputerName
                If ($computerName.Length -gt 1) {
                    $thisCompInfo = Get-ADComputerDetails -computerName $computerName
                    Update-PSManageInfoSharePoint -getAll $thisCompInfo -spWeb $spWeb -spListName $spListName
                }
            }
            # for existing computers that are not phoning home but had changes detected...
            ForEach ($compNew in $computersUpdate) {
                $computerName = $compNew.PSComputerName
                If ($computerName.Length -gt 1) {
                    $thisCompInfo = Get-ADComputerDetails -computerName $computerName
                    Update-PSManageInfoSharePoint -getAll $thisCompInfo -spWeb $spWeb -spListName $spListName
                }
            }



            #
            # get list of computers that are no longer in AD and may be candidates for removal...
            #
            $computersRemove = @()
            ForEach ($compSP in $computersSP) {
                $stillExists = $False
                #$computerNameSP = $compSP
                $computerNameSP = $compSP.ComputerName
                ForEach ($compAD in $computersAD) {
                    $computerNameAD = $compAD.Name
                    If ($computerNameSP -eq $computerNameAD) { $stillExists = $True }
                }

                If ($stillExists -eq $False) {
                    $object1 = [pscustomobject]@{
                        PSComputerName=$computerNameSP;              
                    }
                    $computersRemove += $object1
                }
            }

            #
            # Any computers to be removed from SP, let's get it done...
            #
            If (!(Test-Path "$global:psmServerLocalPath\Server\Tracking")) { New-Item -ItemType Directory -Path "$global:psmServerLocalPath\Server\Tracking" }
            If (Test-Path "$global:psmServerLocalPath\Server\Tracking\removingFromSP.xml") { 
                $gotXML = Import-Clixml "$global:psmServerLocalPath\Server\Tracking\removingFromSP.xml"
            } Else { 
                $gotXML = @() 
            }
            $gotXML += $computersRemove
            $gotXML | Export-Clixml "$global:psmServerLocalPath\Server\Tracking\removingFromSP.xml"

            If ($computersRemove.Count -gt 0) {
                Write-Host "computersRemove count is " $computersRemove.Count
                Write-Host "computersRemove is $computersRemove"
                $spListName = 'PSMANAGE-COMPUTERS'
                Remove-PSManageItemsFromSharePoint -getAll $computersRemove -spWeb $spWeb -remove 'computers'                       
            }




            #
            # Next get the list of existing computers in SP that need to be updated from AD with any changes...
            #
            If (Test-Path "$global:psmServerLocalPath\Server\Queue\ADUpdateComputersList.xml") { 
                # get the list of computers that phoned home recently and not yet updated...
                $getPhonedHome = Import-Clixml "$global:psmServerLocalPath\Server\Queue\ADUpdateComputersList.xml"

                # quick, delete the file so it can be recreated if any other computers phone home while this is going on...
                Remove-Item -Path "$global:psmServerLocalPath\Server\Queue\ADUpdateComputersList.xml" -Force

                # loop through each computer and call the function that gets AD info for it and updates SharePoint...
                ForEach ($compNew in $getPhonedHome) {
                    $computerName = $compNew.PSComputerName
                    If ($computerName.Length -gt 1) {
                        $thisCompInfo = Get-ADComputerDetails -computerName $computerName
                        Update-PSManageInfoSharePoint -getAll $thisCompInfo -spWeb $spWeb -spListName $spListName

                    }
                }
            }

        } Catch {
                    Write-Warning "Error occurred: $_.Exception.Message"
        }
    }
    End {}
}

# function that accepts an existing array of AD user objects and injects each one with Exchange Server details...
function Get-PSManageADUserDetails(){
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [object]$getAll
    )

    BEGIN{}
        PROCESS{
            Try {

                # get the Exchange module loaded if not already...
                Get-ModuleAD



                $adsdump = Get-RemADUser  -Filter * -Properties * | Select AccountExpires,CanonicalName,City,CN,co,Company,Country,countryCode,Created,Department,Description,DisplayName,EmailAddress,Enabled,GivenName,HomeDirectory,HomeDrive,Initials,isDeleted,LockedOut,lockoutTime,logonCount,mail,MobilePhone,Modified,msExchWhenMailboxCreated,msRTCSIP-Line,msRTCSIP-PrimaryUserAddress,msRTCSIP-UserEnabled,Name,ObjectClass,Office,OfficePhone,@{n="PersonalEmail";e={$_.otherIPPhone}},@{n="AIM";e={$_.ipPhone}},PasswordExpired,PasswordLastSet,PasswordNeverExpires,PostalCode,ProtectedFromAccidentalDeletion,pwdLastSet,SamAccountName,sAMAccountType,ServicePrincipalNames,SID,Surname,telephoneNumber,Title,TrustedForDelegation,TrustedToAuthForDelegation,UserPrincipalName
                #$mailboxes = Get-Mailbox | Select Alias,Database,DisplayName,EmailAddresses,Extensions,HasPicture,HasSpokenName,HiddenFromAddressListsEnabled,IsMailboxEnabled,IsResource,IssueWarningQuota,PrimarySMTPAddress,ProhibitSendQuota,ProhibitSendReceiveQuota,RecipientType,RecipientTypeDetails,SamAccountName,UMEnabled,UseDatabaseQuotaDefaults,UseDatabaseRetentionDefaults,WhenChanged,WhenCreated,WhenMailboxCreated
                # get mailbox database quota settings
                #$mailboxDatabases = Get-MailboxDatabase | Select Name, IssueWarningQuota, ProhibitSendQuota, ProhibitSendReceiveQuota


                # First get all the mailbox user details into an mbUsers array...
                $ads =  @()
                ForEach ($ad in $adsdump) {
                    Try {

                        $thisAD = New-Object -TypeName PSObject
                        $ad.PSObject.properties | ForEach-Object {
                            If ($_.Name -ne 'PSComputerName') { $newName = "AD-" + $_.Name } Else { $newName = $_.Name } 
                            $newValue = $_.Value
                            $thisAD | Add-Member -MemberType NoteProperty -Name $newName -Value $newValue
                        }

                        $ads += $thisAD
                        #}
                    } Catch {
                        Write-warning "Error with $Identity was $_.Exception.Message"
                    }
                
                }   
                         

                $newArray = @()
                # Then, loop through getAll and inject all the mbUsers attributes into the users...
                ForEach ($user in $getAll) {
                    $newUser = New-Object -TypeName PSObject
                    $thisSam = $user.SamAccountName                    
                    ForEach ($userAD in $ads) {
                        $thatSam = $userAD.'EXCH-SamAccountName'
                        If ($thisSam -eq $thatSam) {
                            $user.PSObject.properties | ForEach-Object {
                                $newName = $_.Name
                                $newValue = $_.Value
                                $newUser | Add-Member -MemberType NoteProperty -Name $newName -Value $newValue -Force
                            }
                            $userAD.PSObject.properties | ForEach-Object {
                                $newName = $_.Name
                                $newValue = $_.Value
                                $newUser | Add-Member -MemberType NoteProperty -Name $newName -Value $newValue -Force
                            }
                            $newArray += $newUser
                        }
                    }
                }

                # give the results back :-)
                Return $newArray

            } Catch {
                Write-Warning "Error occurred: $_.Exception.Message"
            }
        }
    End {}
}

# function that accepts an existing array of AD user objects and injects each one with Exchange Server details...
function Get-EXCHUserDetails(){
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [object]$getAll
    )

    BEGIN{}
        PROCESS{
            Try {

                # get the Exchange module loaded if not already...
                Get-ModuleExchange

                #$mailboxes = Get-Mailbox | Select Alias,Database,DisplayName,EmailAddresses,Extensions,HasPicture,HasSpokenName,HiddenFromAddressListsEnabled,IsMailboxEnabled,IsResource,IssueWarningQuota,PrimarySMTPAddress,ProhibitSendQuota,ProhibitSendReceiveQuota,RecipientType,RecipientTypeDetails,SamAccountName,UMEnabled,UseDatabaseQuotaDefaults,UseDatabaseRetentionDefaults,WhenChanged,WhenCreated,WhenMailboxCreated
                # get mailbox database quota settings
                $mailboxDatabases = Get-MailboxDatabase | Select Name, IssueWarningQuota, ProhibitSendQuota, ProhibitSendReceiveQuota
      
                # First get all the mailbox user details into an mbUsers array...
                $mbUsers =  @()
                #ForEach ($mailbox in $mailboxes) {
                $exist = [bool](Get-mailbox -Identity "$getAll" -erroraction SilentlyContinue)
                If ($exist) {
                    $mailbox = Get-Mailbox -Identity "$getAll" | Select Alias,Database,DisplayName,EmailAddresses,Extensions,HasPicture,HasSpokenName,HiddenFromAddressListsEnabled,IsMailboxEnabled,IsResource,IssueWarningQuota,PrimarySMTPAddress,ProhibitSendQuota,ProhibitSendReceiveQuota,RecipientType,RecipientTypeDetails,SamAccountName,UMEnabled,UseDatabaseQuotaDefaults,UseDatabaseRetentionDefaults,WhenChanged,WhenCreated,WhenMailboxCreated
                    Try {
                        # current mailbox stats...
                        $mailboxStatistics = $mailbox.SamAccountName | Get-MailboxStatistics | Select DisplayName, StorageLimitStatus, TotalDeletedItemSize, TotalItemSize, Database
                        
                        $temp1 = $mailboxStatistics.TotalItemSize
                        If ($temp1 -Like "*GB*") { 
                            $temp2 = $temp1.Split(" GB")
                            $temp2 = 1024 * $temp2[0]
                        } ElseIf ($temp1 -Like "*MB*") { 
                            $temp2 = $temp1.Split(" MB")
                            $temp2 = $temp2[0] 
                        } ElseIf ($temp1 -Like "*KB*") { 
                            $temp2 = $temp1.Split(" KB")
                            $temp2 = (1/1024) * $temp2[0] 
                        } Else {                            
                            $temp2 = 1
                        }

                        $TotalItemSize = [math]::round($temp2[0],2)

                        $DisplayName = $mailbox.DisplayName
                        $Database = $mailbox.Database

                        $thisDB = $mailboxDatabases | Where {($_.Name -eq $Database)}
                        If ($mailbox.UseDatabaseQuotaDefaults -eq $true) {
                            $temp1a = $thisDB.IssueWarningQuota
                            $temp1b = $thisDB.ProhibitSendQuota
                            $temp1c = $thisDB.ProhibitSendReceiveQuota
                        } ElseIf ($mailbox.UseDatabaseQuotaDefaults -eq $false) {
                            $temp1a = $mailbox.IssueWarningQuota
                            $temp1b = $mailbox.ProhibitSendQuota
                            $temp1c = $mailbox.ProhibitSendReceiveQuota
                        }
                        If ($temp1a -eq 'unlimited') { $temp1a = '102400 GB' }
                        If ($temp1b -eq 'unlimited') { $temp1b = '102400 GB' }
                        If ($temp1c -eq 'unlimited') { $temp1c = '102400 GB' }


                        # current mailbox's database stats...                       
                        If ($temp1a -Like "*GB*") { 
                            $temp2 = $temp1a.Split(" GB")
                            $temp2 = 1024 * $temp2[0]
                        } ElseIf ($temp1 -Like "*MB*") { 
                            $temp2 = $temp1a.Split(" MB")
                            $temp2 = $temp2[0] 
                        } ElseIf ($temp1a -Like "*KB*") { 
                            $temp2 = $temp1a.Split(" KB")
                            $temp2 = (1/1024) * $temp2[0] 
                        }

                        $IssueWarningQuota = $temp2

                        If ($temp1b -Like "*GB*") { 
                            $temp2 = $temp1b.Split(" GB")
                            $temp2 = 1024 * $temp2[0]
                        } ElseIf ($temp1b -Like "*MB*") { 
                            $temp2 = $temp1b.Split(" MB")
                            $temp2 = $temp2[0] 
                        } ElseIf ($temp1b -Like "*KB*") { 
                            $temp2 = $temp1b.Split(" KB")
                            $temp2 = (1/1024) * $temp2[0] 
                        }
                        $ProhibitSendQuota = $temp2

                        If ($temp1c -Like "*GB*") { 
                            $temp2 = $temp1c.Split(" GB")
                            $temp2 = 1024 * $temp2[0]
                        } ElseIf ($temp1c -Like "*MB*") { 
                            $temp2 = $temp1c.Split(" MB")
                            $temp2 = $temp2[0] 
                        } ElseIf ($temp1c -Like "*KB*") { 
                            $temp2 = $temp1c.Split(" KB")
                            $temp2 = (1/1024) * $temp2[0] 
                        }
                        $ProhibitSendReceiveQuota = $temp2
                
                        $availSpaceTillWarning = [math]::round(($IssueWarningQuota - $TotalItemSize),2)
                        $availSpaceTillSend = [math]::round(($ProhibitSendQuota - $TotalItemSize),2)
                        $availSpaceTillSendReceive = [math]::round(($ProhibitSendReceiveQuota - $TotalItemSize),2)

                        $thisMB = New-Object -TypeName PSObject
                        $mailbox.PSObject.properties | ForEach-Object {
                            If ($_.Name -ne 'PSComputerName') { $newName = "EXCH-" + $_.Name } Else { $newName = $_.Name } 
                            #If (($_.Name -Like '*when*') -Or ($_.Name -Like '*date*')) {       
                            #    If ($_.Value.Length -lt 1) { $tempValue = '19500101000000.000000-240' } Else { $tempValue = $_.Value }
                            #    Write-Host "$newName, $tempValue"
                            #    $newValue = [System.Management.ManagementDateTimeConverter]::ToDateTime($tempValue)
                            #} Else {
                                $newValue = $_.Value
                            #}
                            $thisMB | Add-Member -MemberType NoteProperty -Name $newName -Value $newValue
                        }



                        $thisMB | Add-Member -MemberType NoteProperty -Name 'EXCH-TotalSizeMB' -Value $TotalItemSize
                        $thisMB | Add-Member -MemberType NoteProperty -Name 'EXCH-WarningMB' -Value $availSpaceTillWarning
                        $thisMB | Add-Member -MemberType NoteProperty -Name 'EXCH-SendMB' -Value $availSpaceTillSend
                        $thisMB | Add-Member -MemberType NoteProperty -Name 'EXCH-SendReceiveMB' -Value $availSpaceTillSendReceive


                        $mbUsers += $thisMB
                        #}
                    } Catch {
                        Write-warning "Error with $Identity was $_.Exception.Message"
                    }
                
                #}   
                         

                $newArray = @()
                # Then, loop through getAll and inject all the mbUsers attributes into the users...
                ForEach ($user in $getAll) {
                    $newUser = New-Object -TypeName PSObject
                    #$thisSam = $user.SamAccountName 
                    $thisSam = $user                  
                    ForEach ($userMB in $mbUsers) {
                        $thatSam = $userMB.'EXCH-SamAccountName'
                        If ($thisSam -eq $thatSam) {
                            $user.PSObject.properties | ForEach-Object {
                                $newName = $_.Name
                                $newValue = $_.Value
                                $newUser | Add-Member -MemberType NoteProperty -Name $newName -Value $newValue -Force
                            }
                            $userMB.PSObject.properties | ForEach-Object {
                                $newName = $_.Name
                                $newValue = $_.Value
                                $newUser | Add-Member -MemberType NoteProperty -Name $newName -Value $newValue -Force
                            }
                            $newArray += $newUser
                        }
                    }
                }

                # give the results back :-)
                Return $newArray
                } #end if exist loop

            } Catch {
                Write-Warning "Error occurred: $_.Exception.Message"
            }
        }
    End {}
}

# Scan SharePoint for computer that are not yet phoning home, and try to setup the scheduled task on them
function Update-PSManageComputersFromSP(){
<# 
.SYNOPSIS 
Installs PSManage script on workstations that are in SharePoint but not yet phoning home
.DESCRIPTION 
Reviews PSMANAGE-COMPUTERS list for workstations with PSLastPhoneHome value that is still empty, and tries pushing the scripts to them
.PARAMETER spWeb
The URL to the SharePoint site collection that the PSManage content will be read from
.EXAMPLE 
Update-PSManageComputersFromSP -spWeb 'https://sharepoint/sites/psmanage'
#>
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$spWeb
    )

    BEGIN{}
    PROCESS{
        Try {
            #$computersAD = Get-RemADComputer -Filter{(Name -Like 'H*') -And (OperatingSystem -NotLike '*Server*') -And (OperatingSystem -Like '*Windows*')} -Property Name | Select-Object -Property Name | Sort-Object Name
            $computersSP = Get-PSManageComputersListDetailed
            $computersSP = $computersSP | Sort-Object Modified -Descending

            #
            # compare every AD computer to every SP computer to make a list of computers that still need to be added to SharePoint...
            #

            $computersAdd = @()
            $rightNow = Get-Date
            ForEach ($compSP in $computersSP) {
                $ComputerName = $compSP.ComputerName
                $LastPhoneHome = $compSP.LastPhoneHome
                $LastUpdate = $compSP.LastUpdate
                $OperatingSystem = $compSP.'OperatingSystem'
                #If (($ComputerName.Length -gt 0) -And ($LastUpdate.Length -lt 1) -And ($OperatingSystem -Like '*Windows*') -And ($OperatingSystem -NotLike '*Server*')) {
                If (($ComputerName.Length -gt 0) -And ($LastPhoneHome.Length -lt 1) -And ($OperatingSystem -Like '*Windows*')) {
                    #If ($limitBatchTrack -lt $limitBatchSize) {
                        $object1 = [pscustomobject]@{
                            PSComputerName=$ComputerName;              
                        }
                        $computersAdd += $object1 
                        #$limitBatchTrack++
                    #}
                } ElseIf (($ComputerName.Length -gt 0) -And ($LastPhoneHome.Length -gt 0) -And ($OperatingSystem -Like '*Windows*')) {
                    #see if computers lost scripts somehow
                    $daysSince = $rightNow - $LastPhoneHome
                    $daysSince = $daysSince.Days
                    If ($daysSince -gt 30) {
                        $object1 = [pscustomobject]@{
                            PSComputerName=$ComputerName;              
                        }
                        $computersAdd += $object1 
                    }
                }
            }

            #
            # Any computers not yet in SP, let's get it done...
            #
            $limitBatchSize = 10
            $limitBatchTrack = 0
            ForEach ($compNew in $computersAdd) {
                $computerName = $compNew.PSComputerName
                If (($computerName.Length -gt 1) -And ($limitBatchTrack -lt $limitBatchSize)) {                    
                    If (Test-Connection -ComputerName $computerName -Quiet) {
                        $limitBatchTrack++
                        $something = Set-PSManageClientScheduledTask -computerName $computerName
                    }
                }
            }
        } Catch {
                    Write-Warning "Error occurred: $_.Exception.Message"
        }
    }
    End {}
}

# function to remotely scan XP computers and update SharePoint on their behalf...
function Update-PSManageComputersRemotely() {
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$spWeb
    )
        
    BEGIN{}
        PROCESS{
            Try {
                #$computersAD = Get-RemADComputer -Filter{(Name -Like 'H*') -And (OperatingSystem -NotLike '*Server*') -And (OperatingSystem -Like '*Windows*')} -Property Name | Select-Object -Property Name | Sort-Object Name
                $computersSP = Get-PSManageComputersListDetailed

                #
                # compare every AD computer to every SP computer to make a list of computers that still need to be added to SharePoint...
                #

                $computersAdd = @()
                ForEach ($compSP in $computersSP) {
                    $ComputerName = $compSP.ComputerName
                    $LastUpdate = $compSP.LastUpdate
                    $OperatingSystem = $compSP.'OperatingSystem'
                    If (($ComputerName.Length -gt 0) -And ($OperatingSystem -Like '*XP*')) {
                        $object1 = [pscustomobject]@{
                            PSComputerName=$ComputerName;              
                        }
                        $computersAdd += $object1 
                    }
                }

                #
                # now let's scan each computer if possible...
                #
                ForEach ($compNew in $computersAdd) {
                    $computerName = $compNew.PSComputerName
                    If ($computerName.Length -gt 1) {                    
                        If (Test-Connection -ComputerName $computerName -Quiet) {
                            Try {
                                Update-PSManageInfoGatherRemote -computerName $computerName
                                Update-PSManageInfoCompareRemote -computerName $computerName -spWeb $spWeb
                            } Catch {}
                        }
                    }
                }
            } Catch {
                    Write-Warning "Error occurred: $_.Exception.Message"
            }
        }
    End {}


}

# function that setups up the scheduled task to enable a system to phone home to PSMANAGE :-)
function Set-PSManageClientScheduledTask() {
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$computerName
    )
    #
    # get some random variables for the start and repeat times for the scheduled task 
    # (so not every computer updates at the same time and kills SharePoint hehe)
    #
    
    BEGIN{}
    PROCESS{
        If (Test-Connection -ComputerName $computerName -Quiet) {


            $getOS = Get-WmiObject Win32_OperatingSystem -ComputerName $computerName | Select-Object -Property Version
            If ($getOS.Version[0] -ne '5') {

                $startHour = Get-Random -Minimum 0 -Maximum 23
                $startMinute = Get-Random -Minimum 0 -Maximum 59
                If ($startHour -lt 10) { $startHourShow = "0"+$startHour } Else { $startHourShow = $startHour }
                If ($startMinute -lt 10) { $startMinuteShow = "0"+$startMinute } Else { $startMinuteShow = $startMinute }
                $RI = Get-Random -Minimum 120 -Maximum 180
                $DUhour = ($startHour + 12)
                If ($DUhour -gt 23) { $DUhour = $DUhour - 24 }
                If ($DUHour -lt 10) { $DUHourShow = "0"+$DUHour } Else { $DUHourShow = $DUHour }
                $DU = ""
                $DU+=$DUhourShow
                $DU+= ":"
                $DU+=$startMinuteShow


                #
                # Add the service account to the local administrators group on the system
                #
                Try {
                    $addAccountToAdmins = [ADSI]"WinNT://$computerName/Administrators,group" 
                    $addAccountToAdmins.psbase.Invoke("Add",([ADSI]"WinNT://$global:impYourDomainNetBios/$global:impYourServiceAccountSAM").path)
                } Catch {}

                #
                # Copy the scheduled task files to the workstation
                #
                Try {
                    If (Test-Path "$global:psmClientSource\PSManage.ps1") { 
                        If (!(Test-Path "\\$computerName\$global:psmClientRemotePath")) { New-Item -ItemType Directory -Path "\\$computerName\$global:psmClientRemotePath" }
                        Copy-Item -Path "$global:psmClientSource\PSManage.ps1" -Destination "\\$computerName\$global:psmClientRemotePath\PSManage.ps1" -Force
                        Copy-Item -Path "$global:psmClientSource\PSManageImport.ps1" -Destination "\\$computerName\$global:psmClientRemotePath\PSManageImport.ps1" -Force
                    }
                } Catch {}


                #
                # Create the scheduled task on the computer
                #
            
                #First, check if task already exists
                Try {
                    $existingQueries = Schtasks.exe /S $computerName /Query /TN "PSManage"
                } Catch {}

                Try {
                    If ($existingQueries.Length -lt 1) {
                        Schtasks.exe /S $computerName /Create /RU "$global:impYourServiceAccountSAM@$global:impYourDomainFQDN" /RP "$global:impYourServiceAccountPW" /SC DAILY /ST $startHourShow":"$startMinuteShow /RI $RI /DU 12:00 /TN "PSManage" /TR "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File $global:psmClientLocalPath\PSManage.ps1" /RL HIGHEST


                        $newTaskCheck = Schtasks.exe /S $computerName /Query /TN "PSManage"
                        If ($newTaskCheck.Length -lt 1) {
                            $global:PSManageEmailBody = "$computerName ran into an error checking/creating the scheduled task: `n$error"
                            If (Test-Connection -ComputerName "$global:impExchangeServer" -Quiet) {
                                send-mailmessage -to "$global:impEmailTo" -from "$global:impEmailFrom" -subject 'PSManage Scheduled Task Error' -body $global:PSManageEmailBody -smtpserver "$global:impExchangeServer"
                            }
                        } Else {
                            If (!(Test-Path "$global:psmServerLocalPath\Server\Tracking")) { New-Item -ItemType Directory -Path "$global:psmServerLocalPath\Server\Tracking" }
                            If (Test-Path "$global:psmServerLocalPath\Server\Tracking\installingPSManageClient.xml") { $gotXML = Import-Clixml "$global:psmServerLocalPath\Server\Tracking\installingPSManageClient.xml"} Else { $gotXML = @() }

                            $object1 = [pscustomobject]@{
                                ComputerName=$ComputerName;             
                            }
                            If (!($gotXML.Count)) { $gotXML = @($gotXML) }
                            $gotXML += $object1 
                            $gotXML | Export-Clixml "$global:psmServerLocalPath\Server\Tracking\installingPSManageClient.xml"
                            $global:PSManageEmailBody = "$computerName successfully created a new PSManage scheduled task"
                            If (Test-Connection -ComputerName "$global:impExchangeServer" -Quiet) {
                                #send-mailmessage -to "$global:impEmailTo" -from "$global:impEmailFrom" -subject 'PSManage Scheduled Task Success' -body $global:PSManageEmailBody -smtpserver "$global:impExchangeServer"
                            }
                        }
                    }
                } Catch {}
            }
        }
    }
    End {
        Return "1"
    }
}

# function that setups up the scheduled task to enable a system to be a central server for PSMANAGE :-)
function Set-PSManageServerScheduledTask() {
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$computerName
    )
    #
    # get some random variables for the start and repeat times for the scheduled task 
    # (so not every computer updates at the same time and kills SharePoint hehe)
    #
    
    BEGIN{}
    PROCESS{
        If (Test-Connection -ComputerName $computerName -Quiet) {
            $startHour = Get-Random -Minimum 0 -Maximum 23
            $startMinute = Get-Random -Minimum 0 -Maximum 59
            If ($startHour -lt 10) { $startHourShow = "0"+$startHour } Else { $startHourShow = $startHour }
            If ($startMinute -lt 10) { $startMinuteShow = "0"+$startMinute } Else { $startMinuteShow = $startMinute }
            $RI = Get-Random -Minimum 120 -Maximum 240
            $DUhour = ($startHour + 12)
            If ($DUhour -gt 23) { $DUhour = $DUhour - 24 }
            If ($DUHour -lt 10) { $DUHourShow = "0"+$DUHour } Else { $DUHourShow = $DUHour }
            $DU = ""
            $DU+=$DUhourShow
            $DU+= ":"
            $DU+=$startMinuteShow


            #
            # Add the service account to the local administrators group on the system
            #
            Try {
                $addAccountToAdmins = [ADSI]"WinNT://$computerName/Administrators,group" 
                $addAccountToAdmins.psbase.Invoke("Add",([ADSI]"WinNT://$global:impYourDomainNetBios/$global:impYourServiceAccountSAM").path)
            } Catch {}


            #
            # Copy the scheduled task files to the workstation
            #
            Try {
                If (Test-Path "$global:psmServerSource\PSManage-CentralServer-Imports.ps1") { 
                    If (!(Test-Path "\\$computerName\$global:psmServerRemotePath")) { New-Item -ItemType Directory -Path "\\$computerName\$global:psmServerRemotePath" }
                    If (!(Test-Path "\\$computerName\$global:psmServerRemotePath\Server")) { New-Item -ItemType Directory -Path "\\$computerName\$global:psmServerRemotePath\Server" }
                    Copy-Item -Path "$global:psmServerSource\PSManage-CentralServer-Imports.ps1" -Destination "\\$computerName\$global:psmServerRemotePath\Server\PSManage-CentralServer-Imports.ps1" -Force
                    Copy-Item -Path "$global:psmServerSource\PSManage-CentralServer.ps1" -Destination "\\$computerName\$global:psmServerRemotePath\Server\PSManage-CentralServer.ps1" -Force
                }
            } Catch {}


            #
            # Create the scheduled task on the computer
            #
            
            #First, check if task already exists
            Try {
                $existingQueries = Schtasks.exe /S $computerName /Query /TN "PSManageServer"
            } Catch {}

            Try {
                If ($existingQueries.Length -lt 1) {
                    Schtasks.exe /S $computerName /Create /RU "$global:impYourServiceAccountSAM@$global:impYourDomainFQDN" /RP "$global:impYourServiceAccountPW" /SC DAILY /ST $startHourShow":"$startMinuteShow /RI $RI /DU 12:00 /TN "PSManageServer" /TR "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File $global:psmServerLocalPath\Server\PSManage-CentralServer.ps1" /RL HIGHEST
                    $global:PSManageEmailBody = "$computerName successfully created a new PSManage Server scheduled task"
                    If (Test-Connection -ComputerName "$global:impExchangeServer" -Quiet) {
                        send-mailmessage -to "$global:impEmailTo" -from "$global:impEmailFrom" -subject 'PSManage Server Scheduled Task Success' -body $global:PSManageEmailBody -smtpserver "$global:impExchangeServer"
                    }
                }
            } Catch {
                $global:PSManageEmailBody = "$computerName ran into an error checking/creating the scheduled task: `n$error"
                If (Test-Connection -ComputerName "$global:impExchangeServer" -Quiet) {
                    send-mailmessage -to "$global:impExchangeServer" -from "$global:impEmailFrom" -subject 'PSManage Scheduled Task Error' -body $global:PSManageEmailBody -smtpserver "$global:impExchangeServer"
                }
            }
        }
    }
    End {}
}

# create a list in SharePoint to keep a list of available software install packages
function New-PSManageListsPackagesTasks() {
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$spWeb
    )

    BEGIN{}
    PROCESS{
        Try {
            $spListName1 = 'PSMANAGE-PACKAGES'
            $spListName2 = 'PSMANAGE-TASKS'
            # connect to sharepoint and send data over...
            $sessionSharePoint = New-PSSession -ComputerName $global:psmSharePointServer
            Invoke-Command -Session $sessionSharePoint -ScriptBlock {
                # get input from function calling remote session
                Param ($spWeb, $spListName1, $spListName2)

                Add-PSSnapin Microsoft.SharePoint.PowerShell
                # send the list information over to the session

                $spWeb = Get-SPWeb $spWeb
                $spListCheck1 = $spWeb.Lists.TryGetList("$spListName1")
                $spListCheck2 = $spWeb.Lists.TryGetList("$spListName2")

                $spListTemplate = $spWeb.ListTemplates["Custom List"]

                # if list not existing, create it...
                If ($spListCheck1 -eq $null) {
                    $spListCollection = $spWeb.Lists
                    $spListCollection.Add($spListName1, $spListNam1e, $spListTemplate) | Out-Null        
                }
                If ($spListCheck2 -eq $null) {
                    $spListCollection = $spWeb.Lists
                    $spListCollection.Add($spListName2, $spListNam1e, $spListTemplate) | Out-Null        
                }

                # get list info and create columns...
                $path = $spWeb.Url.Trim()
                $spList1 = $spWeb.Lists["$spListName1"]
                $spList2 = $spWeb.Lists["$spListName2"]
                #$spList1.OnQuickLaunch = "True"
                #$spList2.OnQuickLaunch = "True"

                $thisFieldType = [Microsoft.SharePoint.SPFieldType]::Text


                If ($spList1.Fields.ContainsField("PackageInstaller") -eq $False) {
                    $spList1.Fields.Add("PackageInstaller", $thisFieldType, $false) | Out-Null
                    $spList1.Update()
                }
                If ($spList1.Fields.ContainsField("PackageDetails") -eq $False) {
                    $thisFieldType = [Microsoft.SharePoint.SPFieldType]::Note
                    $spList1.Fields.Add("PackageDetails", $thisFieldType, $false) | Out-Null
                    $spList1.Update()
                }  
                
                If ($spList2.Fields.ContainsField("TaskDetails") -eq $False) {
                    $thisFieldType = [Microsoft.SharePoint.SPFieldType]::Note
                    $spList2.Fields.Add("TaskDetails", $thisFieldType, $false) | Out-Null
                    $spList2.Update()
                }              

                If ($spList2.Fields.ContainsField("TaskPackage") -eq $False) {
                    $spLookupList = $spWeb.Lists["PSMANAGE-PACKAGES"]
                    $spList2.Fields.AddLookup("TaskPackage", $spLookupList.id, "true") | Out-Null
                    $newField = $spList2.Fields["TaskPackage"]
                    $newField.Required = $False
                    $newField.LookupField = $spLookupList.Fields["Title"]
                    $newField.Update()
                    $spList2.Update()
                } 

                If ($spList2.Fields.ContainsField("PSComputerName") -eq $False) {
                    $spLookupList = $spWeb.Lists["PSMANAGE-COMPUTERS"]
                    $spList2.Fields.AddLookup("PSComputerName", $spLookupList.id, "true") | Out-Null
                    $newField = $spList2.Fields["PSComputerName"]
                    $newField.Required = $False
                    $newField.LookupField = $spLookupList.Fields["Title"]
                    $newField.Update()
                    $spList2.Update()
                }    
                
                If ($spList2.Fields.ContainsField("TaskStatus") -eq $False) {
                    $choices = New-Object System.Collections.Specialized.StringCollection 
                    $choices.Add("Completed") | Out-Null
                    $choices.Add("In Progress") | Out-Null 
                    $choices.Add("Not Started") | Out-Null 
                    $spFieldType = [Microsoft.SharePoint.SPFieldType]::Choice 
                    $spList2.Fields.Add("TaskStatus",$spFieldType,$false,$false,$choices) | Out-Null
                    $spList2.Update()
                    $newField = $spList2.Fields["TaskStatus"]
                    $newField.DefaultValue = "Not Started"
                    $newField.Update()
                } 

                If ($spList2.Fields.ContainsField("TaskAssignedTo") -eq $False) {
                    $newField = $spList2.Fields.Add("TaskAssignedTo", "User", 0)
                    $spList2.Fields[$newField].Title = "TaskAssignedTo"
                    $spList2.Fields[$newField].Update()
                    $spList2.Update()
                } 

                If ($spList1.Fields.ContainsField("PackageVerify") -eq $False) {
                    $spList1.Fields.Add("PackageVerify", $thisFieldType, $false) | Out-Null
                    $spList1.Update()
                }
                
                If (($spList2.Fields.ContainsField("TaskName") -eq $False) -And ($spList2.Fields.ContainsField("Title") -eq $True)) {
                    $titleField = $spList2.Fields["Title"]
                    $titleField.Title = "TaskName"
                    $titleField.Update()
                    $spList2.Update()
                }             

                If (($spList1.Fields.ContainsField("PackageName") -eq $False) -And ($spList1.Fields.ContainsField("Title") -eq $True)) {
                    $titleField = $spList1.Fields["Title"]
                    $titleField.Title = "PackageName"
                    $titleField.Update()
                    $spList1.Update()
                }                             
                
            } -ArgumentList $spWeb, $spListName1, $spListName2

            # close session once done...
            $sessionSharePoint | Remove-PSSession
        } Catch {
            Write-Warning "Error occurred: $_.Exception.Message"
        }
    }
    End {}
}

# gathers work performed from XML files and sends a summary email
function Get-PSManageEmail() {

    $emailSubject = "Update from $global:impYourServiceAccountDisplay"
    $emailBody = ""
    $emailFrom = "$global:impEmailFrom"
    $emailTo = "$global:impEmailTo"
    $emailServer = "$global:impExchangeServer"

    # first let's find out if any computers were added to SharePoint...
    If (Test-Path "$global:psmServerLocalPath\Server\Tracking\addingToSP.xml") { 
        $addingToSP = Import-Clixml "$global:psmServerLocalPath\Server\Tracking\addingToSP.xml" 
        $addingToSP = $addingToSP | Sort-Object PSComputerName
        #If ($addingToSP[0].PSComputerName) {
        If ($addingToSP) {
            $emailBody += "I noticed there were some computers in Active Directory that were not yet in the SharePoint list, so I've just added them..."    
            $emailBody += "<ul>"
            ForEach ($add in $addingToSP) {
                $compName = $add.PSComputerName
                $emailBody += "<li>$compName</li>"
            }
            $emailBody += "</ul>"
        }
    }
    If (Test-Path "$global:psmServerLocalPath\Server\Tracking\addingToSP.xml") { Remove-Item -Path "$global:psmServerLocalPath\Server\Tracking\addingToSP.xml" -Force}

    # then let's check if any computers got PSManage scripts installed on them...
    If (Test-Path "$global:psmServerLocalPath\Server\Tracking\installingPSManageClient.xml") { 
        $installingPSManageClient = Import-Clixml "$global:psmServerLocalPath\Server\Tracking\installingPSManageClient.xml"                    
        $installingPSManageClient = $installingPSManageClient | Sort-Object ComputerName
        #If ($installingPSManageClient[0].ComputerName) {
        If ($installingPSManageClient) {
            $emailBody += "I found some $global:impYourDomainFQDN domain computers that were not yet setup with the PSManage scripts, so I went and installed them. These computers should start phoning home shortly..."
            $emailBody += "<ul>"
            ForEach ($add in $installingPSManageClient) {
                $compName = $add.ComputerName
                $emailBody += "<li>$compName</li>"
            }
            $emailBody += "</ul>"
        }           
    }
    If (Test-Path "$global:psmServerLocalPath\Server\Tracking\installingPSManageClient.xml") { Remove-Item -Path "$global:psmServerLocalPath\Server\Tracking\installingPSManageClient.xml" -Force}


    # also let's find out if any users were added to SharePoint...
    If (Test-Path "$global:psmServerLocalPath\Server\Tracking\addingToSPUsers.xml") { 
        $addingToSPUsers = Import-Clixml "$global:psmServerLocalPath\Server\Tracking\addingToSPUsers.xml" 
        $addingToSPUsers = $addingToSPUsers | Sort-Object SamAccountName
        #If ($addingToSPUsers[0].SamAccountName) {
        If ($addingToSPUsers) {
            $emailBody += "I noticed there were some users in Active Directory that were not yet in the SharePoint list, so I've just added them..."    
            $emailBody += "<ul>"
            ForEach ($add in $addingToSPUsers) {
                $compName = $add.SamAccountName
                $emailBody += "<li>$compName</li>"
            }
            $emailBody += "</ul>"
        }
    }
    If (Test-Path "$global:psmServerLocalPath\Server\Tracking\addingToSPUsers.xml") { Remove-Item -Path "$global:psmServerLocalPath\Server\Tracking\addingToSPUsers.xml" -Force}


    # check for any computers that were removed from AD and thus from SharePoint...
    If (Test-Path "$global:psmServerLocalPath\Server\Tracking\removingFromSP.xml") { 
        $removingFromSP = Import-Clixml "$global:psmServerLocalPath\Server\Tracking\removingFromSP.xml" 
        $removingFromSP = $removingFromSP | Sort-Object PSComputerName
        #If ($removingFromSP[0].PSComputerName) {
        If ($removingFromSP) {
            $emailBody += "I noticed there were some computers removed from Active Directory, so I've removed them from the SharePoint list..."    
            $emailBody += "<ul>"
            ForEach ($add in $removingFromSP) {
                $compName = $add.PSComputerName
                $emailBody += "<li>$compName</li>"
            }
            $emailBody += "</ul>"
        }
    }
    If (Test-Path "$global:psmServerLocalPath\Server\Tracking\removingFromSP.xml") { Remove-Item -Path "$global:psmServerLocalPath\Server\Tracking\removingFromSP.xml" -Force}

    # check for any computers that were removed from AD and thus from SharePoint...
    If (Test-Path "$global:psmServerLocalPath\Server\Tracking\removingFromSPUsers.xml") { 
        $removingFromSPUsers = Import-Clixml "$global:psmServerLocalPath\Server\Tracking\removingFromSPUsers.xml" 
        $removingFromSPUsers = $removingFromSPUsers | Sort-Object SamAccountName
        #If ($removingFromSPUsers[0].SamAccountName) {
        If ($removingFromSPUsers) {
            $emailBody += "I noticed there were some users removed from Active Directory, so I've removed them from the SharePoint list..."    
            $emailBody += "<ul>"
            ForEach ($add in $removingFromSPUsers) {
                $compName = $add.SamAccountName
                $emailBody += "<li>$compName</li>"
            }
            $emailBody += "</ul>"
        }
    }
    If (Test-Path "$global:psmServerLocalPath\Server\Tracking\removingFromSPUsers.xml") { Remove-Item -Path "$global:psmServerLocalPath\Server\Tracking\removingFromSPUsers.xml" -Force}


    # if anything needs to be emailed, fire away...
    If (($emailBody.Length -gt 0) -And (Test-Connection -ComputerName $emailServer -Quiet)) {
        $emailBody += "If you'd like to, check out the full list of computers in SharePoint:<br /><a href='https://sharepoint/sites/psmanage/Lists/psmanagecomputers/allItems.aspx'>https://sharepoint/sites/psmanage/Lists/psmanagecomputers/allItems.aspx</a><p/>"
        $emailBody += "If you'd like to, check out the full list of users in SharePoint:<br /><a href='https://sharepoint/sites/psmanage/Lists/psmanageusers/allItems.aspx'>https://sharepoint/sites/psmanage/Lists/psmanageusers/allItems.aspx</a><p/>"
        send-mailmessage -to $emailTo -from $emailFrom -subject $emailSubject -body $emailBody -smtpserver $emailServer -BodyAsHtml
    }
     

}

# function that starts the process and calls all the other functions...
function Get-PSManageCentralServerStarted() {
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$spWeb
    )   


    #
    # comment out this next line, only needs to be run once to create the lists and then again if you add columns...
    #
    #New-PSManageListsPackagesTasks -spWeb $spWeb

    #
    # Periodically check AD for new computers, so they can be added to SharePoint and get scheduled task installed...
    #
    Update-PSManageComputersFromAD -spWeb $spWeb


    #
    # Also check AD for new users, so they can be added to SharePoint
    #
    Update-PSManageUsers

    #
    # Also scan SharePoint and try to install PSMANAGE scripts on any systems that are not yet phoning home...
    #
    Update-PSManageComputersFromSP -spWeb $spWeb




    #
    # For now, also try to update SharePoint on behalf of older systems that can't do it themselves (XP)...
    #
    If (($rightNowHour -lt 7) -Or ($rightNowHour -gt 18)) {
        Update-PSManageComputersRemotely -spWeb $spWeb
    }



    #
    # Let's send an email update of what work was performed...
    #
    Get-PSManageEmail
}


