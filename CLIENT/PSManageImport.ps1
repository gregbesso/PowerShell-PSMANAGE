#Requires -Version 3.0

<#
###
the purpose of this PowerShell scripting tool is to allow Windows workstations and servers gather information about various 
hardware and software components, and then send them to a central repository in SharePoint for reference.

The script consists of two files, the PSManage.ps1 file (the control script) and the PSManageImport.ps1 file (the meat and potatoes of the tool).
The control script pulls down the latest version of the actual script and then imports it.
This allows improvements to be made without having to redeploy the script to existing managed systems that are already phoning home.

Prerequisites to run this script, aside from having sufficient permissions on the systems involved, is to have a SharePoint 2013 
workspace created to connect to. 


###
Copyright (c) 2015 Greg Besso

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
#>

#
# global variables that may be used throughout this tool...
#
# the URL to the SharePoint site you'll be storing the information in...
$global:psmSPWeb = 'https://sharepoint/sites/PSMANAGE'           

# the email sender/receiver, body and server details. body is filled later if needed...
$global:psmEmailBody = ''
$global:psmEmailServer = 'exchange1.domain.int'
$global:psmEmailFrom = 'VirtualVicky@yourDomain.com'
$global:psmEmailTo = 'admin@yourDomain.com'

# the SharePoint server you'll connect to to read/write when needed. Just the hostname or FQDN, not the URL...
$global:psmSharePointServer = 'YourSharePointServersName'

# local path that the PSManage server uses, only used in one or two places but still needed...
$global:psmServerLocalPath = 'C:\PSManage'

# the name of the system that will be gathering and sending info...
$computerName = gc env:computername



# function that gets current list of tasks for this computer...
function Get-PSManageTasks() {
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$spWeb
    )
    #create a new session and load the SharePoint plugins...
    $computerName = Get-Content env:computername
    $sessionSharePoint = New-PSSession -ComputerName $global:psmSharePointServer
    Invoke-Command -Session $sessionSharePoint -ScriptBlock {

        Param ($spWeb, $computerName)

        Add-PSSnapin Microsoft.SharePoint.PowerShell

        #send the list information over to the session and get the spare DIDs
        $sourceWebURL = "$spWeb"
        $sourceListName = "PSMANAGE-TASKS"
        $spSourceWeb = Get-SPWeb "$sourceWebURL"
        $spSourceList = $spSourceWeb.Lists[$sourceListName]
        $spSourceItems = $spSourceList.Items        
        $output = @() 
        
        ForEach ($task in $spSourceItems) {
            $tempName = $task['PSComputerName']
            $tempName = $tempName.Split('#')
            $PSComputerName = $tempName[1]
            If ($PSComputerName -eq $computerName) {
                $TaskID = $task['ID']
                $TaskName = $task['TaskName']
                $tempPackage = $task['TaskPackage']
                $tempPackage = $tempPackage.Split('#')
                $TaskPackage = $tempPackage[1]
          
                $TaskStatus = $task['TaskStatus']
                $tempAssignedTo = $task['TaskAssignedTo']
                $tempAssignedTo = $tempAssignedTo.Split('#')
                $TaskAssignedTo = $tempAssignedTo[1]
                $TaskVerify = $task['TaskVerify']

                $object1 = [pscustomobject]@{
                    TaskID = $TaskID
                    TaskPSComputerName = $PSComputerName;
                    TaskName = $TaskName;
                    TaskPackage = $TaskPackage;           
                    TaskStatus = $TaskStatus;
                    TaskAssignedTo = $TaskAssignedTo;   
                    TaskVerify = $TaskVerify;        
                }
                $output += $object1 
            }
        }
    } -ArgumentList $spWeb, $computerName
    $spSourceItems = Invoke-Command -Session $sessionSharePoint -ScriptBlock { $output }

    #close session once information is obtained... $global:existingTemplates = Get-RemADUser -Filter{(Name -Like '*_Template*') -And (ObjectClass -eq 'user')} | Sort-Object Name | Select Name
    $sessionSharePoint | Remove-PSSession

    #give output
    Return $spSourceItems
}

# function that gets a list of the current install packages from SharePoint...
function Get-PSManagePackages() {
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$spWeb
    )
    #create a new session and load the SharePoint plugins...
    $sessionSharePoint = New-PSSession -ComputerName $global:psmSharePointServer
    Invoke-Command -Session $sessionSharePoint -ScriptBlock {

        Param ($spWeb)

        Add-PSSnapin Microsoft.SharePoint.PowerShell

        #send the list information over to the session and get the spare DIDs
        $sourceWebURL = "$spWeb"
        $sourceListName = "PSMANAGE-PACKAGES"
        $spSourceWeb = Get-SPWeb "$sourceWebURL"
        $spSourceList = $spSourceWeb.Lists[$sourceListName]
        $spSourceItems = $spSourceList.Items        
        $output = @() 
        
        ForEach ($package in $spSourceItems) {
            $PackageID = $package['ID']
            $PackageName = $package['PackageName']
            $PackageInstaller = $package['PackageInstaller']
            $PackageDetails = $package['PackageDetails']
            $PackageVerify = $package['PackageVerify']

            #$TaskPackage = $TaskPackage.Replace("1;#","")           

            $object1 = [pscustomobject]@{
                PackageID = $PackageID
                PackageName = $PackageName;
                PackageInstaller = $PackageInstaller;
                PackageDetails = $PackageDetails; 
                PackageVerify = $PackageVerify;                    
            }
            $output += $object1 

        }
    } -ArgumentList $spWeb
    $spSourceItems = Invoke-Command -Session $sessionSharePoint -ScriptBlock { $output }

    #close session once information is obtained... $global:existingTemplates = Get-RemADUser -Filter{(Name -Like '*_Template*') -And (ObjectClass -eq 'user')} | Sort-Object Name | Select Name
    $sessionSharePoint | Remove-PSSession

    #give output
    Return $spSourceItems
}

# function that loops through each task and installs each referenced package on the computer...
function Run-PSManageTasks() {
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [object]$getTasks,
        [object]$getPackages,
        [string]$spWeb
    )

    $getTasks | ForEach-Object {
        $thisID = $_.TaskID
        $thisPackage = $_.TaskPackage
        $thisComputer = $_.TaskPSComputerName
        $thisStatus = $_.TaskStatus        
        $thisVerifyStatus = 0
        If ($thisStatus -eq 'Not Started') {        
            $getPackages | ForEach-Object {
                $thisName = $_.PackageName
                If ($thisPackage -eq $thisName) {
                    $thisInstaller = $_.PackageInstaller
                    $thisVerify = $_.PackageVerify
                    Try {
                        # check if software item is already installed before running
                        If ($thisVerify.Length -gt 0) { 
                            $getProducts = Get-ComputerInstalledSoftware -ComputerName $computerName
                            $getProducts = $getProducts | Sort-Object DisplayName
                            $getProducts | ForEach {
                                $thisProductName = $_.DisplayName
                                If ($thisProductName -eq $thisVerify) {
                                    $thisVerifyStatus = 1
                                    Update-PSManageTask -spWeb $global:psmSPWeb -spTaskID $thisID -spTaskStatus 'Completed' -spTaskDetails 'already installed'
                                }
                            }
                        }

                        If ($thisVerifyStatus -eq 0) {
                            send-mailmessage -to "$global:psmEmailTo" -from "$global:psmEmailFrom" -subject 'PSManage installation pending...' -body "$computerName is going to install $thisInstaller" -smtpserver "$global:psmEmailServer"

                            If ($thisInstaller -Like '*.bat*') {
                                C:\windows\system32\cmd /c "$thisInstaller" | Out-Null
                            } ElseIf ($thisInstaller -Like '*.ps1*') {
                                $something = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File "$thisInstaller"
                            }
                            #C:\windows\system32\cmd /c "$thisInstaller" | Out-Null                     

                            # check if install completed successfully...
                            If ($thisVerify.Length -gt 0) { 
                                $getProducts = Get-ComputerInstalledSoftware -ComputerName $computerName
                                $getProducts = $getProducts | Sort-Object DisplayName
                                $getProducts | ForEach {
                                    $thisProductName = $_.DisplayName
                                    If ($thisProductName -eq $thisVerify) {
                                        $thisVerifyStatus = 1
                                    }
                                }
                            } Else { $thisVerifyStatus = 1 }

                            If ($thisVerifyStatus -eq 1) {
                                Update-PSManageTask -spWeb $global:psmSPWeb -spTaskID $thisID -spTaskStatus 'Completed' -spTaskDetails 'all set'
                            } Else {
                                Update-PSManageTask -spWeb $global:psmSPWeb -spTaskID $thisID -spTaskStatus 'In Progress' -spTaskDetails 'the installation was not able to complete successfully'
                            }
                        }


                    } Catch {
                        $getThis = $_.Exception.Message
                        send-mailmessage -to "$global:psmEmailTo" -from "$global:psmEmailFrom" -subject "Installation on $thisComputer error" -body "$thisComputer tried to install $thisInstaller, but ran into an error: $getThis" -smtpserver "$global:psmEmailServer"
                        Update-PSManageTask -spWeb $global:psmSPWeb -spTaskID $thisID -spTaskStatus 'In Progress' -spTaskDetails $getThis
                    }
                }
            } 
        }       
    }
}

# updates SharePoint tasks list for software that was installed / had an issue.
function Update-PSManageTask() {
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$spWeb,
        [string]$spTaskID,
        [string]$spTaskStatus,
        [string]$spTaskDetails
    )

    BEGIN{}
    PROCESS{
        Try {
            $spListName = 'PSMANAGE-TASKS'

            #connect to sharepoint and send data over...
            If (!($sessionSharePoint)) { $sessionSharePoint = New-PSSession -ComputerName $global:psmSharePointServer}

            Invoke-Command -Session $sessionSharePoint -ScriptBlock {
                # get input from function calling remote session
                Param ($spWeb, $spListName, $spTaskID, $spTaskStatus, $spTaskDetails)

                Add-PSSnapin Microsoft.SharePoint.PowerShell
                #send the list information over to the session
                $rightNow = Get-Date
                $spWeb = Get-SPWeb $spWeb
                $spList = $spWeb.Lists["$spListName"]
                $newItem = $spList.Items | ?{($_["ID"] -eq "$spTaskID")}
                $newItem["TaskStatus"] = $spTaskStatus
                $newItem["TaskDetails"] = $spTaskDetails
                $newItem.Update()  
                $spList.Update()


            #END loop for array

            } -ArgumentList $spWeb, $spListName, $spTaskID, $spTaskStatus, $spTaskDetails

        } Catch {
            Write-Warning "Error occurred: $_.Exception.Message"
        }
    }
    End {}
}

# function that takes a computer name and gathers various information about it FROM LOCAL WMI and stores in text files.
function Update-PSManageInfoGatherLocal() {
<# 
.SYNOPSIS 
Gathers information about the local computer.
.DESCRIPTION 
Uses WMI and registry to gather computer system, OS, BIOS, disks, certificates, and installed program info. Exports to XML for use later.
.EXAMPLE 
Update-PSManageInfoGatherLocal
#>
    BEGIN{}
    PROCESS{
        Try {
            #
            # create folders to store cached info that is gathered...            
            #
            If (!(Test-Path "$global:psmClientLocalPath\Local")) { New-Item -ItemType Directory -Path "$global:psmClientLocalPath\Local" }
            If (!(Test-Path "$global:psmClientLocalPath\SP")) { New-Item -ItemType Directory -Path "$global:psmClientLocalPath\SP" }

            #
            # get all info gathered and store in variables...            
            #           
            $computerName = Get-Content env:computername
            $getCS = Get-WmiObject Win32_ComputerSystem -ComputerName $computerName | Select-Object -Property PSComputerName, BootupState, ThermalState, Status, Domain, CurrentTImeZone, NumberOfLogicalProcessors, NumberOfProcessors, PrimaryOwnerName, Manufacturer, Model, SystemFamily, SystemSKUNumber, SystemType, TotalPhysicalMemory, UserName
            $getOS = Get-WmiObject Win32_OperatingSystem -ComputerName $computerName | Select-Object -Property PSComputerName, FreePhysicalMemory, FreeSpaceInPagingFiles, FreeVirtualMemory, BuildNumber, BuildType, Caption, CodeSet, CountryCode, CurrentTimeZone, InstallDate, LastBootUpTime, LocalDateTime, Manufacturer, NumberOFProcesses, NumberOfUsers, OperatingSystemSKU, OSArchitecture, OSLanguage, OSType, SerialNumber, TotalVirtualMemorySize, TotalVisibleMemorySize, Version
            $getBIOS = Get-WmiObject Win32_BIOS -ComputerName $computerName | Select-Object -Property PSComputerName, BIOSVersion, CurrentLanguage, Manufacturer, ReleaseDate, SerialNumber, SMBIOSBIOSVersion, Version
            $getDisks = Get-WmiObject Win32_LogicalDisk -ComputerName $computerName | Select-Object -Property DeviceID, DriveType, Description, FileSystem, FreeSpace, Size, VolumeName
            # removed the Win32_Product call due to it being unsafe for use in a live environment
            # https://support.microsoft.com/en-us/kb/974524
            # $getProducts = Get-WmiObject Win32_Product -ComputerName $computerName | Select-Object -Property @{Name="ProductName";Expression={$_."Name"}},@{Name="ProductVersion";Expression={$_."Version"}},Vendor,InstallDate,InstallSource,LocalPackage,PackageName,IdentifyingNumber
            $getProducts = Get-ComputerInstalledSoftware -ComputerName $computerName
            $getCerts = Get-ComputerCerts

  
            #
            # cycle through CS, OS, BIOS objects and combine them into one getAll object with renamed column names and formatted values...           
            #            
            $getAll = New-Object -TypeName PSObject
            $getAll | Add-Member -MemberType NoteProperty -Name 'PSComputerName' -Value $computerName
            $getPSVersion = $PSVersionTable.PSVersion.Major
            $getAll | Add-Member -MemberType NoteProperty -Name 'PSVersion' -Value $getPSVersion  
  
            # add computer model if applicable...
            $getThis = Get-WmiObject -Class Win32_ComputerSystemProduct -ComputerName $computerName | Select-Object -Property Name, Version
            $getThisName = $getThis.Name
            $getThisVersion = $getThis.Version
            If ($getThisVersion.Length -lt 5) { $getModel = $getThisName } Else { $getModel = $getThisVersion }
            $getAll | Add-Member -MemberType NoteProperty -Name 'CS-ModelName' -Value $getModel
                     
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
            $getAll | Export-Clixml "$global:psmClientLocalPath\Local\getAll.xml"


            #
            # repeat similar steps but for each disk found on the the system...          
            #
            $getDisks | Export-Clixml "$global:psmClientLocalPath\Local\getDisks.xml"
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
                    $_ | Export-Clixml "$global:psmClientLocalPath\Local\getDisk-$deviceID.xml"
                }
            }

            #
            # repeat similar steps but for each installed product found on the system...           
            #

            $getProducts | ForEach {
                Try {
                    $_.PSObject.properties | ForEach-Object {            
                        If (($_.Name -eq 'InstallDate') -Or ($_.Name -eq 'LastBootUpTime') -Or ($_.Name -eq 'LocalDateTime') -Or ($_.Name -like '*Date*')) {                  
                            If ($_.Value.Length -lt 1) { $tempValue = '19500101000000.000000-240' } Else { $tempValue = $_.Value }
                            If ($tempValue.Length -eq 8) { $tempValue += '000000.000000-240' }
                            $newValue = [System.Management.ManagementDateTimeConverter]::ToDateTime($tempValue)
                            $_.Value = $newValue
                        }
                    } 
                } Catch {}
                #$_ | Add-Member -MemberType NoteProperty -Name 'PSComputerName' -Value $computerName               
            }
            $getProducts | Export-Clixml "$global:psmClientLocalPath\Local\getProducts.xml"



            #
            # repeat similar steps but for each certificate in the local computer store...          
            #
            $getCerts | Export-Clixml "$global:psmClientLocalPath\Local\getCerts.xml"

                       
        } Catch {
                    Write-Warning "Error occurred: $_.Exception.Message"
        }
    }
    End {}
}

# function that compares the gathered information and decides if SharePoint needs to get updated with anything...
function Update-PSManageInfoCompareLocal() {
<# 
.SYNOPSIS 
Compares newly gathered and existing information from XML files to determine if changes need to be sent.
.DESCRIPTION 
Local and SP folders hold the gathered information. If changes are found, they are stored in new objects and then sent to SharePoint.
.PARAMETER spWeb
The URL of the SharePoint site that stores the information.
.EXAMPLE 
Update-PSManageInfoCompareLocal -spWeb 'https://sharepoint/sites/PSMANAGE'
#>
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$spWeb
    )

    BEGIN{}
    PROCESS{
        Try {
            #
            # get all info gathered and store in variables...            
            #            
            $computerName = gc env:computername
            $compareAll = 0
            $compareDisks = 0
            $compareProductsAdd = 0
            $compareProductsRemove = 0
            $compareCertsAdd = 0
            $compareCertsRemove = 0

            #
            # cycle through CS, OS, BIOS objects and combine them into one getAll object with renamed column names and formatted values...           
            #            
            $getAll = Import-Clixml "$global:psmClientLocalPath\Local\getAll.xml"
            If (!(Test-Path "$global:psmClientLocalPath\SP\getAll.xml")) { $getAllSP = New-Object -TypeName PSObject } Else { $getAllSP = Import-Clixml "$global:psmClientLocalPath\SP\getAll.xml" }
     
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
            $getDisks = Import-Clixml "$global:psmClientLocalPath\Local\getDisks.xml"         
            $getDisks | ForEach {                
                #exclude network drives, include all others...
                If ($_.DriveType -ne 4) {
                    $deviceID = $_.DeviceID[0]
                    $getDisk = Import-Clixml "$global:psmClientLocalPath\Local\getDisk-$deviceID.xml"

                    If (!(Test-Path "$global:psmClientLocalPath\SP\getDisk-$deviceID.xml")) { $getDiskSP = New-Object -TypeName PSObject } Else { $getDiskSP = Import-Clixml "$global:psmClientLocalPath\SP\getDisk-$deviceID.xml" }
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

            $getProducts = Import-Clixml "$global:psmClientLocalPath\Local\getProducts.xml"

            If (!(Test-Path "$global:psmClientLocalPath\SP\getProducts.xml")) { $getProductsSP = New-Object -TypeName PSObject } Else { $getProductsSP = Import-Clixml "$global:psmClientLocalPath\SP\getProducts.xml" }

            $getProductsAdd = @()
            $getProductsRemove = @()
            # get list of newly installed products...
            $getProducts | ForEach {
                $isNew = $True
                $idLocal = $_.PSChildName
                $getProductsSP | ForEach {
                    $idSP = $_.PSChildName
                    If ($idLocal -eq $idSP) { $isNew = $False }
                }
                If ($isNew -eq $True) { 
                    $object1 = New-Object PSObject -Property @{
                        PSComputerName=$_.PSComputerName
                        DisplayName=$_.DisplayName
                        DisplayVersion=$_.DisplayVersion
                        EstimatedSize=$_.EstimatedSize
                        HelpLink=$_.HelpLink
                        HelpTelephone=$_.HelpTelephone
                        InstallDate=$_.InstallDate
                        InstallLocation=$_.InstallLocation
                        InstallSource=$_.InstallSource
                        Language=$_.Language
                        ModifyPath=$_.ModifyPath
                        NoModify=$_.NoModify
                        NoRemove=$_.NoRemove
                        NoRepair=$_.NoRepair
                        PSChildName=$_.PSChildName
                        Publisher=$_.Publisher
                        SystemComponent=$_.SystemComponent
                        UninstallString=$_.UninstallString
                        ProductVersion=$_.ProductVersion
                        ProductVersionMajor=$_.ProductVersionMajor
                        ProductVersionMinor=$_.ProductVersionMinor
                        WindowsInstaller=$_.WindowsInstaller            
                    }
                    $getProductsAdd += $object1
                    $compareProductsAdd++
                }
            }
            # get list of recently removed products...
            $getProductsSP | ForEach {
                $isNew = $True
                $idLocal = $_.PSChildName
                $getProducts | ForEach {
                    $idSP = $_.PSChildName
                    If ($idLocal -eq $idSP) { $isNew = $False }

                }
                If ($isNew -eq $True) { 
                    $object1 = New-Object PSObject -Property @{
                        PSComputerName=$_.PSComputerName
                        DisplayName=$_.DisplayName
                        DisplayVersion=$_.DisplayVersion
                        EstimatedSize=$_.EstimatedSize
                        HelpLink=$_.HelpLink
                        HelpTelephone=$_.HelpTelephone
                        InstallDate=$_.InstallDate
                        InstallLocation=$_.InstallLocation
                        InstallSource=$_.InstallSource
                        Language=$_.Language
                        ModifyPath=$_.ModifyPath
                        NoModify=$_.NoModify
                        NoRemove=$_.NoRemove
                        NoRepair=$_.NoRepair
                        PSChildName=$_.PSChildName
                        Publisher=$_.Publisher
                        SystemComponent=$_.SystemComponent
                        UninstallString=$_.UninstallString
                        ProductVersion=$_.ProductVersion
                        ProductVersionMajor=$_.ProductVersionMajor
                        ProductVersionMinor=$_.ProductVersionMinor
                        WindowsInstaller=$_.WindowsInstaller         
                    }
                    $getProductsRemove += $object1
                    $compareProductsRemove++
                }
            }



            #
            # repeat similar steps but for each certificate on the system         
            #            
            $getCerts = Import-Clixml "$global:psmClientLocalPath\Local\getCerts.xml"

            If (!(Test-Path "$global:psmClientLocalPath\SP\getCerts.xml")) { $getCertsSP = New-Object -TypeName PSObject } Else { $getCertsSP = Import-Clixml "$global:psmClientLocalPath\SP\getCerts.xml" }

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
                    Update-PSManageInfoSharePointLocal -getAll $getAll -spWeb $spWeb -spListName $spListName -computerName $computerName
                    Copy-Item -Path "$global:psmClientLocalPath\Local\getAll.xml" -Destination "$global:psmClientLocalPath\SP\getAll.xml" -Force
                }

                If ($compareDisks -gt 0) {
                    $spListName = 'PSMANAGE-DISKS'
                    $getDisks | ForEach {
                        #exclude network drives, include all others...
                        If ($_.DriveType -ne 4) {
                            $deviceID = $_.DeviceID[0]
                            $getDisk = Import-Clixml "$global:psmClientLocalPath\Local\getDisk-$deviceID.xml"
                            $compareDisk = 0
                            #if different than last time, upload to SharePoint
                            If (!(Test-Path "$global:psmClientLocalPath\SP\getDisk-$deviceID.xml")) { $getDiskSP = New-Object -TypeName PSObject } Else { $getDiskSP = Import-Clixml "$global:psmClientLocalPath\SP\getDisk-$deviceID.xml" }
                            $getDisk.PSObject.properties | ForEach-Object {
                                If (($_.Name -NotLike '*Memory*') -And ($_.Name -NotLike '*Paging*') -And ($_.Name -NotLike '*NumberOfProcesses*' )) {
                                    If (Compare-Object $getDisk $getDiskSP -Property $_.Name) { $compareDisk++ }
                                }
                            }
                            If ($compareDisk -gt 0) {
                                Update-PSManageInfoSharePointLocal -getAll $getDisk -spWeb $spWeb -spListName $spListName -computerName $computerName
                                Copy-Item -Path "$global:psmClientLocalPath\Local\getDisk-$deviceID.xml" -Destination "$global:psmClientLocalPath\SP\getDisk-$deviceID.xml" -Force
                            }
                        }
                    }
                }


                If ($compareProductsAdd -gt 0) {
                    $spListName = 'PSMANAGE-PRODUCTS'                 
                    Update-PSManageInfoSharePointLocal -getAll $getProductsAdd -spWeb $spWeb -spListName $spListName -computerName $computerName
                }

                # Remove-PSManageInfoSharePointLocal
                If ($compareProductsRemove -gt 0) {
                    $spListName = 'PSMANAGE-PRODUCTS'
                    Remove-PSManageInfoSharePointLocal -getAll $getProductsRemove -spWeb $spWeb -spListName $spListName -spColumnName 'IdentifyingNumber' -computerName $computerName                    
                }


                If ($compareCertsAdd -gt 0) {
                    $spListName = 'PSMANAGE-CERTIFICATES'                 
                    Update-PSManageInfoSharePointLocal -getAll $getCertsAdd -spWeb $spWeb -spListName $spListName -computerName $computerName
                }

                If ($compareCertsRemove -gt 0) {
                    $spListName = 'PSMANAGE-CERTIFICATES'
                    Remove-PSManageInfoSharePointLocal -getAll $getCertsRemove -spWeb $spWeb -spListName $spListName -spColumnName 'Thumbprint' -computerName $computerName                    
                }


                If (($compareProductsAdd -gt 0) -Or ($compareProductsRemove -gt 0)) {
                    Copy-Item -Path "$global:psmClientLocalPath\Local\getProducts.xml" -Destination "$global:psmClientLocalPath\SP\getProducts.xml" -Force
                }

                If (($compareCertsAdd -gt 0) -Or ($compareCertsRemove -gt 0)) {
                    Copy-Item -Path "$global:psmClientLocalPath\Local\getCerts.xml" -Destination "$global:psmClientLocalPath\SP\getCerts.xml" -Force
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

# updates SharePoint with various information about users and computers...
function Update-PSManageInfoSharePointLocal() {
<# 
.SYNOPSIS 
Updates a SharePoint list with information sent to the function.
.DESCRIPTION 
Accepts a list and a PowerShell object, then updates the list with the record(s) in the object. Also will create the list if it does not
yet exist.
.PARAMETER getAll
The PowerShell object that contains the record(s) of information to add or update in SharePoint.
.PARAMETER spListName
The name of the list that the record(s) should be stored in, such as PSMANAGE-COMPUTERS.
.PARAMETER spWeb
The URL of the SharePoint site that stores the information.
.PARAMETER computerName
The name of the computer that is sending the information.
.EXAMPLE 
Update-PSManageInfoSharePointLocal -getAll $getDrives -spListName 'PSMANAGE-DISKS' -spWeb 'https://sharepoint/sites/PSMANAGE' -computerName 'gbesso-lp'
#>
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [object]$getAll,
        [string]$spListName,
        [string]$spWeb,
        [string]$computerName
    )

    BEGIN{}
    PROCESS{
        Try {
            #connect to sharepoint and send data over...
            If (!($sessionSharePoint)) { $sessionSharePoint = New-PSSession -ComputerName $global:psmSharePointServer}

            Invoke-Command -Session $sessionSharePoint -ScriptBlock {
                # get input from function calling remote session
                Param ($getAll, $spWeb, $spListName, $computerName)

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

                #start loop for array...
                $getAll | ForEach {
                    #get computer name for this item being added/updated...
                    $compareDeviceID = $_.DeviceID
                    $comparePSChildName = $_.PSChildName


                    If ($spList.Fields.ContainsField("DeviceID") -eq $True) { #if list is PSMANAGE-DISKS, and dealing with drives...
                        $newItem = $spList.Items | ?{($_["Title"] -eq "$computerName") -And ($_["DeviceID"] -eq "$compareDeviceID")}
                    } ElseIf ($spList.Fields.ContainsField("ProductVersion") -eq $True) { #if list is PSMANAGE-PRODUCTS, and dealing with installed software...
                        $newItem = $spList.Items | ?{($_["Title"] -eq "$computerName") -And ($_["PSChildName"] -eq "$comparePSChildName")}
                    } Else { #if list is most likely PSMANAGE-COMPUTERS or other list...
                        $newItem = $spList.Items | ?{$_["Title"] -eq "$computerName"}
                    }


                    #loop through all properties and update the item for ComputerSystem...
                    If ($computerName.Length -gt 0) {                        
                        #add new item if existing list entry not found for this computer...
                        If ($newItem.Count -lt 1) { $newItem = $spList.AddItem() }

                        $newItem["Title"] = $computerName
                        $newItem.Update()

                        $_.PSObject.properties | ForEach-Object {
                            #get the name of the computer for the sharepoint list item's title column...
                            $thisName = $_.Name
                            $thisValue = $_.Value
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
                                } ElseIf ($_.TypeNameOfValue -eq 'System.DateTime') {
                                    $thisFieldType = [Microsoft.SharePoint.SPFieldType]::DateTime
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
                        }

                        #
                        # check for, and add if necessary, the PSLastPhoneHome column
                        #
                        If ($spList.Fields.ContainsField('PSLastPhoneHome') -eq $False) {
                            $thisFieldType = [Microsoft.SharePoint.SPFieldType]::DateTime
                            $spList.Fields.Add('PSLastPhoneHome', $thisFieldType, $false)
                        }
                        $newItem['PSLastPhoneHome'] = $rightNow
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
                    
                        #
                        #
                        #
                        #once done adding fields...
                        $spList.Update()
                    }

                #END loop for array
                }
            } -ArgumentList $getAll, $spWeb, $spListName, $computerName

        } Catch {
            Write-Warning "Error occurred: $_.Exception.Message"
        }
    }
    End {}
}

# updates SharePoint with various information about users and computers...
function Remove-PSManageInfoSharePointLocal() {
<# 
.SYNOPSIS 
Removes record(s) from a SharePoint list that are no longer valid / existing on the computer.
.DESCRIPTION 
If an item such as an installed program, certificate or drive no longer exists on a computer, it should be removed from SharePoint. This function 
takes care of that.
.PARAMETER getAll
The PowerShell object that contains the record(s) of information to remove from SharePoint.
.PARAMETER spListName
The name of the list that the record(s) should be removed from, such as PSMANAGE-COMPUTERS.
.PARAMETER spWeb
The URL of the SharePoint site that stores the information.
.PARAMETER computerName
The name of the computer that is sending the information.
.EXAMPLE 
Remove-PSManageInfoSharePointLocal -getAll $getDrives -spListName 'PSMANAGE-DISKS' -spWeb 'https://sharepoint/sites/PSMANAGE' -computerName 'gbesso-lp'
#>
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

# lets client update its own info from AD by using the SP server host session...
function Update-PSManageADUpdateComputersList() {
<# 
.SYNOPSIS 
Adds computer name to an XML file on the SharePoint server, which is used by other functions.
.DESCRIPTION 
Active Directory details are not queried by each workstation, but by the SharePoint server on a schedule. This function adds the computer to the XML file 
which is a queue. Any computer named in that file will get its AD details refreshed in SharePoint next time that function runs. Then the file is flushed. 
If a computer is phoning home, it is active and possibly has some AD changes worth checking on. So that's why this exists.
.PARAMETER computerName
The name of the computer that is sending the information.
.EXAMPLE 
Update-PSManageADUpdateComputersList -computerName 'gbesso-lp' -serverLocalPath 'c:\psmanage'
#>
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$computerName,
        [string]$serverLocalPath
    )


    #connect to SharePoint
    $sessionSharePoint = New-PSSession -ComputerName $global:psmSharePointServer

    # tell SharePoint to do stuff
    Invoke-Command -Session $sessionSharePoint -ScriptBlock {
        # get input from function calling remote session
        Param ($computerName, $serverLocalPath)

        $getAll = @()
        If (!(Test-Path "$serverLocalPath\Server\Queue")) { New-Item -ItemType Directory -Path "$serverLocalPath\Server\Queue" }  
        $getNew = New-Object -TypeName PSObject
        $getNew | Add-Member -MemberType NoteProperty -Name 'PSComputerName' -Value $computerName

    
        If (!(Test-Path "$serverLocalPath\Server\Queue\ADUpdateComputersList.xml")) { 
            $getExisting = New-Object -TypeName PSObject 
        } Else { 
            $getExisting = Import-Clixml "$serverLocalPath\Server\Queue\ADUpdateComputersList.xml" 
            $getAll += $getExisting
        }

   
        $getAll += $getNew
        $getAll | Export-Clixml "$serverLocalPath\Server\Queue\ADUpdateComputersList.xml"

    } -ArgumentList $computerName, $serverLocalPath

    # close SP session once done using...
    If ($sessionSharePoint) { $sessionSharePoint | Remove-PSSession }
}

# gets the local computer stores personal certificates...
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

# gets installed software from a chosen computer...
function Get-ComputerInstalledSoftware() {
<# 
.SYNOPSIS 
Gathers information about installed software on a computer and returns it.
.DESCRIPTION 
Installed software applications are one of several local computer details gathered by this PowerShell tool, this function gets the 
certificate details and sends them to the function that is calling it. That function will then do something with the information.
.PARAMETER computerName
The name of the computer that is sending the information.
.EXAMPLE 
Get-ComputerInstalledSoftware -computerName 'gbesso-lp'
#>
    Param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [string]$computerName
    )
   
    $array = @()
    $getAll = Get-ChildItem -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall -Recurse
    $getAll | ForEach {
        Try {
            $getProperties = $_ | Get-ItemProperty
            $getDate = $getProperties.InstallDate
            $getVersion = $getProperties.DisplayVersion
            #If (($getDate.Length -gt 0) -And ($getVersion.Length -gt 0)) {
            If ($getVersion.Length -gt 0) {
                $obj = New-Object PSObject
                $obj | Add-Member -MemberType NoteProperty -Name "PSComputerName" -Value $computerName
                $obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $getProperties.DisplayName
                $obj | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value $getProperties.DisplayVersion
                $obj | Add-Member -MemberType NoteProperty -Name "EstimatedSize" -Value $getProperties.EstimatedSize
                $obj | Add-Member -MemberType NoteProperty -Name "HelpLink" -Value $getProperties.HelpLink
                $obj | Add-Member -MemberType NoteProperty -Name "HelpTelephone" -Value $getProperties.HelpTelephone
                $obj | Add-Member -MemberType NoteProperty -Name "InstallDate" -Value $getProperties.InstallDate
                $obj | Add-Member -MemberType NoteProperty -Name "InstallLocation" -Value $getProperties.InstallLocation
                $obj | Add-Member -MemberType NoteProperty -Name "InstallSource" -Value $getProperties.InstallSource
                $obj | Add-Member -MemberType NoteProperty -Name "Language" -Value $getProperties.Language
                $obj | Add-Member -MemberType NoteProperty -Name "ModifyPath" -Value $getProperties.ModifyPath
                $obj | Add-Member -MemberType NoteProperty -Name "NoModify" -Value $getProperties.NoModify
                $obj | Add-Member -MemberType NoteProperty -Name "NoRemove" -Value $getProperties.NoRemove
                $obj | Add-Member -MemberType NoteProperty -Name "NoRepair" -Value $getProperties.NoRepair
                $obj | Add-Member -MemberType NoteProperty -Name "PSChildName" -Value $getProperties.PSChildName
                $obj | Add-Member -MemberType NoteProperty -Name "Publisher" -Value $getProperties.Publisher
                $obj | Add-Member -MemberType NoteProperty -Name "SystemComponent" -Value $getProperties.SystemComponent
                $obj | Add-Member -MemberType NoteProperty -Name "UninstallString" -Value $getProperties.UninstallString
                $obj | Add-Member -MemberType NoteProperty -Name "ProductVersion" -Value $getProperties.Version
                $obj | Add-Member -MemberType NoteProperty -Name "ProductVersionMajor" -Value $getProperties.VersionMajor
                $obj | Add-Member -MemberType NoteProperty -Name "ProductVersionMinor" -Value $getProperties.VersionMinor
                $obj | Add-Member -MemberType NoteProperty -Name "WindowsInstaller" -Value $getProperties.WindowsInstaller
                $array += $obj
            }
        } Catch {}
    }

    $getAll = Get-ChildItem -Path HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall -Recurse
    $getAll | ForEach {
        Try {
            $getProperties = $_ | Get-ItemProperty
            $getDate = $getProperties.InstallDate
            $getVersion = $getProperties.DisplayVersion
            #If (($getDate.Length -gt 0) -And ($getVersion.Length -gt 0)) {
            If ($getVersion.Length -gt 0) {
                $obj = New-Object PSObject
                $obj | Add-Member -MemberType NoteProperty -Name "PSComputerName" -Value $computerName
                $obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $getProperties.DisplayName
                $obj | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value $getProperties.DisplayVersion
                $obj | Add-Member -MemberType NoteProperty -Name "EstimatedSize" -Value $getProperties.EstimatedSize
                $obj | Add-Member -MemberType NoteProperty -Name "HelpLink" -Value $getProperties.HelpLink
                $obj | Add-Member -MemberType NoteProperty -Name "HelpTelephone" -Value $getProperties.HelpTelephone
                $obj | Add-Member -MemberType NoteProperty -Name "InstallDate" -Value $getProperties.InstallDate
                $obj | Add-Member -MemberType NoteProperty -Name "InstallLocation" -Value $getProperties.InstallLocation
                $obj | Add-Member -MemberType NoteProperty -Name "InstallSource" -Value $getProperties.InstallSource
                $obj | Add-Member -MemberType NoteProperty -Name "Language" -Value $getProperties.Language
                $obj | Add-Member -MemberType NoteProperty -Name "ModifyPath" -Value $getProperties.ModifyPath
                $obj | Add-Member -MemberType NoteProperty -Name "NoModify" -Value $getProperties.NoModify
                $obj | Add-Member -MemberType NoteProperty -Name "NoRemove" -Value $getProperties.NoRemove
                $obj | Add-Member -MemberType NoteProperty -Name "NoRepair" -Value $getProperties.NoRepair
                $obj | Add-Member -MemberType NoteProperty -Name "PSChildName" -Value $getProperties.PSChildName
                $obj | Add-Member -MemberType NoteProperty -Name "Publisher" -Value $getProperties.Publisher
                $obj | Add-Member -MemberType NoteProperty -Name "SystemComponent" -Value $getProperties.SystemComponent
                $obj | Add-Member -MemberType NoteProperty -Name "UninstallString" -Value $getProperties.UninstallString
                $obj | Add-Member -MemberType NoteProperty -Name "ProductVersion" -Value $getProperties.Version
                $obj | Add-Member -MemberType NoteProperty -Name "ProductVersionMajor" -Value $getProperties.VersionMajor
                $obj | Add-Member -MemberType NoteProperty -Name "ProductVersionMinor" -Value $getProperties.VersionMinor
                $obj | Add-Member -MemberType NoteProperty -Name "WindowsInstaller" -Value $getProperties.WindowsInstaller
                $array += $obj
            }
        } Catch {}
    }

    Return $array
}

# function that starts the process and calls all the other functions...
function Get-PSManageStarted() {
<# 
.SYNOPSIS 
This is the control script that calls all the other functions as needed.
.DESCRIPTION 
This function walks the local computer through the process of gathering local information, then comparing it to previously gathered information. 
If changes are identified, those are then sent to SharePoint to be added (or removed).
.EXAMPLE 
Get-PSManageStarted
#>
    
    # MANUAL CLEANUP START
    # these test-path lines are temporary lines to do cleanup of testing files or flushing cached queries to ensure updates are performed...
    <#
    If (Test-Path "$global:psmClientLocalPath\SP\reDoProducts2.xml") { Remove-Item -Path "$global:psmClientLocalPath\SP\reDoProducts2.xml" -Force}

    # temporary to trigger another full upload of all installed products on computers that already had tried
    If (!(Test-Path "$global:psmClientLocalPath\SP\reDoProducts3.xml")) {
        New-Item -Path "$global:psmClientLocalPath\SP\reDoProducts3.xml" -ItemType "File"
        If (Test-Path "$global:psmClientLocalPath\Local\GetProducts.xml") { Remove-Item -Path "$global:psmClientLocalPath\Local\GetProducts.xml" -Force}
        If (Test-Path "$global:psmClientLocalPath\SP\GetProducts.xml") { Remove-Item -Path "$global:psmClientLocalPath\SP\GetProducts.xml" -Force}
    }
    #>
    # MANUAL CLEANUP END


    #
    # Get tasks for this computer, if any...
    #
    $computerName = gc env:computername
    $getTasks = Get-PSManageTasks -spWeb $global:psmSPWeb
    $getPackages = Get-PSManagePackages -spWeb $global:psmSPWeb
    If ($getTasks) {
        Run-PSManageTasks -spWeb $global:psmSPWeb -getTasks $getTasks -getPackages $getPackages
    }

    #
    # Run the first script, which is to gather local system info and store them in XML files...
    #
    Update-PSManageInfoGatherLocal


    #
    # Run the comparision script to see if any updates to SharePoint are needed...
    #
    Update-PSManageInfoCompareLocal -spWeb $global:psmSPWeb


    #
    # Let server know to check this computer for new AD information
    #
    Update-PSManageADUpdateComputersList -computerName $computerName -serverLocalPath $global:psmServerLocalPath

    #
    # Phone home update to let Greg know script is running
    #    

    # for troubleshooting or ridiculously frequent insight, uncomment out if you want 
    # email notifications to flow about phoning home systems...
    <#
    $global:psmEmailBody += "`n$computerName just checking in :-)"
    $tasksCount = $getTasks
    $global:psmEmailBody += "`ntasks is $tasksCount"
    If (Test-Connection -ComputerName "$global:psmEmailServer" -Quiet) {        
        send-mailmessage -to "$global:psmEmailTo" -from "$global:psmEmailFrom" -subject 'PSManage Phone Home' -body "$global:psmEmailBody" -smtpserver "$global:psmEmailServer"
    }
    #>
}