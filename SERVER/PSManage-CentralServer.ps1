#Requires -Version 3.0

<#
###
The purpose of this PowerShell scripting tool is to configure a chosen server to act as the PSMANAGE server host, which 
pairs with the Windows workstations that will run the PSMANAGE client scripts. Most of the work is done by the workstations 
but there are certain steps that the server can take care of. 

The server portion of the scripts consists of two files, the PSManage-CentralServer.ps1 file (the control script) and 
the PSManage-CentralServer-Imports.ps1 file (the meat and potatoes of the tool).
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
# network location that is shared out so the server can connect and download the PSMange client scripts...
$global:psmServerSource = '\\server\share\psmanage\SERVER'
$global:psmServerLocalPath = 'C:\PSManage'
$global:psmServerRemotePath = 'C$\PSManage'

# network location that is shared out so workstations can connect and download the PSMange client scripts...
$global:psmClientSource = '\\server\share\psmanage\CLIENT'

# local and remote paths referencing where the script files will be stored on the workstations.
# this needs to match the path you also will set in the PSManage.ps1 script file!
$global:psmClientLocalPath = 'C:\PSManage'
$global:psmClientRemotePath = 'C$\PSManage' #use remote c$ or similar admin share to connect to your chosen drive on workstations

# the SharePoint server you'll connect to to read/write when needed. Just the hostname or FQDN, not the URL...
$global:psmSharePointServer = 'YourSharePointServersName'
# this site needs to exist already, just go create any empty site collection and/or workspace for the scripts to use...
$spWeb = 'https://YourSharePointServersName/sites/PSMANAGE'

# some more global variables that might be called from several of the functions in the imports file.
$global:impDomainController = 'YourDomainControllersName'
$global:impExchangeServer = 'YourExchangeServersName'
$global:impLyncServer = 'YourLyncServersName'
$global:impYourDomainNetBios = 'DOMAIN'
$global:impYourDomainFQDN = 'DOMAIN.local'
$global:impEmailFrom = 'VirtualVicky@yourDomain.com'
$global:impEmailTo = 'admin@yourDomain.com'
# the SAM account name for your dedicated service account that will run all the
# PSMANAGE scripts on the server and workstations
$global:impYourServiceAccountDisplay = 'Virtual Vicky'
$global:impYourServiceAccountSAM = 'VirtualVicky'
# in this version of the scripts, the password for the service account is stored in this file for 
# the ability to push scripts to clients and create scheduled tasks under this account. 
# Store this file in a place that is protected so only the service account and your domain admins
# can access this. Sorry! Perhaps in "version 2" I can improve on this.
$global:impYourServiceAccountPW = 'SomeAwesomePasswordGoesHere'



#
# Check if network copy of scripts is accessible. If it is, copy down latest version before importing...
#
Try {
    If (Test-Path "$global:psmServerSource\PSManage-CentralServer-Imports.ps1") { 
        If (!(Test-Path "$global:psmServerLocalPath")) { New-Item -ItemType Directory -Path "$global:psmServerLocalPath" }
        If (!(Test-Path "$global:psmServerLocalPath\Server")) { New-Item -ItemType Directory -Path "$global:psmServerLocalPath\Server" }
        Copy-Item -Path "$global:psmServerSource\PSManage-CentralServer-Imports.ps1" -Destination "$global:psmServerLocalPath\Server\PSManage-CentralServer-Imports.ps1" -Force
        Copy-Item -Path "$global:psmServerSource\PSManage-CentralServer.ps1" -Destination "$global:psmServerLocalPath\Server\PSManage-CentralServer.ps1" -Force
    }
} Catch {}



#
# As long as local version of script is accessible, continue with everything else...
#
If (Test-Path "$global:psmServerLocalPath\Server\PSManage-CentralServer-Imports.ps1") { 
    #  
    # Import local copy of scripts to be used below, and then call the control script to get things moving along...
    #
    . "$global:psmServerLocalPath\Server\PSManage-CentralServer-Imports.ps1"

    #
    # Variables that may be used later on...
    #    
    $global:PSManageEmailBody = ''


    #$something = Get-PSManageCentralServerStarted -spWeb $spWeb
    #Set-PSManageServerScheduledTask -computerName "$global:psmSharePointServer"
    Get-PSManageCentralServerStarted -spWeb $spWeb
}


