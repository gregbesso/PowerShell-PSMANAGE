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
# network location that is shared out so workstations can connect and download the PSMange client scripts...
$global:psmClientSource = '\\server\share\psmanage\CLIENT'
$global:psmClientLocalPath = 'C:\PSManage'


#
# Check if network copy of scripts is accessible. If it is, copy down latest version before importing...
#
If (Test-Path "$global:psmClientSource\PSManageImport.ps1") { 
    If (!(Test-Path "$global:psmClientLocalPath")) { New-Item -ItemType Directory -Path "$global:psmClientLocalPath" }
    Copy-Item -Path "$global:psmClientSource\PSManageImport.ps1" -Destination "$global:psmClientLocalPath\PSManageImport.ps1" -Force
    Copy-Item -Path "$global:psmClientSource\PSManage.ps1" -Destination "$global:psmClientLocalPath\PSManage.ps1" -Force
}


#
# As long as local version of script is accessible, continue with everything else...
#
If (Test-Path "$global:psmClientLocalPath\PSManageImport.ps1") { 
    #  
    # Import local copy of scripts to be used below, and then call the control script to get things moving along...
    #
    . "$global:psmClientLocalPath\PSManageImport.ps1"
	
    Get-PSManageStarted
}