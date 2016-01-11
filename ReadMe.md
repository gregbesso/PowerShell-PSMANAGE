## Synopsis

The purpose of this PowerShell scripting tool is to configure a chosen server to act as the PSMANAGE server host, which 
pairs with the Windows workstations that will run the PSMANAGE client scripts. Most of the work is done by the workstations 
but there are certain steps that the server can take care of. 

The server portion of the scripts consists of two files, the PSManage-CentralServer.ps1 file (the control script) and 
the PSManage-CentralServer-Imports.ps1 file (the meat and potatoes of the tool).
The control script pulls down the latest version of the actual script and then imports it.
This allows improvements to be made without having to redeploy the script to existing managed systems that are already phoning home.

Prerequisites to run this script, aside from having sufficient permissions on the systems involved, is to have a SharePoint 2013 
workspace created to connect to. 

## Code Example

This set of scripts has three components. A SharePoint workspace that you need to create ahead of time, server scripts that are run on a chosen 
server, and then client scripts that get installed and run on the workstations by the server.

The server finds systems in AD, installs scripts on them, and also gathers data from server systems about these systems (and your users). The server 
updates SharePoint with information, and so do the systems that get the client scripts installed. 

Then you can go to SharePoint and access all the information in one place :-)


## Motivation

I had many reasons for creating these scripts, just like there are always many things on any persons wish list when working with an environment of systems.
I wanted easier access to information that I already knew how to get to, I wanted to pull additional details that I either wasn't familiar with getting, or 
being able to get them from many systems at a time. There were several instances where people would ask for information and it would either take too long, 
take too many clicks, and just was too manual of a process. I wanted to have a way to pull any information I dealt with frequently from a "one stop shopping" 
portal.

Also I liked the idea of being able to make something from the ground up and not rely on some packaged (and not free) product. It's a fun project and I keep 
making changes to the scripts as new needs arise.



## Installation

1) Think up a name for your new "virtual assistant", which is kind of how the script can be thought of. For example, "SharePoint Steve" will be my example here.
2) Setup the domain account for this new service account, such as DOMAIN\SharePointSteve
3) Grant permissions to your new service account. In my example, I have applied...

Active Directory read to everything, 
SharePoint site collection admin on a new PSMANAGE site collection,
Lync server admin rights and remote powershell permissions
Exchange server admin rights
Windows worsktations local admin rights (i cheated and gave domain admins but if you have a better group use that instead)

4) Copy the CLIENT and SERVER folders somewhere shared on the network. Only you and the service account will need access. You need to lock this folder
down with NTFS permissions because one of the .ps1 files contains the password for your service account. 

5) Run the PSManage-CentralServer.ps1 file from your chosen server. This will copy the SERVER scripts to a local folder on that server, and create a scheduled task on it.
From then on out, the server will keep pulling own the scripts (in case you make changes to them) and running them on an interval.

6) Keep an eye on SharePoint, and watch the data start pouring in. Also check your inbox and see any emails about the service accounts actions. :-)


## API Reference

No API here. <sounds of crickets>

## Tests

No testing info here. <sounds of crickets>

## Contributors

Just a solo script project by moi, Greg Besso. Hi there :-)

## License

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