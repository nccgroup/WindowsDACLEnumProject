Windows DACL Enum Project
======================

A collection of tools to enumerate and analyse Windows DACLs

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

https://github.com/nccgroup/WindowsDACLEnumProject

Released under AGPL see LICENSE for more information

Overview of Windows DACLs and ACEs
-------------
Read - http://msdn.microsoft.com/en-us/library/windows/desktop/aa446597(v=vs.85).aspx

Tool #1: Process Perms
-------------

###### Features
The first tools released as part of this project. Will enumerate:
* Processes and the integrity level and user they are running as.
* Optionally: the DACLs associated with the process object.
* Optionally: the threads for a process and the DACLs associated with them.
* Optionally: The modules loaded by a process
* Optionally: Exclude non mapped SIDs from the output

The tool will automatically flag any suspicious DACLs.

###### Command Line Options
The command line take the following options:
* -p Process permissions
* -m Modules
* -t Threads and permissions
* -o [PID]
* -x exclude non mapped SIDs from alerts

###### Typical Usage
Typical usage will be with a command line such as:
processperms -px

The tool is designed for Windows Vista / Server 2008 and higher due to integrity level awareness.

###### Screenshot
=======
Designed for Windows Vista / Server 2008 and higher due to integrity level awareness.

![ScreenShot](https://raw.github.com/nccgroup/WindowsDACLEnumProject/master/screenshots/processandthread.png)