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
The first tool released as part of this project. Will enumerate:
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


Tool #2: Window Stations and Desktops
-------------

###### Features
The second tool released as part of this project. Will enumerate:
* Window Stations within the session that it is executed and the associated DACL
* Desktops within those Window Stations and the associated DACLs


Tool #3: Services
-------------

###### Features
The third tool released as part of this project. Will enumerate:
* Services including kernel drivers, filter drivers and user land services.
* DACLs associated with the service entries in the service control manager.
* Service status, PID, binary path.
* DACLs associated with with the binaries associated
* Flag obviously weak DACLs

Tool #4: File System
-------------

###### Features
The fourth tool released as part of this project. Will enumerate:
* Files and access control lists
* Directories and access control lists
* Alert on files or directories with access control which appear weak