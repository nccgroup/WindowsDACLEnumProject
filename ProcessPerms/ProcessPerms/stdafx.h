/*
A Micrsoft Windows process and thread batch permissions dumper with suspicious DACL alerting

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

https://github.com/nccgroup/WindowsDACLEnumProject

Released under AGPL see LICENSE for more information
*/

#pragma once

#ifndef _WIN32_WINNT		// Allow use of features specific to Windows XP or later.     
// 0x0501
#define _WIN32_WINNT 0x0600	// Change this to the appropriate value to target other versions of Windows.
#endif						


#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <Psapi.h>
#include <Aclapi.h>
#include <tlhelp32.h>
#include <wtsapi32.h>


// TODO: reference additional headers your program requires here
