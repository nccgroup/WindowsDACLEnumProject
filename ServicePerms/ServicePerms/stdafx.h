/*
A Microsoft Windows service permissions dumper with suspicious DACL alerting

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

https://github.com/nccgroup/WindowsDACLEnumProject

Released under AGPL see LICENSE for more information
*/

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include <wtsapi32.h>