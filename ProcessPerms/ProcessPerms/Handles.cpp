/*
A Microsoft Windows process and thread batch permissions dumper with suspicious DACL alerting

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

https://github.com/nccgroup/WindowsDACLEnumProject

Released under AGPL see LICENSE for more information
*/

#include "stdafx.h"
#include "Handles.h"
#include <vector>

//
//
//
//
//
BYTE GetObjectTypeNumber(LPCWSTR objectName)
{
	OpenDirectory openDir = reinterpret_cast<OpenDirectory>(GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtOpenDirectoryObject"));
	QueryDirectory queryDir = reinterpret_cast<QueryDirectory>(GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtQueryDirectoryObject"));
	BYTE objectNumber = 0;
	UNICODE_STRING us = {0};
	us.Buffer = L"\\ObjectTypes";
	us.Length = wcslen(us.Buffer) * sizeof(WCHAR);
	us.MaximumLength = us.Length + sizeof(WCHAR);
	OBJECT_ATTRIBUTES oa = {sizeof(oa), 0};
	oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.ObjectName = &us;
	HANDLE hDir = NULL;	
    NTSTATUS stat = openDir(&hDir, DIRECTORY_QUERY, &oa);
	if(stat == STATUS_SUCCESS)
	{
		std::vector<BYTE> buffer(32000);
		ULONG len = 0, ctx = 0;
		while((stat = queryDir(hDir, &buffer[0], buffer.size(), FALSE, TRUE, &ctx, &len)) == STATUS_INFO_LENGTH_MISMATCH)
		{
			if(len)
			{
				buffer.resize(len);
			}
			else
			{
				buffer.resize(buffer.size() * 2);
			}
		}
		if(stat == STATUS_SUCCESS)
		{
			POBJECT_DIRECTORY_INFORMATION pObjInf = reinterpret_cast<POBJECT_DIRECTORY_INFORMATION>(&buffer[0]);
			for(ULONG i = 0; i < ctx; ++i)
			{
				OBJECT_DIRECTORY_INFORMATION& obj = pObjInf[i];
				if(!objectNumber)
				{
					if(_wcsicmp(objectName, obj.Name.Buffer) == 0)
					{
						objectNumber = i + 1;
					}
				}
			}
		}
		CloseHandle(hDir);
	}
	return objectNumber;
}

//
//
//
//
//
bool GetJobHandles(HANDLE hProcess, DWORD dwPID)
{
	_NtQuerySystemInformation ntQSI = (_NtQuerySystemInformation) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtQuerySystemInformation");
	if(ntQSI == NULL) return false;

	DWORD dwSize = sizeof(SYSTEM_HANDLE_INFORMATION);

	fprintf(stdout,"[jobs]\n");

	PSYSTEM_HANDLE_INFORMATION pHandleInfo = (PSYSTEM_HANDLE_INFORMATION) HeapAlloc(GetProcessHeap(),NULL,dwSize);
	NTSTATUS dwRet = ntQSI(SystemHandleInformation, pHandleInfo, dwSize, &dwSize);

	if(dwRet == STATUS_INFO_LENGTH_MISMATCH){
		HeapFree(GetProcessHeap(),NULL,pHandleInfo);
		pHandleInfo = (PSYSTEM_HANDLE_INFORMATION) HeapAlloc(GetProcessHeap(),NULL,dwSize);
		dwRet = ntQSI(SystemHandleInformation, pHandleInfo, dwSize, &dwSize);
	}
	
	fprintf(stdout,"[jobs]\n");

	for(DWORD dwCount = 0; dwCount < pHandleInfo->HandleCount ; dwCount++){
		
		if(pHandleInfo->Handles[dwCount].ProcessId == dwPID)
		{
			BYTE bType = GetObjectTypeNumber(L"Job");

			if(bType==0) fprintf(stdout,"[!] Couldn't find job object type within Windows object manager\n");
			else if(bType == pHandleInfo->Handles[dwCount].ObjectTypeNumber) {

				fprintf(stdout,"[opening process]\n");
				fflush(stdout);

				HANDLE hProcessSuperHandle = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pHandleInfo->Handles[dwCount].ProcessId);
				if(hProcessSuperHandle==INVALID_HANDLE_VALUE){
					fprintf(stdout,"[!] Couldn't re-open process with required permissions - %d for PID %d\n",GetLastError(),GetLastError());
					return false;
				}

				fprintf(stdout,"[duplicating]\n");
				fflush(stdout);

				HANDLE hJob = NULL;
				if(DuplicateHandle(hProcessSuperHandle,(HANDLE) pHandleInfo->Handles[dwCount].Handle,GetCurrentProcess(),&hJob,JOB_OBJECT_QUERY,FALSE,0) != FALSE){
					fprintf(stdout,"[jobs] %s\n",pHandleInfo->Handles[dwCount].Handle);
					fflush(stdout);
				} else {
					fprintf(stdout,"[!] Couldn't duplicate job handle - %d %08x\n",GetLastError(),hJob);
					fflush(stdout);
				}


				CloseHandle(hProcessSuperHandle);
				
			}
		} else {
			//fprintf(stdout,"[handle doesn't match]\n");
		}

	}

	
}