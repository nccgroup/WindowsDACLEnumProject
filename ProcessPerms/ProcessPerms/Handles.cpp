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
ULONG_PTR GetParentProcessId(HANDLE hProcess) // By Napalm @ NetCore2K
{
	ULONG_PTR pbi[6];
	ULONG ulSize = 0;
	LONG (WINAPI *NtQueryInformationProcess)(HANDLE ProcessHandle, ULONG ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength); 
 
	*(FARPROC *)&NtQueryInformationProcess =  GetProcAddress(LoadLibraryA("NTDLL.DLL"), "NtQueryInformationProcess");
 
	if(NtQueryInformationProcess){
		if(NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &ulSize) >= 0 && ulSize == sizeof(pbi))
		return pbi[5];
	}
 
	return (ULONG_PTR)-1;
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
	_NtDuplicateObject ntDupe = (_NtDuplicateObject) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtDuplicateObject");

	DWORD dwSize = sizeof(SYSTEM_HANDLE_INFORMATION_EX);

	PSYSTEM_HANDLE_INFORMATION_EX pHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX) HeapAlloc(GetProcessHeap(),NULL,dwSize);
	NTSTATUS dwRet = ntQSI(SystemExtendedHandleInformation, pHandleInfo, dwSize, &dwSize);

	if(dwRet == STATUS_INFO_LENGTH_MISMATCH){
		HeapFree(GetProcessHeap(),NULL,pHandleInfo);
		pHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX) HeapAlloc(GetProcessHeap(),NULL,dwSize);
		dwRet = ntQSI(SystemExtendedHandleInformation, pHandleInfo, dwSize, &dwSize);
	}
	
	BOOL bRes=FALSE;

	for(DWORD dwCount = 0; dwCount < pHandleInfo->NumberOfHandles ; dwCount++){
	
		bRes=FALSE;

		//ULONG
		//if(GetParentProcessId(hProcess) == pHandleInfo->Handles[dwCount].UniqueProcessId);
		//else if (dwPID == pHandleInfo->Handles[dwCount].UniqueProcessId);
		//else continue;

		HANDLE hProc = NULL;

		//if(GetParentProcessId(hProcess) == pHandleInfo->Handles[dwCount].UniqueProcessId) hProc = OpenProcess(MAXIMUM_ALLOWED,FALSE,GetParentProcessId(hProcess));
		//else if (dwPID == pHandleInfo->Handles[dwCount].UniqueProcessId) hProc = hProcess;
		//else if (752 == pHandleInfo->Handles[dwCount].UniqueProcessId) hProc = OpenProcess(MAXIMUM_ALLOWED,FALSE,GetParentProcessId(hProcess));
		//else continue;

		hProc = OpenProcess(MAXIMUM_ALLOWED,FALSE,pHandleInfo->Handles[dwCount].UniqueProcessId);

		if(hProc == NULL) { 
			//fprintf(stdout,"failed to opened proc\n");
			continue;
		} else {
			//fprintf(stdout,"opened proc\n");
		}

		HANDLE hFoo = NULL;
		ntDupe(hProc,(HANDLE)pHandleInfo->Handles[dwCount].HandleValue,GetCurrentProcess(),&hFoo,GENERIC_READ,0,0);
		
		if(hFoo == NULL) {
			//fprintf(stdout,"failed to dup obj\n");
			continue;
		} else {
			//fprintf(stdout,"duped obj\n");
		}
		
		if(IsProcessInJob(hProcess,hFoo,&bRes) != 0){
			if(bRes==TRUE){
				fprintf(stdout,"[i]   i-> Found job object handle in PID %u\n",pHandleInfo->Handles[dwCount].UniqueProcessId);

				JOBOBJECT_EXTENDED_LIMIT_INFORMATION jelInfo = { 0 };
				JOBOBJECT_BASIC_UI_RESTRICTIONS jelUI = { 0 };

				DWORD dwRet = 0;
				if(QueryInformationJobObject(hFoo,JobObjectExtendedLimitInformation,&jelInfo,sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION),&dwRet) != ERROR_SUCCESS){
					if(jelInfo.BasicLimitInformation.ActiveProcessLimit > 0) fprintf(stdout,"[i]   +-> Job active process limit %d\n",jelInfo.BasicLimitInformation.ActiveProcessLimit);
					if(jelInfo.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS) fprintf(stdout,"[i]   +-> Job active process limit enforced\n");
					if(jelInfo.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_BREAKAWAY_OK) fprintf(stdout,"[i]   +-> Can creat job away jobs\n");
					if(jelInfo.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION) fprintf(stdout,"[i]   +-> Die on unhandled exception\n");
					if(jelInfo.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_JOB_MEMORY) fprintf(stdout,"[i]   +-> Job total memory limited\n");
					if(jelInfo.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) fprintf(stdout,"[i]   +-> All process associated with job will die when last job handle closed\n");
					if(jelInfo.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_PROCESS_MEMORY) fprintf(stdout,"[i]   +-> Process total memory limited\n");
					if(jelInfo.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) fprintf(stdout,"[i]   +-> Can create silent breakaway processes\n");
									
				} else {
					fprintf(stderr,"[!] Failed to get job object limit information - %d\n",GetLastError()); 
				}

				
				if(QueryInformationJobObject(hFoo,JobObjectBasicUIRestrictions,&jelUI,sizeof(JOBOBJECT_BASIC_UI_RESTRICTIONS),&dwRet) != ERROR_SUCCESS){
					if(jelUI.UIRestrictionsClass & JOB_OBJECT_UILIMIT_DESKTOP) fprintf(stdout,"[i]   +-> can't switch or create desktops\n");
					else fprintf(stdout,"[i]   +-> can switch or create desktops\n");

					if(jelUI.UIRestrictionsClass & JOB_OBJECT_UILIMIT_DISPLAYSETTINGS) fprintf(stdout,"[i]   +-> can't call display settings\n");
					fprintf(stdout,"[i]   +-> can call display settings\n");

					if(jelUI.UIRestrictionsClass & JOB_OBJECT_UILIMIT_EXITWINDOWS) fprintf(stdout,"[i]   +-> can't call exit Windows\n");
					else fprintf(stdout,"[i]   +-> can call exit Windows\n");

					if(jelUI.UIRestrictionsClass & JOB_OBJECT_UILIMIT_GLOBALATOMS) fprintf(stdout,"[i]   +-> can't access global atoms\n");
					else fprintf(stdout,"[i]   +-> can access global atoms\n");

					if(jelUI.UIRestrictionsClass & JOB_OBJECT_UILIMIT_HANDLES) fprintf(stdout,"[i]   +-> can't use user handles\n");
					else fprintf(stdout,"[i]   +-> can use user handles\n");

					if(jelUI.UIRestrictionsClass & JOB_OBJECT_UILIMIT_READCLIPBOARD) fprintf(stdout,"[i]   +-> can't read clipboard\n");
					else fprintf(stdout,"[i]   +-> can read clipboard\n");

					if(jelUI.UIRestrictionsClass & JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS) fprintf(stdout,"[i]   +-> can't change system parameters\n");
					else fprintf(stdout,"[i]   +-> can change system parameters\n");

					if(jelUI.UIRestrictionsClass & JOB_OBJECT_UILIMIT_WRITECLIPBOARD) fprintf(stdout,"[i]   +-> can't write to clipboard\n");
					else fprintf(stdout,"[i]   +-> can write to clipboard\n");


				} else {
					fprintf(stderr,"[!] Failed to get job object UI limit information - %d\n",GetLastError()); 
				}

			}
		}

		if(hProc != NULL) CloseHandle(hProc);
		if(hFoo != NULL) CloseHandle(hFoo);
	}

	
}