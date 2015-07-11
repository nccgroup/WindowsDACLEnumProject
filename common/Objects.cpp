
#include "Objects.h"
#include <Windows.h>
#include <malloc.h>
#include <stdio.h>
#include <tchar.h>
#include "stdafx.h"

// Native calls
NTSTATUS (__stdcall *NtOpenDirectoryObject)(HANDLE *, unsigned long, POBJECT_ATTRIBUTES); 
NTSTATUS (__stdcall *NtQueryDirectoryObject)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);
NTSTATUS (__stdcall *NtQueryDirectoryFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);


void EnumerateObjects(PWSTR strRoot)
{
	NTSTATUS statusNT;
	HANDLE hDirOb;
	OBJECT_ATTRIBUTES oaAttrib;
	int intCount=0;
	
	HMODULE hNTDLL = LoadLibrary("ntdll.dll");
	NtOpenDirectoryObject = (NTSTATUS (__stdcall *)(HANDLE *, ACCESS_MASK, POBJECT_ATTRIBUTES)) GetProcAddress(hNTDLL,"NtOpenDirectoryObject");
	NtQueryDirectoryObject = (NTSTATUS (__stdcall *)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG)) GetProcAddress(hNTDLL,"NtQueryDirectoryObject");
	NtQueryDirectoryFile = (NTSTATUS (__stdcall *)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN)) GetProcAddress(hNTDLL,"NtQueryDirectoryFile");

	oaAttrib.Length = 6*4;
	oaAttrib.RootDirectory = 0;
	oaAttrib.ObjectName = (PUNICODE_STRING)malloc(sizeof(UNICODE_STRING)); /* ObjectName is a UNICODE_STRING of fixed size */
	oaAttrib.Attributes = 0;
	oaAttrib.a = 0;
	oaAttrib.b = 0;

	oaAttrib.ObjectName->Length = (USHORT)wcslen(strRoot)*2;
	oaAttrib.ObjectName->MaximumLength = (USHORT)wcslen(strRoot)*2+2;
	oaAttrib.ObjectName->Buffer = strRoot;

	statusNT = NtOpenDirectoryObject(&hDirOb,DIRECTORY_ALL_ACCESS,&oaAttrib);
	
	if (statusNT != STATUS_SUCCESS)
	{
		return;
	}

	UCHAR *strBuffer = (UCHAR*)malloc(1048576); // lovely
	ULONG uContext=0;
	ULONG uRetlen;
	statusNT = NtQueryDirectoryObject(hDirOb,strBuffer,1048576,false,false,&uContext,&uRetlen);
	UNICODE_STRING *pstrName = (PUNICODE_STRING)strBuffer;

	for(intCount=0;pstrName[intCount].Length != 0;intCount+=2)
	{	
		
		TCHAR strFullpath[MAX_PATH];
		sprintf_s(strFullpath,"\\\\.\\%ws",pstrName[intCount].Buffer);
			
		
		if (wcscmp(pstrName[intCount+1].Buffer,L"Directory") == 0 || wcscmp(pstrName[intCount+1].Buffer,L"SymbolicLink") == 0)
		{
			if (wcsstr(strRoot,pstrName[intCount].Buffer) != NULL) break; 

			TCHAR strNewroot[MAX_PATH];
			_tcscpy_s(strNewroot,strRoot);
			
			if (wcscmp(strRoot,L"\\") != 0) _tcscat_s(strNewroot,L"\\");
			_tcscat_s(strNewroot,pstrName[intCount].Buffer);
			EnumerateObjects(strNewroot);

		}

	}

	CloseHandle(hDirOb);
	if (oaAttrib.ObjectName !=NULL) free(oaAttrib.ObjectName);
	if (strBuffer !=NULL)  free(strBuffer);
}