/*
A Microsoft Windows process and thread batch permissions dumper with suspicious DACL alerting

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

https://github.com/nccgroup/WindowsDACLEnumProject

Released under AGPL see LICENSE for more information
*/


#include "stdafx.h"
#include "XGetopt.h"

// global 
HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

BOOL CALLBACK EnumWindowStationProc(LPTSTR lpszWindowStation, LPARAM lParam)
{
	fprintf(stdout,"[win] found %s\n",lpszWindowStation);
	if(OpenWindowStation(lpszWindowStation,FALSE,WINSTA_ALL_ACCESS) == NULL){
		fprintf(stdout,"[win!] couldn't open %s - %d\n",lpszWindowStation,GetLastError());
	}

	return true;
}

//
BOOL WindowStationEnumOpen(){
	EnumWindowStations(&EnumWindowStationProc,NULL);
	return true;
}


//
// Function	: SetDebugPrivilege
// Role		: Gets debug privs for our process
// Notes	: 
//
BOOL SetDebugPrivilege(HANDLE hProcess)
{
	LUID luid ;
	TOKEN_PRIVILEGES privs ;
	HANDLE hToken = NULL ;
	DWORD dwBufLen = 0 ;
	char buf[1024] ;
	
	ZeroMemory( &luid,sizeof(luid) ) ;
	
	if(! LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &luid ))
		return false ;
	
	privs.PrivilegeCount = 1 ;
	privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED ;
	memcpy( &privs.Privileges[0].Luid, &luid, sizeof(privs.Privileges[0].Luid )
		) ;
	
	
	if( ! OpenProcessToken( hProcess, TOKEN_ALL_ACCESS,&hToken))
		return false ;
	
	if( !AdjustTokenPrivileges( hToken, FALSE, &privs,
		sizeof(buf),(PTOKEN_PRIVILEGES)buf, &dwBufLen ) )
		return false ;

	CloseHandle(hProcess);
	CloseHandle(hToken);
	
	return true ;
}

//
// Function	: UserForPID
// Role		: Username for a PID
// Notes	: 
// 
bool UserForPID(DWORD dwPID){
	DWORD dwRet=0;
	DWORD dwCount=0;
	DWORD dwSize = 2048;
	char lpName[2048];
	char lpDomain[2048];
	SID_NAME_USE SNU;

	PWTS_PROCESS_INFO ppProcessInfo;
	
	if(WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE,0,1,&ppProcessInfo,&dwRet)){
		for(dwCount=0;dwCount<dwRet;dwCount++){
			if(ppProcessInfo[dwCount].ProcessId==dwPID){
				// Lookup the account name and print it.
				// http://msdn2.microsoft.com/en-library/aa379554.aspx
				if( !LookupAccountSid( NULL, ppProcessInfo[dwCount].pUserSid, lpName, &dwSize, lpDomain, &dwSize, &SNU ) ) {
					DWORD dwResult = GetLastError();
					if( dwResult == ERROR_NONE_MAPPED ){
						fprintf(stdout,"[NotMapped]");
						WTSFreeMemory(ppProcessInfo);
						return false;
					}else {
						fprintf(stdout,"[*ERRROR*]");
						WTSFreeMemory(ppProcessInfo);
						return false;
					}
				} else {
					fprintf(stdout,"%s",lpName);
					WTSFreeMemory(ppProcessInfo);
					if(strcmp(lpName,"SYSTEM")==0) return true;
					else return false;
				}
			}
		}
	} else {
		fprintf(stdout,"[*ERRROR* - *ERROR*]");
		return false;
	}

	return false;
}

//
// Function	: UserForPID
// Role		: Username for a PID
// Notes	: 
// 
bool UserForPIDToString(DWORD dwPID, char* strUser, DWORD strLen){
	DWORD dwRet=0;
	DWORD dwCount=0;
	DWORD dwSize = 2048;
	char lpName[2048];
	char lpDomain[2048];
	SID_NAME_USE SNU;

	PWTS_PROCESS_INFO ppProcessInfo;
	
	if(WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE,0,1,&ppProcessInfo,&dwRet)){
		for(dwCount=0;dwCount<dwRet;dwCount++){
			if(ppProcessInfo[dwCount].ProcessId==dwPID){
				// Lookup the account name and print it.
				// http://msdn2.microsoft.com/en-library/aa379554.aspx
				if( !LookupAccountSid( NULL, ppProcessInfo[dwCount].pUserSid, lpName, &dwSize, lpDomain, &dwSize, &SNU ) ) {
					DWORD dwResult = GetLastError();
					if( dwResult == ERROR_NONE_MAPPED ){
						strcpy_s(strUser,strLen,"NONMAPPED");
						WTSFreeMemory(ppProcessInfo);
						return strlen(strUser);
					}else {
						WTSFreeMemory(ppProcessInfo);
						strcpy_s(strUser,strLen,"ERROR");
						return 0;
					}
				} else {
					WTSFreeMemory(ppProcessInfo);
					strcpy_s(strUser,strLen,lpName);
					return strlen(strUser);
				}
			}
		}
	} else {
		fprintf(stdout,"[*ERRROR* - *ERROR*]");
		return false;
	}

	return false;
}

//
// Function	: GetProcessIntegrityLevel
// Role		: Gets a process handles integrity level
// Notes	: http://msdn.microsoft.com/en-us/library/bb625966.aspx
//
DWORD GetProcessIntegrityLevel(HANDLE hProcess,bool bPrint)
{
	HANDLE hToken;
	DWORD dwLengthNeeded;
	DWORD dwError = ERROR_SUCCESS;
	PTOKEN_MANDATORY_LABEL pTIL = NULL;
	DWORD dwIntegrityLevel = 0;
	DWORD dwRet = 0;
 
	if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) 
	{
		// Get the Integrity level.
		if (!GetTokenInformation(hToken, TokenIntegrityLevel, 
			NULL, 0, &dwLengthNeeded))
		{
			dwError = GetLastError();
			if (dwError == ERROR_INSUFFICIENT_BUFFER)
			{
				pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLengthNeeded);
    
				if (pTIL != NULL)
				{
					if (GetTokenInformation(hToken, TokenIntegrityLevel, 
						pTIL, dwLengthNeeded, &dwLengthNeeded))
					{
						dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, 
							(DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid)-1));
 
						if (dwIntegrityLevel == SECURITY_MANDATORY_UNTRUSTED_RID)
						{
							// System Integrity
							SetConsoleTextAttribute(hConsole, 11);
							if(bPrint==true) printf("Untrusted Process - ");
							SetConsoleTextAttribute(hConsole, 7);
							dwRet = 0;
						} 
						else if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
						{
							// Low Integrity
							SetConsoleTextAttribute(hConsole, 10);
							if(bPrint==true) printf("Low Integrity Process - ");
							SetConsoleTextAttribute(hConsole, 7);
							dwRet =  1;
						}
						else if (dwIntegrityLevel == SECURITY_MANDATORY_MEDIUM_RID)
						{
							// Medium Integrity
							SetConsoleTextAttribute(hConsole, 8);
							if(bPrint==true) printf("Medium Integrity Process - ");
							SetConsoleTextAttribute(hConsole, 7);
							dwRet = 2;
						}		
						else if (dwIntegrityLevel == SECURITY_MANDATORY_MEDIUM_PLUS_RID)
						{
							// System Integrity
							SetConsoleTextAttribute(hConsole, 13);
							if(bPrint==true) printf("Medium Plus Integrity Process - ");
							SetConsoleTextAttribute(hConsole, 7);
							dwRet = 3;
						}
						else if (dwIntegrityLevel == SECURITY_MANDATORY_HIGH_RID)
						{
							// High Integrity
							SetConsoleTextAttribute(hConsole, 14);
							if(bPrint==true) printf("High Integrity Process - ");
							SetConsoleTextAttribute(hConsole, 7);
							dwRet = 4;
						}
						else if (dwIntegrityLevel == SECURITY_MANDATORY_SYSTEM_RID)
						{
							// System Integrity
							SetConsoleTextAttribute(hConsole, 12);
							if(bPrint==true) printf("System Integrity Process - ");
							SetConsoleTextAttribute(hConsole, 7);
							dwRet = 5;
						}  
						else if (dwIntegrityLevel == SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
						{
							// System Integrity
							SetConsoleTextAttribute(hConsole, 15);
							if(bPrint==true) printf("Protected Process - ");
							SetConsoleTextAttribute(hConsole, 7);
							dwRet = 6;
						} 
						else 
						{
							// Unknown
							SetConsoleTextAttribute(hConsole, 12);
							if(bPrint ==true)  printf("Unknown Integrity Process %d - ",dwIntegrityLevel);
							SetConsoleTextAttribute(hConsole, 7);
							dwRet = 99;
						}
					}
				
					LocalFree(pTIL);
				}
			}
		}
		
		CloseHandle(hToken);
	}

	return dwRet;
}

//
// Function	: sidToText
// Role		: Converts a binary SID to a nice one
// Notes	: http://win32.mvps.org/security/dumpacl/dumpacl.cpp
//
const char *sidToText( PSID psid )
{
	// S-rev- + SIA + subauthlen*maxsubauth + terminator
	static char buf[15 + 12 + 12*SID_MAX_SUB_AUTHORITIES + 1];
	char *p = &buf[0];
	PSID_IDENTIFIER_AUTHORITY psia;
	DWORD numSubAuths, i;

	// Validate the binary SID.

	if ( ! IsValidSid( psid ) )
		return FALSE;

	psia = GetSidIdentifierAuthority( psid );

	p = buf;
	p += _snprintf_s( p, 15 + 12 + 12*SID_MAX_SUB_AUTHORITIES + 1, &buf[sizeof buf] - p, "S-%lu-", 0x0f & *( (byte *) psid ) );

	if ( ( psia->Value[0] != 0 ) || ( psia->Value[1] != 0 ) )
		p += _snprintf_s( p,15 + 12 + 12*SID_MAX_SUB_AUTHORITIES + 1, &buf[sizeof buf] - p, "0x%02hx%02hx%02hx%02hx%02hx%02hx",
			(USHORT) psia->Value[0], (USHORT) psia->Value[1],
			(USHORT) psia->Value[2], (USHORT) psia->Value[3],
			(USHORT) psia->Value[4], (USHORT) psia->Value[5] );
	else
		p += _snprintf_s( p, 15 + 12 + 12*SID_MAX_SUB_AUTHORITIES + 1, &buf[sizeof buf] - p, "%lu", (ULONG) ( psia->Value[5] ) +
			(ULONG) ( psia->Value[4] << 8 ) + (ULONG) ( psia->Value[3] << 16 ) +
			(ULONG) ( psia->Value[2] << 24 ) );

	// Add SID subauthorities to the string.

	numSubAuths = *GetSidSubAuthorityCount( psid );
	for ( i = 0; i < numSubAuths; ++ i )
		p += _snprintf_s( p, 15 + 12 + 12*SID_MAX_SUB_AUTHORITIES + 1,&buf[sizeof buf] - p, "-%lu", *GetSidSubAuthority( psid, i ) );

	return buf;
}

//
// Function	: PrintPermissions
// Role		: Print and interpret the permissions for threads and processes
// Notes	: 
//
void PrintPermissions( HANDLE hObject, char *strProc, bool bSystem, bool bThread, DWORD dwPID, bool bExclude)
{

	DWORD					dwRet=0;
	DWORD					dwCount=0;
	PACL					DACL;
	PSECURITY_DESCRIPTOR	PSD;
	ACCESS_ALLOWED_ACE		*ACE;
	
	// http://msdn2.microsoft.com/en-us/library/aa446654.aspx
	dwRet = GetSecurityInfo(hObject, 
							SE_KERNEL_OBJECT, 
							OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
							NULL,
							NULL,
							&DACL,
							NULL,
							&PSD
	);

	if(hObject==NULL || hObject==INVALID_HANDLE_VALUE) return;

	if (dwRet!=ERROR_SUCCESS) 
	{
		DWORD dwError = GetLastError();
		fprintf(stderr,"[!] Error - %d %d - GetSecurityInfo\n", dwError,dwRet);
		return;
	} else {
		// http://msdn2.microsoft.com/en-us/library/aa379142.aspx
		if(IsValidAcl(DACL) == TRUE){

			// Now for each ACE in the DACL
			for(dwCount=0;dwCount<DACL->AceCount;dwCount++){
				// http://msdn2.microsoft.com/en-us/library/aa446634.aspx
				// http://msdn2.microsoft.com/en-us/library/aa379608.aspx
				if(GetAce(DACL,dwCount,(LPVOID*)&ACE)){
					// http://msdn2.microsoft.com/en-us/library/aa374892.aspx		
					SID *sSID = (SID*)&(ACE->SidStart);
					if(sSID != NULL)
					{
						DWORD dwSize = 2048;
						char lpName[2048];
						char lpDomain[2048];
						SID_NAME_USE SNU;
						
						switch(ACE->Header.AceType){

							// Allowed ACE
							case ACCESS_ALLOWED_ACE_TYPE:
								// Lookup the account name and print it.										
								// http://msdn2.microsoft.com/en-us/library/aa379554.aspx
								if( !LookupAccountSidA( NULL, sSID, lpName, &dwSize, lpDomain, &dwSize, &SNU ) ) {
									
									DWORD dwResult = GetLastError();
									if( dwResult == ERROR_NONE_MAPPED && !bExclude ){
										fprintf(stdout,"[i]    |\n");
										fprintf(stdout,"[i]    +-+-> Allowed - NONMAPPED (on %s) - SID %s\n", strProc,sidToText(sSID));
										fprintf(stdout,"[i]    |\n");
										SetConsoleTextAttribute(hConsole, 12);
										fprintf(stdout,"[i]    +-+-+-> Alert!\n");
										SetConsoleTextAttribute(hConsole, 7);
									} else if (dwResult != ERROR_NONE_MAPPED){
										fprintf(stderr,"[!] LookupAccountSid Error 	%u\n", GetLastError());
										fprintf(stdout,"[i]    |\n");
										fprintf(stdout,"[i]    +-+-> Allowed - ERROR     (on %s) - SID %s\n", strProc,sidToText(sSID));
										fprintf(stdout,"[i]    |\n");
										SetConsoleTextAttribute(hConsole, 12);
										fprintf(stdout,"[i]    +-+-+-> Alert!\n");
										SetConsoleTextAttribute(hConsole, 7);
										//return;
									} else {
										continue;
									}
								} else {
									
									fprintf(stdout,"[i]    |\n");
									fprintf(stdout,"[i]    +-+-> Allowed - %s\\%s (on %s ) %d\n",lpDomain,lpName,strProc,bThread);

									char strUserFromPID[1024];
									memset(strUserFromPID,0x00,1024);
									UserForPIDToString(dwPID,strUserFromPID,1024);

									if(!strcmp(lpDomain,"BUILTIN")==0 && !strcmp(lpName,"OWNER RIGHTS")==0 && !strcmp(lpDomain,"NT AUTHORITY")==0 && !strcmp(lpDomain,"NT SERVICE")==0) {
										if(!strcmp(lpName,strUserFromPID)==0 && !bThread){
											fprintf(stdout,"[i]    |\n");
											SetConsoleTextAttribute(hConsole, 12);
											fprintf(stdout,"[i]    +-+-+-> Alert!\n");
										}
										SetConsoleTextAttribute(hConsole, 7);
									}
								}
								
								// print out the ACE mask
								fprintf(stdout,"[i]      |\n");
								fprintf(stdout,"[i]      +-> Permissions - ");
								
								if(!bThread){
									if(ACE->Mask & PROCESS_ALL_ACCESS) fprintf(stdout,",Process All");
									if(ACE->Mask & PROCESS_CREATE_PROCESS) fprintf(stdout,",Create Process");
									if(ACE->Mask & PROCESS_CREATE_THREAD ) fprintf(stdout,",Create Thread");
									if(ACE->Mask & PROCESS_DUP_HANDLE) fprintf(stdout,",Duplicate Handle");
									if(ACE->Mask & PROCESS_QUERY_INFORMATION ) fprintf(stdout,",Query Information");
									if(ACE->Mask & PROCESS_QUERY_LIMITED_INFORMATION) fprintf(stdout,",Query Limited Information");
									if(ACE->Mask & PROCESS_SET_INFORMATION ) fprintf(stdout,",Set Information");
									if(ACE->Mask & PROCESS_SET_QUOTA) fprintf(stdout,",Set Quota");
									if(ACE->Mask & PROCESS_SUSPEND_RESUME) fprintf(stdout,",Suspend/Resume");
									if(ACE->Mask & PROCESS_TERMINATE ) fprintf(stdout,",Terminate");
									if(ACE->Mask & PROCESS_VM_OPERATION  ) fprintf(stdout,",Virtual Memory Operation");
									if(ACE->Mask & PROCESS_VM_READ) fprintf(stdout,",Virtual Memory Read");
									if(ACE->Mask & PROCESS_VM_WRITE  ) fprintf(stdout,",Virtual Memory Write");
									if(ACE->Mask & PROCESS_SET_SESSIONID) fprintf(stdout,",Set Session ID");
									if(ACE->Mask & SYNCHRONIZE  ) fprintf(stdout,",Synchronize");
									if(ACE->Mask & WRITE_OWNER) fprintf(stdout,",Change Owner");
									if(ACE->Mask & WRITE_DAC) fprintf(stdout,",Change Permissions");
								} else {
									if(ACE->Mask & THREAD_TERMINATE) fprintf(stdout,",Terminate Thread"); 
									if(ACE->Mask & THREAD_SUSPEND_RESUME) fprintf(stdout,",Suspend Thread"); 
									if(ACE->Mask & THREAD_GET_CONTEXT) fprintf(stdout,",Get Thread Context");           
									if(ACE->Mask & THREAD_SET_CONTEXT) fprintf(stdout,",Set Thread Context");    
									if(ACE->Mask & THREAD_QUERY_INFORMATION) fprintf(stdout,",Query Thread Information");  
									if(ACE->Mask & THREAD_SET_INFORMATION) fprintf(stdout,",Set Thread Information");      
									if(ACE->Mask & THREAD_SET_THREAD_TOKEN) fprintf(stdout,",Set Thread Token");  
									if(ACE->Mask & THREAD_IMPERSONATE) fprintf(stdout,",Impersonate Thread");        
									if(ACE->Mask & THREAD_DIRECT_IMPERSONATION) fprintf(stdout,",Direct Impersonate Thread"); 
									if(ACE->Mask & THREAD_SET_LIMITED_INFORMATION) fprintf(stdout,",Set Limited Information"); 
									if(ACE->Mask & THREAD_QUERY_LIMITED_INFORMATION) fprintf(stdout,",Query Limited Information");
									if(ACE->Mask & DELETE) fprintf(stdout,",Delete object");
									if(ACE->Mask & READ_CONTROL) fprintf(stdout,",Read DACL");
									if(ACE->Mask & WRITE_OWNER) fprintf(stdout,",Change Owner");
									if(ACE->Mask & WRITE_DAC) fprintf(stdout,",Change Permissions");
								}
							
								fprintf(stdout,"\n");
								break;

							// Denied ACE
							case ACCESS_DENIED_ACE_TYPE:
								// Lookup the account name and print it.
								// http://msdn2.microsoft.com/en-library/aa379554.aspx
								if( !LookupAccountSid( NULL, sSID, lpName, &dwSize, lpDomain, &dwSize, &SNU ) ) {
									DWORD dwResult = GetLastError();

									if( dwResult == ERROR_NONE_MAPPED ){
										fprintf(stdout,"[i]    |\n");
										fprintf(stdout,"[i]    +-+-> Denied - NONMAPPED (on %s) - SID %s\n", strProc,sidToText(sSID));
									} else {
										fprintf(stdout,"[!] LookupAccountSid Error 	%u\n", GetLastError());
										return;
									}
								} else {
									fprintf(stdout,"[i]    |\n");
									fprintf(stdout,"[i]    +-+-> Denied - %s (on %s )\n",lpName,strProc);
								}
							
								// print out the ACE mask
								/*
								fprintf(stdout,"[i]      |\n");
								fprintf(stdout,"[i]      +-> Permissions - ");
								*/
							
								fprintf(stdout,"\n");

								break;

							// Uh oh
							default:
								break;

						}
					}
				} else {
					DWORD dwError = GetLastError();
					fprintf(stderr,"[!] Error - %d - GetAce\n", dwError);
					return;
				}

			}
		} else {
			DWORD dwError = GetLastError();
			fprintf(stderr,"[!] Error - %d - IsValidAcl\n", dwError);
			return;
		}
	}

	LocalFree(PSD);

}



//
// Function	: EnumerateThreads
// Role		: Enumerate threads for a PID
// Notes	: Based in part on - http://msdn.microsoft.com/en-us/library/ms686852(VS.85).aspx
// 
DWORD EnumerateThreads(DWORD dwPID, char *strProc, bool bSystem,bool bExclude){

	HANDLE hThreadSnap = INVALID_HANDLE_VALUE; 
	HANDLE hThread=NULL;
	DWORD  dwCount=0;
	THREADENTRY32 te32; 

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0); 
	if( hThreadSnap == INVALID_HANDLE_VALUE ) {
		fprintf(stderr,"[!] CreateToolhelp32Snapshot(),%d\n", GetLastError());
		return 0; 
	}
 
	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32 ); 
 
	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if( !Thread32First( hThreadSnap, &te32 ) ) 
	{
		fprintf(stderr,"[!] Thread32First(),%d\n", GetLastError());
		CloseHandle( hThreadSnap );    // Must clean up the snapshot object!
		return 0;
	}

	// Now walk the thread list of the system,
	// and display information about each thread
	// associated with the specified process
	GetDesktopWindow();
	do 
	{ 
		TCHAR strName[4096];
		if(te32.th32OwnerProcessID==dwPID){
			dwCount++;
			/*
			HDESK hdThread = NULL;
			hdThread = GetThreadDesktop(te32.th32ThreadID);
			if(hdThread == NULL) fprintf(stderr,"[!] Failed to get thread desktop for %d - %d\n",te32.th32ThreadID,GetLastError());
			DWORD szNeeded = NULL;
			if(GetUserObjectInformation(hdThread,UOI_NAME,&strName,4094,&szNeeded)==0) sprintf(strName,"FailedToGetName - %d",GetLastError());
			fprintf(stdout,"[i] %s\n", "  |");
			*/
			/*
			if(strcmp(strName,"Default") != 0){
				fprintf(stdout,"[i] %s [0x%08X - %d - %s - Alert]\n", "  +--> Thread", te32.th32ThreadID, te32.th32ThreadID,strName);
			} else{
				fprintf(stdout,"[i] %s [0x%08X - %d - %s]\n", "  +--> Thread", te32.th32ThreadID, te32.th32ThreadID,strName);
			}*/
			fprintf(stdout,"[i] %s [0x%08X - %d]\n", "  +--> Thread", te32.th32ThreadID, te32.th32ThreadID);
			hThread=OpenThread(THREAD_ALL_ACCESS,false,te32.th32ThreadID);
			if( hThread != INVALID_HANDLE_VALUE ) {
				PrintPermissions(hThread,strProc,bSystem,true,dwPID,bExclude);
			}
		}
	} while( Thread32Next(hThreadSnap, &te32 ) ); 

	//  Don't forget to clean up the snapshot object.
	CloseHandle( hThreadSnap );
	if( hThread != INVALID_HANDLE_VALUE ) CloseHandle( hThread);
	
	return dwCount;
}

//
// Function	: EnumerateProcessInformation
// Role		: Basic process information
// Notes	: 
// 
void EnumerateProcessInformation(bool bModules, bool bPerms, bool bThreads,DWORD dwPID,bool bExclude)
{
	DWORD intCount, dwRet, dwMods;
	HANDLE hProcess;
	HMODULE hModule[9000];
	char cProcess[MAX_PATH];
	char cModule[MAX_PATH];
	
	//PROCESS_ALL_ACCESS |PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
	hProcess = OpenProcess(PROCESS_ALL_ACCESS |PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID);
	if (hProcess == NULL)
	{
		if(GetLastError()==5){
			hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID);
			
			if (hProcess == NULL){
				
				PWTS_PROCESS_INFO pProcessInfo;
				DWORD dwProcessCount=0;
				
				if(WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE,0,1,&pProcessInfo, &dwProcessCount)==0){
					fprintf(stderr,"[!] OpenProcess fallback failed (%d),%d\n", dwPID, GetLastError());
					return;
				} else{
					for(DWORD dwCount=0;dwCount<dwProcessCount;dwCount++){
						if(pProcessInfo[dwCount].ProcessId == dwPID){
							strcpy_s(cProcess,MAX_PATH,pProcessInfo[dwCount].pProcessName);				
						}
					}
					WTSFreeMemory(pProcessInfo);
				}
			}
		} else { // Last error wasn't access denied 
			fprintf(stderr,"[!] OpenProcess failed (%d),%d\n", dwPID, GetLastError());
			return;
		}
	} else { // Process handle not NULL

		if (EnumProcessModules(hProcess,hModule,9000*sizeof(HMODULE), &dwRet) == 0)
		{
			if(GetLastError() == 299){
				fprintf(stderr,"[i] 64bit process and we're 32bit - sad panda! skipping PID %d\n",dwPID);
			} else {
				fprintf(stderr,"[!] EnumProcessModules(%d),%d\n", dwPID, GetLastError());
			}
			return;
		}
		dwMods = dwRet / sizeof(HMODULE);

		GetModuleBaseName(hProcess,hModule[0],cProcess,MAX_PATH);
	}


	DWORD dwSessionID = 0;
	ProcessIdToSessionId(dwPID,&dwSessionID);
	
	PWTS_SESSION_INFO pSessionInfo;
	DWORD dwSessionInfo=0;
	WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE,0,1,&pSessionInfo,&dwSessionInfo);
	DWORD dwCount=0;
	for(dwCount=0;dwCount<dwSessionInfo;dwCount++){
		if(pSessionInfo[dwCount].SessionId == dwSessionID) break;
	}

	fprintf(stdout,"[i] %s [%s - PID: %d in session %d - window station %s] - ", "+> Process", cProcess,dwPID, dwSessionID,pSessionInfo[dwCount].pWinStationName);	
	GetProcessIntegrityLevel(hProcess,true);
	bool bSystem=UserForPID(dwPID);
	fprintf(stdout,"\n");

	if(bPerms){
		fprintf(stdout,"[i] %s\n", "|");
		fprintf(stdout,"[i] %s [%s]\n", "+-+-> Permissions", cProcess);
		PrintPermissions(hProcess,cProcess,bSystem,false,dwPID,bExclude);
	}

	if(bThreads){
		fprintf(stdout,"[i] %s\n", "|");
		fprintf(stdout,"[i] %s [%s]\n", "+-+-> Threads", cProcess);
		if(EnumerateThreads(dwPID,cProcess,bSystem,bExclude)==0){
			fprintf(stdout,"[i] %s\n", "  +--> No Threads");
		}
	}

	if(bModules){
		fprintf(stdout,"[i] %s\n", "|");
		fprintf(stdout,"[i] %s [%s]\n", "+-+-> Modules", cModule);
		for(intCount=0;intCount<dwMods;intCount++)
		{
			GetModuleFileNameEx(hProcess,hModule[intCount],cModule,MAX_PATH);
			fprintf(stdout,"[i] %s\n", "  |");
			fprintf(stdout,"[i] %s [%s]\n", "  +--> Module", cModule);
		}
	}

	CloseHandle(hProcess);
}

//
// Function	: EnumerateProcesses
// Role		: Basic process running
// Notes	: 
// 
void EnumerateProcesses(bool bModules, bool bPerms, bool bThreads, bool bExclude)
{
	DWORD dwPIDArray[2048], dwRet, dwPIDS, intCount;


	if (EnumProcesses(dwPIDArray,2048*sizeof(DWORD),&dwRet) == 0)
	{
		fprintf(stderr,"[!]  EnumProcessesAndModules(),%d\n", GetLastError());
		return;
	}

	dwPIDS = dwRet / sizeof(DWORD);

	for(intCount=0;intCount<dwPIDS;intCount++)
	{
		EnumerateProcessInformation(bModules,bPerms,bThreads,dwPIDArray[intCount],bExclude);
	}
}


//
// Function	: PrintHelp
// Role		: 
// Notes	: 
// 
void PrintHelp(char *strExe){

	fprintf (stdout,"    i.e. %s [-p] [-m] [-t] [-o] [-x] [-h]\n",strExe);
	fprintf (stdout,"    -p Process permissions\n");
	fprintf (stdout,"    -m Modules\n");
	fprintf (stdout,"    -t Threads and permissions\n");
	fprintf (stdout,"    -o [PID] just analyse this specific PID\n");
	fprintf (stdout,"    -x exclude non mapped SIDs from alerts\n");
	fprintf (stdout,"\n");
	ExitProcess(1);
}


//
// Function	: _tmain
// Role		: Entry point
// Notes	: 
// 
int _tmain(int argc, _TCHAR* argv[])
{

	bool	bHelp=false;
	bool	bProcPerms=false;
	bool	bModules=false;
	bool	bThreadsandPerms=false;
	bool	bExclude=false;
	DWORD	dwPID=0;
	char	chOpt;

	SetConsoleTextAttribute(hConsole, 7);

	// Extract all the options
	while ((chOpt = getopt(argc, argv, _T("o:pmtnxh"))) != EOF) 
	switch(chOpt)
	{
		case _T('p'):
			bProcPerms=true;
			break;
		case _T('m'):
			bModules=true;
			break;
		case _T('t'):
			bThreadsandPerms=true;
			break;
		case _T('o'):
			dwPID = _tstoi(optarg);
			fprintf(stdout,"[!] %d\n", dwPID);
			break;
		case _T('x'):
			bExclude=true;
			break;
		case _T('h'): // Help
			bHelp=true;
			break;
		default:
			fwprintf(stderr,L"[!] No handler - %c\n", chOpt);
			break;
	}

	if(bHelp) PrintHelp(argv[0]);

	// Get out debug privs
	if ( SetDebugPrivilege(GetCurrentProcess())){
		fwprintf(stdout,L"[i] Debug privileges obtained\n");
	} else{
		fwprintf(stderr,L"[!] Failed to obtain debug privileges\n");
		return 1;
	}

	//WindowStationEnumOpen();

	if(dwPID ==0){
		EnumerateProcesses(bModules,bProcPerms,bThreadsandPerms,bExclude);
	} else {
		EnumerateProcessInformation(bModules,bProcPerms,bThreadsandPerms,dwPID,bExclude);
	}

	return 0;
}

