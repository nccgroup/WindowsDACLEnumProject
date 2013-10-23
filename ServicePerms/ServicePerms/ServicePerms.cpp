/*
A Microsoft Windows service permissions dumper with suspicious DACL alerting

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

https://github.com/nccgroup/WindowsDACLEnumProject

Released under AGPL see LICENSE for more information
*/


#include "stdafx.h"
#include "XGetopt.h"

//
// http://msdn.microsoft.com/en-us/library/windows/desktop/dn369256(v=vs.85).aspx
//
typedef struct _SERVICE_LAUNCH_PROTECTED_INFO {
	DWORD  dwLaunchProtected;
	} SERVICE_LAUNCH_PROTECTED_INFO, *PSERVICE_LAUNCH_PROTECTED_INFO;

//
// http://msdn.microsoft.com/en-us/library/windows/desktop/ms684935(v=vs.85).aspx
//
#define SERVICE_CONFIG_LAUNCH_PROTECTED 12 

//
//
//
//
bool UsersWeCareAbout(char *lpDomain, char *lpName)
{
	
	if(strcmp(lpDomain,"NT AUTHORITY") == 0 && strcmp(lpName,"SYSTEM") ==0 ) return false;
	else if(strcmp(lpDomain,"BUILTIN") == 0 && strcmp(lpName,"Users") ==0) return true;
	else if(strcmp(lpDomain,"BUILTIN") == 0) return false;
	else if(strcmp(lpDomain,"NT SERVICE") == 0) return false;
	else if(strcmp(lpDomain,"NT AUTHORITY") == 0 && strcmp(lpName,"SERVICE") == 0) return false;
	else if(strcmp(lpDomain,"NT AUTHORITY") == 0 && strcmp(lpName,"INTERACTIVE") == 0) return false;
	else {
		//fprintf(stdout,"- %s we care",lpName);
		return true;
	}
}

//
//
//
//
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
						return true;
					}else {
						WTSFreeMemory(ppProcessInfo);
						strcpy_s(strUser,strLen,"ERROR");
						return 0;
					}
				} else {
					WTSFreeMemory(ppProcessInfo);
					strcpy_s(strUser,strLen,lpName);
					return true;
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
//
//
void PrintPermissions(PACL DACL, bool bFile)
{

	DWORD					dwRet=0;
	DWORD					dwCount=0;
	ACCESS_ALLOWED_ACE		*ACE;
	
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
								if( dwResult == ERROR_NONE_MAPPED){
									fprintf(stdout,"[i]   |\n");
									fprintf(stdout,"[i]   +-+-> Allowed - NONMAPPED - SID %s\n", sidToText(sSID));
								} else if (dwResult != ERROR_NONE_MAPPED){
									fprintf(stderr,"[!] LookupAccountSid Error 	%u\n", GetLastError());
									fprintf(stdout,"[i]   |\n");
									fprintf(stdout,"[i]   +-+-> Allowed - ERROR     - SID %s\n", sidToText(sSID));
									//return;
								} else {
									continue;
								}
							} else {
								
								fprintf(stdout,"[i]   |\n");
								fprintf(stdout,"[i]   +-+-> Allowed - %s\\%s\n",lpDomain,lpName);
							}
							
							// print out the ACE mask
							fprintf(stdout,"[i]     |\n");
							fprintf(stdout,"[i]     +-> Permissions - ");
							
						
							if(bFile == false){
								if(ACE->Mask & SERVICE_ALL_ACCESS) fprintf(stdout,",All");
							
								if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & SERVICE_CHANGE_CONFIG)) fprintf(stdout,",Change Config - Alert");
								else if(ACE->Mask & SERVICE_CHANGE_CONFIG ) fprintf(stdout,",Change Config");

								if(ACE->Mask & SERVICE_ENUMERATE_DEPENDENTS) fprintf(stdout,",Enumerate Dependents");
								if(ACE->Mask & SERVICE_INTERROGATE) fprintf(stdout,",Interrogate");
								if(ACE->Mask & SERVICE_PAUSE_CONTINUE) fprintf(stdout,",Pause / Config");
								if(ACE->Mask & SERVICE_QUERY_CONFIG) fprintf(stdout,",Query Config");
								if(ACE->Mask & SERVICE_QUERY_STATUS) fprintf(stdout,",Query Status");
								if(ACE->Mask & SERVICE_START) fprintf(stdout,",Start");
								if(ACE->Mask & SERVICE_STOP) fprintf(stdout,",Stop");
							
								if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & SERVICE_USER_DEFINED_CONTROL)) fprintf(stdout,",User Defined Control - Alert");
								else if(ACE->Mask & SERVICE_USER_DEFINED_CONTROL) fprintf(stdout,",User Defined Control");
							
								if(ACE->Mask & DELETE) fprintf(stdout,"Delete");
								if(ACE->Mask & READ_CONTROL) fprintf(stdout,",Read Security");
								if(ACE->Mask & WRITE_OWNER) fprintf(stdout,",Change Owner");
							
								if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & WRITE_DAC)) fprintf(stdout,",Change Permissions - Alert");
								else if(ACE->Mask & WRITE_DAC) fprintf(stdout,",Change Permissions");
							
								if(ACE->Mask & GENERIC_READ) fprintf(stdout,",Generic Read");
								if(ACE->Mask & GENERIC_WRITE ) fprintf(stdout,",Generic Write");
								if(ACE->Mask & GENERIC_EXECUTE) fprintf(stdout,",Generic Execute");
								if(ACE->Mask & ACCESS_SYSTEM_SECURITY) fprintf(stdout,",Read/Write SACL");
							} 
							else 
							{

								if(ACE->Mask & FILE_GENERIC_EXECUTE) fprintf(stdout,",Execute");
								//if(ACE->Mask & STANDARD_RIGHTS_READ) fprintf(stdout,",Write");
								if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & FILE_WRITE_ATTRIBUTES)) fprintf(stdout,",Write Attributes - Alert");
								else if(ACE->Mask & FILE_WRITE_ATTRIBUTES) fprintf(stdout,",Write Attributes");

								if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & FILE_WRITE_DATA)) fprintf(stdout,",Write Data- Alert");
								else if(ACE->Mask & FILE_WRITE_DATA) fprintf(stdout,",Write Data");
								
								if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & FILE_WRITE_EA)) fprintf(stdout,",Write Extended Attributes- Alert");
								else if(ACE->Mask & FILE_WRITE_EA) fprintf(stdout,",Write Extended Attributes");

								//if(ACE->Mask & FILE_GENERIC_READ) fprintf(stdout,",Read");
								if(ACE->Mask & FILE_READ_ATTRIBUTES) fprintf(stdout,",Read Attributes");
								if(ACE->Mask & FILE_READ_DATA) fprintf(stdout,",Read Data");
								if(ACE->Mask & FILE_READ_EA) fprintf(stdout,",Read Extended Attributes");
								if(ACE->Mask & FILE_APPEND_DATA) fprintf(stdout,",Append");
								if(ACE->Mask & FILE_EXECUTE) fprintf(stdout,",Execute");
								//if(ACE->Mask & FILE_ALL_ACCESS) fprintf(stdout,",All");
								if(ACE->Mask & STANDARD_RIGHTS_READ) fprintf(stdout,",Read DACL");
								if(ACE->Mask & STANDARD_RIGHTS_WRITE) fprintf(stdout,",Read DACL");
								
								if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & WRITE_DAC)) fprintf(stdout,",Change Permissions - Alert");
								else if(ACE->Mask & WRITE_DAC) fprintf(stdout,",Change Permissions");
								
								if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & WRITE_OWNER)) fprintf(stdout,",Change Owner - Alert");
								else if(ACE->Mask & WRITE_OWNER) fprintf(stdout,",Change Owner");

							}

							break;
						// Denied ACE
						case ACCESS_DENIED_ACE_TYPE:
							break;
						// Uh oh
						default:
							break;
					}

					fprintf(stdout,"\n");
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

//
//
//
//
BOOL printService(ENUM_SERVICE_STATUS_PROCESS sService, SC_HANDLE scMgr){
	
	SC_HANDLE scService = NULL;
	QUERY_SERVICE_CONFIG *qsConfig;
	DWORD dwBytesNeeded = 0;

	char strUserFromPID[1024];
	char strSession[1024];
	DWORD dwSessionID = 0;
	if(sService.ServiceStatusProcess.dwProcessId != 0){
		memset(strUserFromPID,0x00,1024);
		UserForPIDToString(sService.ServiceStatusProcess.dwProcessId,strUserFromPID,1024);
		ProcessIdToSessionId(sService.ServiceStatusProcess.dwProcessId,&dwSessionID);
		sprintf_s(strSession," in session %d",dwSessionID);
	} else {
		strcpy_s(strUserFromPID,1024,"N/A");
	}

	fprintf(stdout,"[i] +> Service [%s (%s) - PID %d as %s ] - ",sService.lpServiceName,sService.lpDisplayName,sService.ServiceStatusProcess.dwProcessId,strUserFromPID,dwSessionID,strSession);

	switch(sService.ServiceStatusProcess.dwCurrentState){
		case SERVICE_CONTINUE_PENDING:
			fprintf(stdout,"Contine Pending\n");
			break;
		case SERVICE_PAUSE_PENDING:
			fprintf(stdout,"Pause Pending\n");
			break;
		case SERVICE_PAUSED:
			fprintf(stdout,"Paused\n");
			break;
		case SERVICE_RUNNING:
			fprintf(stdout,"Running\n");
			break;
		case SERVICE_START_PENDING:
			fprintf(stdout,"Start Pending\n");
			break;
		case SERVICE_STOP_PENDING:
			fprintf(stdout,"Stop Pending\n");
			break;
		case SERVICE_STOPPED:
			fprintf(stdout,"Stopped\n");
			break;
		default:
			fprintf(stdout,"Unknown\n");
			break;
	}


	switch(sService.ServiceStatusProcess.dwServiceType){
			case SERVICE_INTERACTIVE_PROCESS:
				// Alert
				fprintf(stdout,"[i] |\n");
				fprintf(stdout,"[i] +-+-> Process can interact with desktop\n");
			default:
				break;

	}

	if(sService.ServiceStatusProcess.dwServiceFlags ==SERVICE_RUNS_IN_SYSTEM_PROCESS){
		// Alert
		fprintf(stdout,"[i] |\n");
		fprintf(stdout,"[i] +-+-> Process runs in system process\n");
	}

	scService = OpenService(scMgr,sService.lpServiceName,SERVICE_QUERY_CONFIG);
	if(scService == NULL){
		fprintf(stdout,"[i] |\n");
		fprintf(stdout,"[i] +-+-> Failed to open service - %d\n",GetLastError());
		return false;
	}

	SERVICE_LAUNCH_PROTECTED_INFO scLaunchProtectedNfo;
	DWORD dwNeeded = 0;
	if(QueryServiceConfig2(scService,SERVICE_CONFIG_LAUNCH_PROTECTED,(LPBYTE)&scLaunchProtectedNfo,sizeof(scLaunchProtectedNfo),&dwNeeded) == false) {
		fprintf(stdout,"[i] |\n");
		fprintf(stdout,"[i] +-+-> Failed to query launch protection level (only supported by Windows 8.1 and 2012 R2) - %d\n",GetLastError());
	}

	QueryServiceConfig(scService,NULL,sizeof(qsConfig),&dwBytesNeeded );
	DWORD dwSize = dwBytesNeeded;
	qsConfig= (QUERY_SERVICE_CONFIG*)LocalAlloc(LMEM_FIXED,dwBytesNeeded);

	if(QueryServiceConfig(scService,qsConfig,dwSize,&dwBytesNeeded ) == false){
		fprintf(stdout,"[i] |\n");
		fprintf(stdout,"[i] +-+-> Failed to query service configuration - %d\n",GetLastError());
		return false;
	}

	fprintf(stdout,"[i] |\n");
	fprintf(stdout,"[i] +-+-> Binary path name - %s\n",qsConfig->lpBinaryPathName);
	
	char strFilename[MAX_PATH];
	memset(strFilename,0x00,MAX_PATH);
	if(qsConfig->lpBinaryPathName[0] == '"')
	{
		char strTemp[MAX_PATH];
		memset(strTemp,0x00,MAX_PATH);
		memcpy_s(strTemp,MAX_PATH,&qsConfig->lpBinaryPathName[1],(strlen(qsConfig->lpBinaryPathName) - strlen("\"\"")));
		sprintf_s(strFilename,MAX_PATH,"%s",strTemp);
	} 
	else if(_strnicmp(qsConfig->lpBinaryPathName,"system32",strlen("system32")) == 0 )
	{
		sprintf_s(strFilename,MAX_PATH,"C:\\Windows\\%s",qsConfig->lpBinaryPathName);
	}
	else if(_strnicmp(qsConfig->lpBinaryPathName,"\\SystemRoot\\",strlen("\\SystemRoot\\")) == 0 )
	{
		char strTemp[MAX_PATH];
		memcpy_s(strTemp,MAX_PATH,&qsConfig->lpBinaryPathName[12],(strlen(qsConfig->lpBinaryPathName) - strlen("\\SystemRoot\\") + 1));
		sprintf_s(strFilename,MAX_PATH,"C:\\Windows\\%s",strTemp);
	} 
	else if (strstr(qsConfig->lpBinaryPathName," ") == 0) 
	{
		strcpy_s(strFilename,MAX_PATH,qsConfig->lpBinaryPathName);
	} 
	else 
	{
		_snprintf(strFilename,strstr(qsConfig->lpBinaryPathName," ")-qsConfig->lpBinaryPathName,"%s",qsConfig->lpBinaryPathName);
	}

	fprintf(stdout,"[i] %s\n", strFilename);
	
	PSECURITY_DESCRIPTOR sdFile;
	DWORD dwLen = 0;
	
	GetFileSecurity(strFilename, OWNER_SECURITY_INFORMATION  | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,NULL,NULL,&dwLen);
	sdFile = (PSECURITY_DESCRIPTOR) LocalAlloc(LMEM_FIXED,dwLen);
	PACL DACL;
	BOOL bDACLPresent = false;
	BOOL bDACLDefaulted = false;

	GetFileSecurity(strFilename, OWNER_SECURITY_INFORMATION  | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,sdFile,dwLen,&dwLen);
	if(GetSecurityDescriptorDacl(sdFile,&bDACLPresent,&DACL,&bDACLDefaulted) == false){
		fprintf(stdout,"[i] |\n");
		fprintf(stdout,"[i] +-+-> Failed to get file security descriptor - %d\n",GetLastError());
		//return false;
	} else {
		PrintPermissions(DACL,true);
		LocalFree(sdFile);
	}
	LocalFree(qsConfig);

	SC_HANDLE scSecService = OpenService(scMgr,sService.lpServiceName,SERVICE_ALL_ACCESS);
	if(scSecService == NULL){
		fprintf(stdout,"[i] |\n");
		fprintf(stdout,"[i] +-+-> Failed to open service for security interogation - %d\n",GetLastError());
		return false;
	}

	
	QueryServiceObjectSecurity(scSecService,DACL_SECURITY_INFORMATION,NULL,0,&dwBytesNeeded);
	dwSize = dwBytesNeeded;
	PSECURITY_DESCRIPTOR* secDesc = (PSECURITY_DESCRIPTOR*)LocalAlloc(LMEM_FIXED,dwBytesNeeded);

	if(QueryServiceObjectSecurity(scSecService,DACL_SECURITY_INFORMATION,secDesc,dwSize,&dwBytesNeeded) == false){
		fprintf(stdout,"[i] |\n");
		fprintf(stdout,"[i] +-+-> Failed to query service object security - %d\n",GetLastError());
		return false;
	}

	bDACLPresent = false;
	bDACLDefaulted = false;
	if(GetSecurityDescriptorDacl(secDesc,&bDACLPresent,&DACL,&bDACLDefaulted) == false){
		fprintf(stdout,"[i] |\n");
		fprintf(stdout,"[i] +-+-> Failed to get security descriptor - %d\n",GetLastError());
		return false;
	}

	fprintf(stdout,"[i] |\n");
	fprintf(stdout,"[i] +-+-> Service permissions\n");
	PrintPermissions(DACL,false);
	LocalFree(secDesc);


	return true;
}


BOOL enumService(DWORD dwType, SC_HANDLE scMgr)
{

		DWORD dwNeeded = NULL;
		DWORD dwRetNumber = 0;
		DWORD dwResume = 0;
		DWORD dwRet =0;
		DWORD dwSize = 0;
		LPENUM_SERVICE_STATUS_PROCESS hBuffer = NULL;

		for(;;){

			if(EnumServicesStatusEx(scMgr,SC_ENUM_PROCESS_INFO,dwType,SERVICE_STATE_ALL,NULL,NULL,&dwNeeded,&dwRetNumber,&dwResume, NULL)){
				return false; // we don't expect this to work
			} else {
				if(GetLastError() == ERROR_INSUFFICIENT_BUFFER || ERROR_MORE_DATA){
					
					EnumServicesStatusEx(scMgr,SC_ENUM_PROCESS_INFO ,dwType,SERVICE_STATE_ALL,NULL,NULL,&dwNeeded,&dwRetNumber,&dwResume, NULL);

					hBuffer = (LPENUM_SERVICE_STATUS_PROCESS)LocalAlloc(LMEM_FIXED,dwNeeded);
					if(hBuffer==NULL){
						fprintf(stderr,"[!] - Error allocating memory\n");
						return false;
					}

					dwSize = dwNeeded;

					if(EnumServicesStatusEx(scMgr,SC_ENUM_PROCESS_INFO ,dwType,SERVICE_STATE_ALL,(LPBYTE)hBuffer,dwSize,&dwNeeded,&dwRetNumber,&dwResume,NULL)){
						for(DWORD dwCount =0;dwCount<dwRetNumber;dwCount++){
							printService(hBuffer[dwCount],scMgr);
						}

						if(GetLastError() != ERROR_MORE_DATA || dwResume == 0){
							LocalFree(hBuffer);
							return true;
						}
					} else {
						fprintf(stderr,"[!] Fatal error during EnumServicesStatus - %d\n", GetLastError());
						LocalFree(hBuffer);
						return false;
					}

					LocalFree(hBuffer);
				} else {
					return true;
				}
			}
		}

		return true;
}

int _tmain(int argc, _TCHAR* argv[])
{

	printf("[*] Windows DACL Enumeration Project - https://github.com/nccgroup/WindowsDACLEnumProject - ServicePerms\n");
	printf("[*] NCC Group Plc - http://www.nccgroup.com/ \n");

	SC_HANDLE scMgr = OpenSCManager(NULL,NULL, GENERIC_READ);
	
	if(scMgr == NULL && GetLastError() == ERROR_ACCESS_DENIED){
		fprintf(stderr,"[!] Couldn't open service control manager - access denied\n"); 
	}

	fprintf(stdout,"[i] File System Drivers\n");
	enumService(SERVICE_FILE_SYSTEM_DRIVER,scMgr);
	fprintf(stdout,"[i] Kernel Drivers\n");
	enumService(SERVICE_KERNEL_DRIVER,scMgr);
	fprintf(stdout,"[i] Userland Own Processes\n");
	enumService(SERVICE_WIN32_OWN_PROCESS,scMgr);
	fprintf(stdout,"[i] Userland Shared Processes\n");
	enumService(SERVICE_WIN32_SHARE_PROCESS,scMgr);
	
	return 0;
}

