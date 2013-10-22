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
void PrintPermissions(PACL DACL)
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
									fprintf(stdout,"[i]    |\n");
									fprintf(stdout,"[i]    +-+-> Allowed - NONMAPPED - SID %s\n", sidToText(sSID));
								} else if (dwResult != ERROR_NONE_MAPPED){
									fprintf(stderr,"[!] LookupAccountSid Error 	%u\n", GetLastError());
									fprintf(stdout,"[i]    |\n");
									fprintf(stdout,"[i]    +-+-> Allowed - ERROR     - SID %s\n", sidToText(sSID));
									//return;
								} else {
									continue;
								}
							} else {
								
								fprintf(stdout,"[i]    |\n");
								fprintf(stdout,"[i]    +-+-> Allowed - %s\\%s\n",lpDomain,lpName);
							}
							
							// print out the ACE mask
							fprintf(stdout,"[i]      |\n");
							fprintf(stdout,"[i]      +-> Permissions - ");
							
						
							if(ACE->Mask & SERVICE_ALL_ACCESS) fprintf(stdout,",All");
							if(ACE->Mask & SERVICE_CHANGE_CONFIG ) fprintf(stdout,",Change Config");
							if(ACE->Mask & SERVICE_ENUMERATE_DEPENDENTS) fprintf(stdout,",Enumerate Dependents");
							if(ACE->Mask & SERVICE_INTERROGATE) fprintf(stdout,",Interrogate");
							if(ACE->Mask & SERVICE_PAUSE_CONTINUE) fprintf(stdout,",Pause / Config");
							if(ACE->Mask & SERVICE_QUERY_CONFIG) fprintf(stdout,",Query Config");
							if(ACE->Mask & SERVICE_QUERY_STATUS) fprintf(stdout,",Query Status");
							if(ACE->Mask & SERVICE_START) fprintf(stdout,",Start");
							if(ACE->Mask & SERVICE_STOP) fprintf(stdout,",Stop");
							if(ACE->Mask & SERVICE_USER_DEFINED_CONTROL) fprintf(stdout,",User Defined Control");
							if(ACE->Mask & DELETE) fprintf(stdout,"Delete");
							if(ACE->Mask & READ_CONTROL) fprintf(stdout,",Read Security");
							if(ACE->Mask & WRITE_OWNER) fprintf(stdout,",Change Owner");
							if(ACE->Mask & WRITE_DAC) fprintf(stdout,",Change Permissions");
							if(ACE->Mask & GENERIC_READ) fprintf(stdout,",Generic Read");
							if(ACE->Mask & GENERIC_WRITE ) fprintf(stdout,",Generic Write");
							if(ACE->Mask & GENERIC_EXECUTE) fprintf(stdout,",Generic Execute");
									
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

	fprintf(stdout,"[i] +> Service [%s (%s) - PID %d] - ",sService.lpServiceName,sService.lpDisplayName,sService.ServiceStatusProcess.dwProcessId);

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

	PACL DACL;
	BOOL bDACLPresent = false;
	BOOL bDACLDefaulted = false;
	if(GetSecurityDescriptorDacl(secDesc,&bDACLPresent,&DACL,&bDACLDefaulted) == false){
		fprintf(stdout,"[i] |\n");
		fprintf(stdout,"[i] +-+-> Failed to get security descriptor - %d\n",GetLastError());
		return false;
	}

	fprintf(stdout,"[i] |\n");
	fprintf(stdout,"[i] +-+-> Service permissions\n");
	PrintPermissions(DACL);
	LocalFree(secDesc);


	//fprintf(stdout,"[i] |\n");
	//fprintf(stdout,"[i] +-+-> Binary path name - %s\n",qsConfig->);

	


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

