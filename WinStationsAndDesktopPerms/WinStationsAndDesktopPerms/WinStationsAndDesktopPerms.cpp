/*
A Microsoft Windows winstation and desltop permissions dumper with suspicious DACL alerting

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

https://github.com/nccgroup/WindowsDACLEnumProject

Released under AGPL see LICENSE for more information
*/


#include "stdafx.h"

//
// Function	: SetDebugPrivilege
// Role		: Gets privs for our process
// Notes	: 
//
BOOL SetPrivilege(HANDLE hProcess, LPCTSTR lPriv)
{
	LUID luid ;
	TOKEN_PRIVILEGES privs ;
	HANDLE hToken = NULL ;
	DWORD dwBufLen = 0 ;
	char buf[1024] ;
	
	ZeroMemory( &luid,sizeof(luid) ) ;
	
	if(!LookupPrivilegeValue( NULL, lPriv, &luid )) return false;
	
	privs.PrivilegeCount = 1 ;
	privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED ;
	memcpy( &privs.Privileges[0].Luid, &luid, sizeof(privs.Privileges[0].Luid )) ;
	
	
	if(!OpenProcessToken( hProcess, TOKEN_ALL_ACCESS,&hToken))
		return false ;
	
	if(!AdjustTokenPrivileges( hToken, FALSE, &privs,
		sizeof(buf),(PTOKEN_PRIVILEGES)buf, &dwBufLen ) )
		return false ;

	CloseHandle(hProcess);
	CloseHandle(hToken);
	
	return true ;
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
void PrintPermissions( HANDLE hObject, bool bDesktop)
{

	DWORD					dwRet=0;
	DWORD					dwCount=0;
	PACL					DACL;
	PSECURITY_DESCRIPTOR	PSD;
	ACCESS_ALLOWED_ACE		*ACE;
	
	// http://msdn2.microsoft.com/en-us/library/aa446654.aspx
	dwRet = GetSecurityInfo(hObject, 
							SE_WINDOW_OBJECT, 
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
								
								if(!bDesktop){
						
									if(ACE->Mask & WINSTA_ALL_ACCESS == WINSTA_ALL_ACCESS) fprintf(stdout,",All");
									if(ACE->Mask & WINSTA_ACCESSCLIPBOARD ) fprintf(stdout,",Clipboard");
									if(ACE->Mask & WINSTA_ACCESSGLOBALATOMS ) fprintf(stdout,",Global Atoms");
									if(ACE->Mask & WINSTA_CREATEDESKTOP ) fprintf(stdout,",Create Desktop");
									if(ACE->Mask & WINSTA_ENUMDESKTOPS  ) fprintf(stdout,",Enum Desktop");
									if(ACE->Mask & WINSTA_ENUMERATE) fprintf(stdout,",Enumerate");
									if(ACE->Mask & WINSTA_EXITWINDOWS ) fprintf(stdout,",Exit Windows");
									if(ACE->Mask & WINSTA_READATTRIBUTES ) fprintf(stdout,",Read Attributes");
									if(ACE->Mask & WINSTA_READSCREEN ) fprintf(stdout,",Read Screen");
									if(ACE->Mask & WINSTA_WRITEATTRIBUTES ) fprintf(stdout,",Write Attributes");
									if(ACE->Mask & SYNCHRONIZE  ) fprintf(stdout,",Synchronize");
									if(ACE->Mask & DELETE) fprintf(stdout,",Delete");
									if(ACE->Mask & READ_CONTROL) fprintf(stdout,",Read Security");
									if(ACE->Mask & WRITE_OWNER) fprintf(stdout,",Change Owner");
									if(ACE->Mask & WRITE_DAC) fprintf(stdout,",Change Permissions");
									if(ACE->Mask & GENERIC_READ) fprintf(stdout,",Generic Read");
									if(ACE->Mask & GENERIC_WRITE ) fprintf(stdout,",Generic Write");
									if(ACE->Mask & GENERIC_EXECUTE) fprintf(stdout,",Generic Execute");
									if(ACE->Mask & GENERIC_ALL ) fprintf(stdout,",All");

								} else {
									if(ACE->Mask & DELETE ) fprintf(stdout,",Desktop Delete");
									if(ACE->Mask & READ_CONTROL ) fprintf(stdout,",Read Security Descriptor");
									if(ACE->Mask & DESKTOP_CREATEMENU ) fprintf(stdout,",Create Menu");
									if(ACE->Mask & DESKTOP_CREATEWINDOW ) fprintf(stdout,",Create Window");
									if(ACE->Mask & DESKTOP_ENUMERATE  ) fprintf(stdout,",Enumerate");
									if(ACE->Mask & DESKTOP_HOOKCONTROL) fprintf(stdout,",Hook Windows");
									if(ACE->Mask & DESKTOP_JOURNALPLAYBACK ) fprintf(stdout,",Journal Playpack");
									if(ACE->Mask & DESKTOP_JOURNALRECORD  ) fprintf(stdout,",Journal Record");
									if(ACE->Mask & DESKTOP_READOBJECTS) fprintf(stdout,",Read Objects");
									if(ACE->Mask & DESKTOP_SWITCHDESKTOP ) fprintf(stdout,",Switch Desktop");
									if(ACE->Mask & DESKTOP_WRITEOBJECTS) fprintf(stdout,",Write Objects");
									if(ACE->Mask & GENERIC_READ) fprintf(stdout,",Generic Read");
									if(ACE->Mask & GENERIC_WRITE ) fprintf(stdout,",Generic Write");
									if(ACE->Mask & GENERIC_EXECUTE) fprintf(stdout,",Generic Execute");
									if(ACE->Mask & GENERIC_ALL ) fprintf(stdout,",All");

								}
								fprintf(stdout,"\n");
								break;

							// Denied ACE
							case ACCESS_DENIED_ACE_TYPE:
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
//
//
BOOL CALLBACK EnumDesktopProc(LPTSTR lpszDesktop, LPARAM lParam)
{
	fprintf(stdout,"[i] |\n");
	fprintf(stdout,"[i] +-+-> Desktop [%s]\n",lpszDesktop);

	HDESK hDesk = OpenDesktop(lpszDesktop, NULL, false, READ_CONTROL);

	if(hDesk != NULL){
		PrintPermissions(hDesk,true);
	} else {
		fprintf(stderr,"[!] Couldn't open desktop - %s - %d\n",lpszDesktop, GetLastError());
	}

	return true;
}


//
//
//
BOOL CALLBACK EnumWindowStationProc(LPTSTR lpszWindowStation, LPARAM lParam)
{

	fprintf(stdout,"[i] +> WindowStation [%s]\n",lpszWindowStation);
	HWINSTA hWinStat = OpenWindowStation(lpszWindowStation,FALSE,READ_CONTROL); // |WINSTA_ALL_ACCESS|GENERIC_ALL
	   
	if(hWinStat != NULL){
		PrintPermissions(hWinStat,false);
		
	}

	CloseHandle(hWinStat);

	hWinStat = OpenWindowStation(lpszWindowStation,FALSE,WINSTA_ENUMDESKTOPS); // Change #2: Only ask for WINSTA_ENUMDESKTOPS - this didn't actually get me more info in practice, but didn't get any less either.
    
	if(hWinStat != NULL){
        SetProcessWindowStation(hWinStat);
        if(EnumDesktops(hWinStat,&EnumDesktopProc,NULL)== NULL){
			fprintf(stderr,"[!} Couldn't enumerate desktops - %s - %d\n",lpszWindowStation,GetLastError());
		}
	}

	return true;
}

//
//
//
int _tmain(int argc, _TCHAR* argv[])
{

	PWTS_SESSION_INFO pSessionInfo;
	DWORD dwSessionInfo=0;
	WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE,0,1,&pSessionInfo,&dwSessionInfo);
	
	printf("[*] Windows DACL Enumeration Project - https://github.com/nccgroup/WindowsDACLEnumProject - WinStationsAndDesktopsPerms\n");
	printf("[*] NCC Group Plc - http://www.nccgroup.com/ \n");
	printf("[*] -h for help \n");

	SetPrivilege(GetCurrentProcess(),SE_DEBUG_NAME);
	
	DWORD dwSessID = 0;
	ProcessIdToSessionId(GetCurrentProcessId(),&dwSessID);
	fprintf(stdout,"[i] Running in session %d\n",dwSessID);

	EnumWindowStations(&EnumWindowStationProc,NULL);

	
	return 0;
}

