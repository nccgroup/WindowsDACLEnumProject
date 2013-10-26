/*
A Microsoft Windows registry permissions dumper with suspicious DACL alerting

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

https://github.com/nccgroup/WindowsDACLEnumProject

Released under AGPL see LICENSE for more information
*/


#include "stdafx.h"
#include "XGetopt.h"

#define MAGIC (0xa0000000L)

//
// Globals
//
bool	bExclude=false;
bool	bSuperExclude=false;

//
//
//
//
bool UsersWeCareAbout(char *lpDomain, char *lpName)
{
	
	if(strcmp(lpDomain,"NT AUTHORITY") == 0 && strcmp(lpName,"SYSTEM") ==0 ) return false;
	else if(strcmp(lpName,"CREATOR OWNER") == 0) return false;
	else if(strcmp(lpName,"Administrator") == 0) return false;
	else if(strcmp(lpDomain,"NT AUTHORITY") == 0 && strcmp(lpName,"NETWORK SERVICE") ==0 ) return false;
	else if(strcmp(lpDomain,"NT AUTHORITY") == 0 && strcmp(lpName,"LOCAL SERVICE") ==0 ) return false;
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
							// http://www.netid.washington.edu/documentation/domains/sddl.aspx

							if( !LookupAccountSidA( NULL, sSID, lpName, &dwSize, lpDomain, &dwSize, &SNU ) ) {
								
								DWORD dwResult = GetLastError();
								if(dwResult == ERROR_NONE_MAPPED && bExclude == true){
									break;
								} else if( dwResult == ERROR_NONE_MAPPED && bExclude == false){
									fprintf(stdout,"[i]   |\n");
									fprintf(stdout,"[i]   +-+-> Allowed 2 - NONMAPPED - SID %s\n", sidToText(sSID));
								} else if (dwResult != ERROR_NONE_MAPPED){
									fprintf(stderr,"[!] LookupAccountSid Error 	%u\n", GetLastError());
									fprintf(stdout,"[i]   |\n");
									fprintf(stdout,"[i]   +-+-> Allowed - ERROR     - SID %s\n", sidToText(sSID));
									//return;
								} else {
									continue;
								}
							} else {
								if(bSuperExclude && UsersWeCareAbout(lpDomain,lpName) == false) continue;
								fprintf(stdout,"[i]   |\n");
								fprintf(stdout,"[i]   +-+-> Allowed - %s\\%s\n",lpDomain,lpName);
							}
							
							// print out the ACE mask
							fprintf(stdout,"[i]     |\n");
							fprintf(stdout,"[i]     +-> Permissions %08x - ",ACE->Mask);
							
						
							if(ACE->Mask & KEY_ALL_ACCESS) fprintf(stdout,",Key All");
							if(ACE->Mask & GENERIC_ALL) fprintf(stdout,",Generic All");
							
							//if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & KEY_CREATE_LINK)) fprintf(stdout,",Create link - Alert");
							//else if(ACE->Mask & KEY_CREATE_LINK) fprintf(stdout,",Create link");

							if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & KEY_CREATE_SUB_KEY )) fprintf(stdout,",Create sub key - Alert");
							else if(ACE->Mask & KEY_CREATE_SUB_KEY ) fprintf(stdout,",Create sub key");
							
							if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & KEY_SET_VALUE )) fprintf(stdout,",Set value - Alert");
							else if(ACE->Mask & KEY_SET_VALUE) fprintf(stdout,",Set value");

							//if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & KEY_WRITE)) fprintf(stdout,",Read & Set Value & Create Sub Key");
							//else if(ACE->Mask & KEY_WRITE) fprintf(stdout,",Read & Set Value & Create Sub Key");

							if(ACE->Mask & KEY_ENUMERATE_SUB_KEYS ) fprintf(stdout,",Enumerate sub keys");

							if(ACE->Mask & KEY_EXECUTE ) fprintf(stdout,",Read key");
							if(ACE->Mask & KEY_READ ) fprintf(stdout,",Read key and values");
							if(ACE->Mask & KEY_NOTIFY ) fprintf(stdout,",Notify");
							if(ACE->Mask & KEY_QUERY_VALUE ) fprintf(stdout,",Query values");

												
							//if(ACE->Mask & STANDARD_RIGHTS_READ) fprintf(stdout,",Read DACL");
							//if(ACE->Mask & STANDARD_RIGHTS_WRITE) fprintf(stdout,",Write DACL");
								

							if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & WRITE_DAC)) fprintf(stdout,",Change Permissions - Alert");
							else if(ACE->Mask & WRITE_DAC) fprintf(stdout,",Change Permissions");
								
							if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & WRITE_OWNER)) fprintf(stdout,",Change Owner - Alert");
							else if(ACE->Mask & WRITE_OWNER) fprintf(stdout,",Change Owner");

							if(ACE->Mask & READ_CONTROL) fprintf(stdout,",Read Control");
							if(ACE->Mask & DELETE) fprintf(stdout,",Delete");
							
							//if(ACE->Mask & SYNCHRONIZE) fprintf(stdout,",Synchronize"); - not supported

							// http://www.grimes.nildram.co.uk/workshops/secWSNine.htm
							if(ACE->Mask & MAGIC) fprintf(stdout,",Generic Read OR Generic Write");
							
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

bool GetDACLBeforePrint(HKEY hkThis){
	DWORD dwSize =0;
	DWORD dwBytesNeeded =0;
	
	RegGetKeySecurity(hkThis,DACL_SECURITY_INFORMATION,NULL,&dwBytesNeeded);
	dwSize = dwBytesNeeded;
	PSECURITY_DESCRIPTOR* secDesc = (PSECURITY_DESCRIPTOR*)LocalAlloc(LMEM_FIXED,dwBytesNeeded);
	if(RegGetKeySecurity(hkThis,DACL_SECURITY_INFORMATION,secDesc,&dwBytesNeeded) != ERROR_SUCCESS){
		fprintf(stdout,"[i] |\n");
		fprintf(stdout,"[i] +-+-> Failed to query registry key security - %d\n",GetLastError());
		return false;
	}
	
	PACL DACL;
	BOOL bDACLPresent = false;
	BOOL bDACLDefaulted = false;


	bDACLPresent = false;
	bDACLDefaulted = false;
	if(GetSecurityDescriptorDacl(secDesc,&bDACLPresent,&DACL,&bDACLDefaulted) == false){
		fprintf(stdout,"[i] |\n");
		fprintf(stdout,"[i] +-+-> Failed to get security descriptor - %d\n",GetLastError());
		return false;
	}

	PrintPermissions(DACL);

	LocalFree(secDesc);
	return true;
}

//
//
//
//
//
bool ListRegistry(HKEY hKey, char *strSubKey, char *strKeyPath, char *strParent) {
    
	// http://msdn.microsoft.com/en-us/library/windows/desktop/ms724872(v=vs.85).aspx
	//
	HKEY hkThis = NULL;
	DWORD dwIdx = 0;
	char strRegPath[6000];
	TCHAR strName[6000];
	DWORD dwstrNameLen = sizeof(strName);
	DWORD dwType=0;

	if(hKey==NULL) return false;

	DWORD dwRet = RegOpenKey(hKey,strSubKey,&hkThis);
	if(dwRet!= ERROR_SUCCESS){
		fprintf(stderr,"[!] Coudln't open registry key - %s\\%s for %s- %d\n", strParent,strSubKey,strKeyPath,dwRet);
		return false;
	}

	//
	if(strSubKey && strKeyPath){
		//sprintf_s(strRegPath,MAX_PATH,"%s\\%s",strKeyPath,strSubKey);
		strcpy_s(strRegPath,sizeof(strRegPath),strKeyPath);
		strcat_s(strRegPath,sizeof(strRegPath),"\\");
		strcat_s(strRegPath,sizeof(strRegPath),strSubKey);
	} else {
		memset(strRegPath,0x00,sizeof(strRegPath));
	}

	fprintf(stdout,"[Key] %s\\%s \n",strParent,strRegPath);
	GetDACLBeforePrint(hkThis);

	dwRet = 0;
	do{
		dwstrNameLen = sizeof(strName);
		memset(strName,0x00,sizeof(strName));
		dwRet = RegEnumKeyEx(hkThis,dwIdx,strName,&dwstrNameLen,NULL,NULL,NULL,NULL);
		if(dwRet == ERROR_NO_MORE_ITEMS) {
			break;
		} else if(dwRet == ERROR_ACCESS_DENIED)
		{
			break;
		}
		else if (dwRet == ERROR_SUCCESS){
			ListRegistry(hkThis,strName,strRegPath,strParent);
			dwIdx++;
		} else {
			fprintf(stderr,"[!] RegEnumKeyEx error %d\n",dwRet);
		}
	} while(dwRet == ERROR_SUCCESS);

	RegCloseKey(hkThis);
	return true;
}


//
// Function	: PrintHelp
// Role		: 
// Notes	: 
// 
void PrintHelp(char *strExe){

	fprintf (stdout,"    i.e. %s [-s] [-x] [-r <hive>] [-h]\n",strExe);
	fprintf (stdout,"    -h this help\n");
	fprintf (stdout,"    -x exclude non mapped SIDs from alerts\n");
	fprintf (stdout,"    -s exclude SYSTEM and Administrators from all output\n");
	fprintf (stdout,"    -r only dump this hive\n");
	fprintf (stdout,"       1 - HKEY_CLASSES_ROOT\n");
	fprintf (stdout,"       2 - HKEY_USERS\n");
	fprintf (stdout,"       3 - HKEY_LOCAL_MACHINE\n");
	fprintf (stdout,"       4 - HKEY_CURRENT_CONFIG\n");
	fprintf (stdout,"\n");
	ExitProcess(1);
}

//
//
//
//
//
int _tmain(int argc, _TCHAR* argv[])
{
	bool	bHelp=false;
	TCHAR	*strPath=NULL;
	char	chOpt;
	DWORD	intHive=0;

	printf("[*] Windows DACL Enumeration Project - https://github.com/nccgroup/WindowsDACLEnumProject - RegistryPerms\n");
	printf("[*] NCC Group Plc - http://www.nccgroup.com/ \n");
	printf("[*] -h for help \n");

	// Extract all the options
	while ((chOpt = getopt(argc, argv, _T("r:hxs"))) != EOF) 
	switch(chOpt)
	{
		case _T('x'):
			bExclude=true;
			break;
		case _T('s'):
			bSuperExclude=true;
			break;
		case _T('h'): // Help
			bHelp=true;
			break;
		case _T('r'):
			intHive=atoi(optarg);
			break;
		default:
			fwprintf(stderr,L"[!] No handler - %c\n", chOpt);
			break;
	}

	if(bHelp)
	{
		PrintHelp(argv[0]);
		return -1;
	}

	if(intHive > 4){
		fprintf(stderr,"[!] Invalid hive reference\n");
		PrintHelp(argv[0]);
		return -1;
	}

	if(intHive ==0){
		ListRegistry(HKEY_CLASSES_ROOT,NULL,NULL,"HKEY_CLASSES_ROOT");
		ListRegistry(HKEY_USERS,NULL,NULL,"HKEY_USERS");
		ListRegistry(HKEY_LOCAL_MACHINE,NULL,NULL,"HKEY_LOCAL_MACHINE");
		ListRegistry(HKEY_CURRENT_CONFIG,NULL,NULL,"HKEY_CURRENT_CONFIG");
	} 
	else
	{
		switch(intHive){
			case 1:
			ListRegistry(HKEY_CLASSES_ROOT,NULL,NULL,"HKEY_CLASSES_ROOT");
			break;

			case 2:
				ListRegistry(HKEY_USERS,NULL,NULL,"HKEY_USERS");
				break;

			case 3:
				ListRegistry(HKEY_LOCAL_MACHINE,NULL,NULL,"HKEY_LOCAL_MACHINE");
				break;

			case 4:
				ListRegistry(HKEY_CURRENT_CONFIG,NULL,NULL,"HKEY_CURRENT_CONFIG");
				break;

			default:
				fprintf(stderr,"[!] Invalid hive reference\n");
				PrintHelp(argv[0]);
				return -1;
		}
	}
  
	return 0;
}

