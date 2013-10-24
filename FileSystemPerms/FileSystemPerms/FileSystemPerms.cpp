/*
A Microsoft Windows file system permissions dumper with suspicious DACL alerting

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

https://github.com/nccgroup/WindowsDACLEnumProject

Released under AGPL see LICENSE for more information
*/


#include "stdafx.h"
#include "XGetopt.h"

//
// Globals
//
bool	bExclude=false;

//
//
//
//
bool UsersWeCareAbout(char *lpDomain, char *lpName)
{
	
	if(strcmp(lpDomain,"NT AUTHORITY") == 0 && strcmp(lpName,"SYSTEM") ==0 ) return false;
	if(strcmp(lpDomain,"NT AUTHORITY") == 0 && strcmp(lpName,"NETWORK SERVICE") ==0 ) return false;
	if(strcmp(lpDomain,"NT AUTHORITY") == 0 && strcmp(lpName,"LOCAL SERVICE") ==0 ) return false;
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
								if(dwResult == ERROR_NONE_MAPPED && bExclude == true){
									break;
								} else if( dwResult == ERROR_NONE_MAPPED){
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
								if(ACE->Mask & FILE_GENERIC_EXECUTE) fprintf(stdout,",Execute");
								
								if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & FILE_DELETE_CHILD)) fprintf(stdout,",Delete diretory and files - Alert");
								else if(ACE->Mask & FILE_DELETE_CHILD) fprintf(stdout,",Delete diretory and files");

								if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & FILE_ADD_FILE)) fprintf(stdout,",Add File - Alert");
								else if(ACE->Mask & FILE_ADD_FILE) fprintf(stdout,",Add File");
								
								//if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & FILE_WRITE_EA)) fprintf(stdout,",Write Extended Attributes - Alert");
								//else if(ACE->Mask & FILE_WRITE_EA) fprintf(stdout,",Write Extended Attributes");

								if(ACE->Mask & FILE_READ_ATTRIBUTES) fprintf(stdout,",Read Attributes");
								if(ACE->Mask & FILE_LIST_DIRECTORY) fprintf(stdout,",List Directory");
								if(ACE->Mask & FILE_READ_EA) fprintf(stdout,",Read Extended Attributes");
								if(ACE->Mask & FILE_ADD_SUBDIRECTORY) fprintf(stdout,",Add Subdirectory");
								
								if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & FILE_TRAVERSE)) fprintf(stdout,",Traverse Directory - Alert");
								else if (ACE->Mask & FILE_TRAVERSE) fprintf(stdout,",Traverse Directory");

								if(ACE->Mask & STANDARD_RIGHTS_READ) fprintf(stdout,",Read DACL");
								if(ACE->Mask & STANDARD_RIGHTS_WRITE) fprintf(stdout,",Read DACL");
								
								if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & WRITE_DAC)) fprintf(stdout,",Change Permissions - Alert");
								else if(ACE->Mask & WRITE_DAC) fprintf(stdout,",Change Permissions");
								
								if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & WRITE_OWNER)) fprintf(stdout,",Change Owner - Alert");
								else if(ACE->Mask & WRITE_OWNER) fprintf(stdout,",Change Owner");
							} 
							else 
							{

								if(ACE->Mask & FILE_GENERIC_EXECUTE) fprintf(stdout,",Execute");
								if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & FILE_WRITE_ATTRIBUTES)) fprintf(stdout,",Write Attributes - Alert");
								else if(ACE->Mask & FILE_WRITE_ATTRIBUTES) fprintf(stdout,",Write Attributes");

								if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & FILE_WRITE_DATA)) fprintf(stdout,",Write Data - Alert");
								else if(ACE->Mask & FILE_WRITE_DATA) fprintf(stdout,",Write Data");
								
								if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & FILE_WRITE_EA)) fprintf(stdout,",Write Extended Attributes - Alert");
								else if(ACE->Mask & FILE_WRITE_EA) fprintf(stdout,",Write Extended Attributes");

								if(ACE->Mask & FILE_READ_ATTRIBUTES) fprintf(stdout,",Read Attributes");
								if(ACE->Mask & FILE_READ_DATA) fprintf(stdout,",Read Data");
								if(ACE->Mask & FILE_READ_EA) fprintf(stdout,",Read Extended Attributes");
								if(ACE->Mask & FILE_APPEND_DATA) fprintf(stdout,",Append");
								if(ACE->Mask & FILE_EXECUTE) fprintf(stdout,",Execute");

								if(ACE->Mask & STANDARD_RIGHTS_READ) fprintf(stdout,",Read DACL");
								if(ACE->Mask & STANDARD_RIGHTS_WRITE) fprintf(stdout,",Read DACL");
								
								if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & WRITE_DAC)) fprintf(stdout,",Change Permissions - Alert");
								else if(ACE->Mask & WRITE_DAC) fprintf(stdout,",Change Permissions");
								
								if(UsersWeCareAbout(lpDomain,lpName) == true && (ACE->Mask & WRITE_OWNER)) fprintf(stdout,",Change Owner - Alert");
								else if(ACE->Mask & WRITE_OWNER) fprintf(stdout,",Change Owner");

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

bool GetHandleBeforePrint(char* strFile){
	DWORD dwSize =0;
	DWORD dwBytesNeeded =0;
	
	GetFileSecurity (strFile,DACL_SECURITY_INFORMATION,NULL,NULL,&dwBytesNeeded);
	dwSize = dwBytesNeeded;
	PSECURITY_DESCRIPTOR* secDesc = (PSECURITY_DESCRIPTOR*)LocalAlloc(LMEM_FIXED,dwBytesNeeded);
	if(GetFileSecurity (strFile,DACL_SECURITY_INFORMATION,secDesc,dwSize,&dwBytesNeeded) == false){
		fprintf(stdout,"[i] |\n");
		fprintf(stdout,"[i] +-+-> Failed to query service object security - %d\n",GetLastError());
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

	PrintPermissions(DACL,true);

	return true;
}

bool ListFiles(char *strPath) {
    HANDLE hFind = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATA ffdThis;
         
    
	char strThisSpec[MAX_PATH];
	sprintf_s(strThisSpec,MAX_PATH,"%s\\*.*",strPath);

	hFind = FindFirstFile(strThisSpec, &ffdThis);
	if (hFind == INVALID_HANDLE_VALUE)  {
		return false;
	} 

	do {
		if (strcmp(ffdThis.cFileName, ".") != 0 && 
			strcmp(ffdThis.cFileName, "..") != 0) {
            if (ffdThis.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				char strFoo[MAX_PATH];
				sprintf_s(strFoo,MAX_PATH,"%s\\%s",strPath,ffdThis.cFileName);
				fprintf(stdout,"[directory] %s \n",strFoo);
				GetHandleBeforePrint(strFoo);
				ListFiles(strFoo);
            }
			else 
			{
                char strFoo[MAX_PATH];
				sprintf_s(strFoo,MAX_PATH,"%s\\%s",strPath,ffdThis.cFileName);
				fprintf(stdout,"[file] %s \n",strFoo);
				GetHandleBeforePrint(strFoo);
			}
		}
	} while (FindNextFile(hFind, &ffdThis) != 0);

	if (GetLastError() != ERROR_NO_MORE_FILES) {
		FindClose(hFind);
		return false;
	}

	FindClose(hFind);
	hFind = INVALID_HANDLE_VALUE;


    return true;
}


//
// Function	: PrintHelp
// Role		: 
// Notes	: 
// 
void PrintHelp(char *strExe){

	fprintf (stdout,"    i.e. %s [-p] [-x] [-h]\n",strExe);
	fprintf (stdout,"    -p [PATH] Path to use instead of C:\\\n");	
	fprintf (stdout,"    -x exclude non mapped SIDs from alerts\n");
	fprintf (stdout,"\n");
	ExitProcess(1);
}


int EndsWith(const char *str, const char *suffix)
{
    if (!str || !suffix)
        return 0;
    size_t lenstr = strlen(str);
    size_t lensuffix = strlen(suffix);
    if (lensuffix >  lenstr)
        return 0;
    return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

int _tmain(int argc, _TCHAR* argv[])
{

	bool	bHelp=false;
	TCHAR	*strPath=NULL;
	char	chOpt;

	printf("[*] Windows DACL Enumeration Project - https://github.com/nccgroup/WindowsDACLEnumProject - FileSystemPerms\n");
	printf("[*] NCC Group Plc - http://www.nccgroup.com/ \n");

	// Extract all the options
	while ((chOpt = getopt(argc, argv, _T("p:hx"))) != EOF) 
	switch(chOpt)
	{
		case _T('p'):
			strPath=optarg;
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

	if(strPath) {

		while(EndsWith(strPath," ") == true){
			char *strPtr = strrchr(strPath,' ');
			*strPtr = 0x00;
		}

		if(EndsWith(strPath,"\"") == true){
			char *strPtr = strrchr(strPath,'\"');
			*strPtr = 0x00;
		} 
		fprintf(stdout,"[i] Path now %s \n", strPath);
		ListFiles(strPath);
	}
	else ListFiles("C:\\");
        
    

	return 0;
}

