/*
A Microsoft Windows process and thread batch permissions dumper with suspicious DACL alerting

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

https://github.com/nccgroup/WindowsDACLEnumProject

Released under AGPL see LICENSE for more information
*/

#include "stdafx.h"


//
// Function	: sidToText
// Role		: Converts a binary SID to a nice one
// Notes	: http://win32.mvps.org/security/dumpacl/dumpacl.cpp
//
const char *sidToTextTok( PSID psid )
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
//
void PrintPermissionsTok( PACL DACL)
{
	DWORD dwCount=0;
	ACCESS_ALLOWED_ACE		*ACE;

	// http://msdn2.microsoft.com/en-us/library/aa379142.aspx
	if(IsValidAcl(DACL) == TRUE){
		fprintf(stdout,"[i]    |\n");
		fprintf(stdout,"[i]    +-+-> Default DACL for new objects created by this user\n");

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
								if( dwResult == ERROR_NONE_MAPPED ){
									fprintf(stdout,"[i]    |\n");
									fprintf(stdout,"[i]    +---+-> Allowed - NONMAPPED - SID %s\n", sidToTextTok(sSID));
								} else if (dwResult != ERROR_NONE_MAPPED){
									fprintf(stderr,"[!] LookupAccountSid Error 	%u\n", GetLastError());
									fprintf(stdout,"[i]    |\n");
									fprintf(stdout,"[i]    +---+-> Allowed - ERROR     - SID %s\n", sidToTextTok(sSID));
									//return;
								} else {
									continue;
								}
							} else {
								
								fprintf(stdout,"[i]    |\n");
								fprintf(stdout,"[i]    +---+-> Allowed - %s\\%s\n",lpDomain,lpName);

								char strUserFromPID[1024];
								memset(strUserFromPID,0x00,1024);
								if(!strcmp(lpDomain,"BUILTIN")==0 && !strcmp(lpName,"OWNER RIGHTS")==0 && !strcmp(lpDomain,"NT AUTHORITY")==0 && !strcmp(lpDomain,"NT SERVICE")==0) {
									fprintf(stdout,"[i]      |\n");
									fprintf(stdout,"[i]      +-+-+-> Alert!\n");
								}
							}
								
							// print out the ACE mask
							fprintf(stdout,"[i]        |\n");
							fprintf(stdout,"[i]        +-> Permissions - ");
							
							if(ACE->Mask & GENERIC_ALL) fprintf(stdout,",All");
							if(ACE->Mask & GENERIC_EXECUTE) fprintf(stdout,",Execute");
							if(ACE->Mask & GENERIC_READ) fprintf(stdout,",Read");
							if(ACE->Mask & GENERIC_WRITE) fprintf(stdout,",Write");
							if(ACE->Mask & DELETE) fprintf(stdout,",Delete");
							if(ACE->Mask & READ_CONTROL) fprintf(stdout,",Read control");
							if(ACE->Mask & SYNCHRONIZE) fprintf(stdout,",Sync");
							if(ACE->Mask & WRITE_DAC) fprintf(stdout,",Modify DACL");
							if(ACE->Mask & WRITE_OWNER) fprintf(stdout,",Write Owner");
							if(ACE->Mask & STANDARD_RIGHTS_ALL) fprintf(stdout,",All");
							if(ACE->Mask & STANDARD_RIGHTS_EXECUTE) fprintf(stdout,",Execute");
							if(ACE->Mask & STANDARD_RIGHTS_READ) fprintf(stdout,",Read Control");
							if(ACE->Mask & STANDARD_RIGHTS_REQUIRED)  fprintf(stdout,",Write");
							if(ACE->Mask & STANDARD_RIGHTS_WRITE) fprintf(stdout,",Read Control");


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

//
//
//
//
//
BOOL TokenProcess(HANDLE hToken){
	DWORD dwRet = 0;

	TOKEN_USER *tokUser;
	TOKEN_GROUPS *tokGroups;
	TOKEN_PRIVILEGES *tokPrivs;
	TOKEN_OWNER *tokOwner;
	TOKEN_PRIMARY_GROUP *tokPrimGroup;
	TOKEN_DEFAULT_DACL *tokDACL;
	TOKEN_SOURCE tokSource;
	TOKEN_TYPE tokType;
	SECURITY_IMPERSONATION_LEVEL *tokImpersonationLvl;
	TOKEN_STATISTICS *tokStats;
	DWORD tokSessionID;
	TOKEN_GROUPS_AND_PRIVILEGES *tokGrpPrivs;
	DWORD dwSandboxInert;
	TOKEN_ORIGIN *tokOrigin;
	TOKEN_ELEVATION_TYPE tokElevType;
	TOKEN_LINKED_TOKEN *tokLinkedToken;
	TOKEN_ELEVATION tokElev;
	DWORD tokHasRestrictions;
	TOKEN_ACCESS_INFORMATION *tokAccessInformation;
	DWORD tokVirtAllowed;
	DWORD tokVirtEnabled;
	TOKEN_MANDATORY_LABEL *tokIntegrityLevel;
	DWORD tokUIAccess;
	TOKEN_MANDATORY_POLICY *tokMandaPolicy;
	TOKEN_GROUPS *tokLogonSid;
	DWORD tokAppContainer;
	TOKEN_GROUPS *tokCapabilities;
	//TOKEN_APPCONTAINER_INFORMATION tokAppContainerNfo;
	DWORD tokContainerNumber;
	//CLAIM_SECURITY_ATTRIBUTES_INFORMATION tokClaimAttributes;


	GetTokenInformation(hToken,TokenSource,&tokSource,sizeof(tokSource),&dwRet);
	GetTokenInformation(hToken,TokenType,&tokType,sizeof(tokType),&dwRet);
	GetTokenInformation(hToken,TokenElevationType,&tokElevType,sizeof(tokElevType),&dwRet);
	GetTokenInformation(hToken,TokenElevation,&tokElev,sizeof(tokElev),&dwRet);
	
	char strType[200];
	if(tokType == TokenPrimary) strcpy_s(strType,"Primary");
	else strcpy_s(strType,"Impersonation");
	
	char strElevated[200];
	if(tokElevType == TokenElevationTypeDefault) strcpy_s(strElevated,"No linked token");
	else if(tokElevType == TokenElevationTypeFull) strcpy_s(strElevated,"Elevated token");
	else if(tokElevType == TokenElevationTypeLimited) strcpy_s(strElevated,"Limited token");

	fprintf(stdout,"[i] +-+-> Token [%08x] - Token source: %s - Token type %s - %s - %s\n",hToken,tokSource.SourceName,strType,strElevated, tokElev.TokenIsElevated ? "Elevated privs" : "Normal privs" );

	// User
	GetTokenInformation(hToken,TokenOwner,NULL,0,&dwRet);
	tokOwner = (TOKEN_OWNER*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwRet);
	if(GetTokenInformation(hToken,TokenOwner,tokOwner,dwRet,&dwRet) == true){
		fprintf(stdout,"[i]    |\n");
		DWORD dwSize = 2048;
		char lpName[2048];
		char lpDomain[2048];
		SID_NAME_USE SNU;
		if( LookupAccountSidA( NULL, tokOwner->Owner, lpName, &dwSize, lpDomain, &dwSize, &SNU ) ){
			fprintf(stdout,"[i]    +-+-> Owner: %s\\%s\n",lpDomain,lpName);
		} else {
			fprintf(stdout,"[i]    +-+-> Owner: Unkown\n");
		}
	} else {
		fprintf(stderr,"[!] GetTokenInformation %d\n", GetLastError());
	}
	HeapFree(GetProcessHeap(),NULL,tokOwner);
	
	// User
	GetTokenInformation(hToken,TokenUser,NULL,0,&dwRet);
	tokUser = (TOKEN_USER*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwRet);
	if(GetTokenInformation(hToken,TokenUser,tokUser,dwRet,&dwRet) == true){
		fprintf(stdout,"[i]    |\n");
		DWORD dwSize = 2048;
		char lpName[2048];
		char lpDomain[2048];
		SID_NAME_USE SNU;
		if( LookupAccountSidA( NULL, tokUser->User.Sid, lpName, &dwSize, lpDomain, &dwSize, &SNU ) ){
			fprintf(stdout,"[i]    +-+-> User: %s\\%s\n",lpDomain,lpName);
		} else {
			fprintf(stdout,"[i]    +-+-> User: Unkown\n");
		}
	} else {
		fprintf(stderr,"[!] GetTokenInformation %d\n", GetLastError());
	}
	HeapFree(GetProcessHeap(),NULL,tokUser);


	// Groups
	GetTokenInformation(hToken,TokenGroups,NULL,0,&dwRet);
	tokGroups = (TOKEN_GROUPS*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwRet);
	if(GetTokenInformation(hToken,TokenGroups,tokGroups,dwRet,&dwRet) == true){
		fprintf(stdout,"[i]    |\n");
		DWORD dwSize = 2048;
		char lpName[2048];
		char lpDomain[2048];
		SID_NAME_USE SNU;

		for(DWORD dwCount=0;dwCount<tokGroups->GroupCount;dwCount++){
			
			dwSize=2048;
			if( LookupAccountSidA( NULL, tokGroups->Groups[dwCount].Sid, lpName, &dwSize, lpDomain, &dwSize, &SNU ) ){
				fprintf(stdout,"[i]    +-+-> Group: %s\\%s\n",lpDomain,lpName);
			} else {
				if(GetLastError() == ERROR_NONE_MAPPED ){
					fprintf(stdout,"[i]    +-+-> Group: None Mapped\n");
				} else {
					fprintf(stdout,"[i]    +-+-> Group: %s (%d)\n",sidToTextTok(tokGroups->Groups[dwCount].Sid),GetLastError());
				}
			}

			if(tokGroups->Groups[dwCount].Attributes & SE_GROUP_ENABLED) {
				fprintf(stdout,"[i]      +-> Enabled\n");
			}

			if(tokGroups->Groups[dwCount].Attributes & SE_GROUP_ENABLED_BY_DEFAULT) {
				fprintf(stdout,"[i]      +-> Enabled by default\n");
			}

			if(tokGroups->Groups[dwCount].Attributes & SE_GROUP_INTEGRITY) {
				fprintf(stdout,"[i]      +-> Integrity SID\n");
			}

			if(tokGroups->Groups[dwCount].Attributes & SE_GROUP_INTEGRITY_ENABLED) {
				fprintf(stdout,"[i]      +-> Integrity enabled\n");
			}
			if(tokGroups->Groups[dwCount].Attributes & SE_GROUP_LOGON_ID) {
				fprintf(stdout,"[i]      +-> Logon SID\n");
			}
			if(tokGroups->Groups[dwCount].Attributes & SE_GROUP_MANDATORY) {
				fprintf(stdout,"[i]      +-> Mandatory\n");
			}
			if(tokGroups->Groups[dwCount].Attributes & SE_GROUP_OWNER) {
				fprintf(stdout,"[i]      +-> Owner\n");
			}
			if(tokGroups->Groups[dwCount].Attributes & SE_GROUP_RESOURCE) {
				fprintf(stdout,"[i]      +-> Domain-local group\n");
			}

			if(tokGroups->Groups[dwCount].Attributes & SE_GROUP_OWNER) {
				fprintf(stdout,"[i]      +-> Owner\n");
			}

			if(tokGroups->Groups[dwCount].Attributes & SE_GROUP_USE_FOR_DENY_ONLY) {
				fprintf(stdout,"[i]      +-> Deny only SID\n");
			}
		}
	} else {
		fprintf(stderr,"[!] GetTokenInformation %d\n", GetLastError());
	}
	HeapFree(GetProcessHeap(),NULL,tokGroups);

	// Privs
	GetTokenInformation(hToken,TokenPrivileges,NULL,0,&dwRet);
	tokPrivs = (TOKEN_PRIVILEGES*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwRet);
	if(GetTokenInformation(hToken,TokenPrivileges,tokPrivs,dwRet,&dwRet) == true){
		fprintf(stdout,"[i]    |\n");
		fprintf(stdout,"[i]    +-+-> Privileges - %d\n",tokPrivs->PrivilegeCount);
		for(DWORD dwCount=0;dwCount<tokPrivs->PrivilegeCount;dwCount++){
			DWORD dwSize = 2048;
			char lpName[2048];

			LUID lFoo = tokPrivs->Privileges[dwCount].Luid;
			if(LookupPrivilegeName(NULL,&lFoo,lpName,&dwSize)){
				fprintf(stdout,"[i]      +-> Name: %s\n",lpName);
			} else {
				fprintf(stdout,"[i]      +-> Name: Unknown (%d)\n",GetLastError());
			}
			

		}
	} else {
		fprintf(stderr,"[!] GetTokenInformation %d\n", GetLastError());
	}
	HeapFree(GetProcessHeap(),NULL,tokPrivs);
	
	// Token owner
	GetTokenInformation(hToken,TokenOwner,NULL,0,&dwRet);
	tokOwner = (TOKEN_OWNER*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwRet);
	if(GetTokenInformation(hToken,TokenOwner,tokOwner,dwRet,&dwRet) == true){
		
		fprintf(stdout,"[i]    |\n");
		DWORD dwSize = 2048;
		char lpName[2048];
		char lpDomain[2048];
		SID_NAME_USE SNU;
		if( LookupAccountSidA( NULL, tokOwner->Owner, lpName, &dwSize, lpDomain, &dwSize, &SNU ) ){
			fprintf(stdout,"[i]    +-+-> Owner: %s\\%s\n",lpDomain,lpName);
		} else {
			fprintf(stdout,"[i]    +-+-> Owner: Unkown\n");
		}

	} else {
		fprintf(stderr,"[!] GetTokenInformation %d\n", GetLastError());
	}
	HeapFree(GetProcessHeap(),NULL,tokOwner);

	// Primary group 
	GetTokenInformation(hToken,TokenPrimaryGroup,NULL,0,&dwRet);
	tokPrimGroup = (TOKEN_PRIMARY_GROUP *)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwRet);
	if(GetTokenInformation(hToken,TokenPrimaryGroup,tokPrimGroup,dwRet,&dwRet) == true){
		
		fprintf(stdout,"[i]    |\n");
		DWORD dwSize = 2048;
		char lpName[2048];
		char lpDomain[2048];
		SID_NAME_USE SNU;
		if( LookupAccountSidA( NULL, tokPrimGroup->PrimaryGroup, lpName, &dwSize, lpDomain, &dwSize, &SNU ) ){
			fprintf(stdout,"[i]    +-+-> Primary group: %s\\%s\n",lpDomain,lpName);
		} else {
			fprintf(stdout,"[i]    +-+-> Primary group: Unkown\n");
		}

	} else {
		fprintf(stderr,"[!] GetTokenInformation %d\n", GetLastError());
	}
	HeapFree(GetProcessHeap(),NULL,tokPrimGroup);

	// Sandbox inert
	if(GetTokenInformation(hToken,TokenSandBoxInert,&dwSandboxInert,sizeof(dwSandboxInert),&dwRet)){
		
		if(dwSandboxInert > 0){
			fprintf(stdout,"[i]    |\n");
			fprintf(stdout,"[i]    +-+-> Alert - Sandbox inert\n");
		}

	} else {
		fprintf(stderr,"[!] GetTokenInformation %d\n", GetLastError());
	}

	// UI Access
	if(GetTokenInformation(hToken,TokenUIAccess,&tokUIAccess,sizeof(tokUIAccess),&dwRet)){
		
		if(tokUIAccess > 0){
			fprintf(stdout,"[i]    |\n");
			fprintf(stdout,"[i]    +-+-> Alert - UI Access\n");
		}

	} else {
		fprintf(stderr,"[!] GetTokenInformation %d\n", GetLastError());
	}

	// Integirty level
	bool bLow = false;
	GetTokenInformation(hToken,TokenIntegrityLevel,NULL,0,&dwRet);
	tokIntegrityLevel = (TOKEN_MANDATORY_LABEL *)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwRet);
	if(GetTokenInformation(hToken,TokenIntegrityLevel,tokIntegrityLevel ,dwRet,&dwRet) == true){
		fprintf(stdout,"[i]    |\n");

		DWORD dwSize = 2048;
		char lpName[2048];
		char lpDomain[2048];
		SID_NAME_USE SNU;
		if( LookupAccountSidA( NULL, tokIntegrityLevel->Label.Sid, lpName, &dwSize, lpDomain, &dwSize, &SNU ) ){
			fprintf(stdout,"[i]    +-+-> Integrity level: %s\\%s\n",lpDomain,lpName);
			if(strcmp(lpName,"Low Mandatory Level") ==0)
			{
				bLow = true;
			}
		} else {
			fprintf(stdout,"[i]    +-+-> Integrity level: Unkown\n");
		}
	
	} else {
		fprintf(stderr,"[!] GetTokenInformation %d\n", GetLastError());
	}
	HeapFree(GetProcessHeap(),NULL,tokIntegrityLevel);
	

	// Virtualisation allowed
	if(GetTokenInformation(hToken,TokenVirtualizationAllowed,&tokVirtAllowed,sizeof(tokVirtAllowed),&dwRet)){
		
		if(tokVirtAllowed > 0){
			fprintf(stdout,"[i]    |\n");
			fprintf(stdout,"[i]    +-+-> UAC virtualisation allowed\n");
		}

	} else {
		fprintf(stderr,"[!] GetTokenInformation %d\n", GetLastError());
	}

	// Virtualisation enabled
	if(GetTokenInformation(hToken,TokenVirtualizationEnabled,&tokVirtEnabled,sizeof(tokVirtEnabled),&dwRet)){
		
		if(dwSandboxInert > 0){
			fprintf(stdout,"[i]    |\n");
			fprintf(stdout,"[i]    +-+-> UAC virtualisation enabled\n");
		} else {
			if(tokVirtAllowed && bLow){
				fprintf(stdout,"[i]    |\n");
				fprintf(stdout,"[i]    +-+-> Alert - UAC virtualisation disabled\n");
			} 
		}

	} else {
		fprintf(stderr,"[!] GetTokenInformation %d\n", GetLastError());
	}
	
	// Default DACL
	GetTokenInformation(hToken,TokenDefaultDacl,NULL,0,&dwRet);
	tokDACL = (TOKEN_DEFAULT_DACL*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwRet);
	if(GetTokenInformation(hToken,TokenDefaultDacl,tokDACL,dwRet,&dwRet) == true){
		PrintPermissionsTok(tokDACL->DefaultDacl);
	} else {
		fprintf(stderr,"[!] GetTokenInformation %d\n", GetLastError());
	}
	HeapFree(GetProcessHeap(),NULL,tokDACL);
	

	return true;
}
