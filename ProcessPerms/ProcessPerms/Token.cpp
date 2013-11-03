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
BOOL TokenProcess(HANDLE hToken){
	DWORD dwRet = 0;

	TOKEN_USER *tokUser;
	TOKEN_GROUPS *tokGroups;
	TOKEN_PRIVILEGES *tokPrivs;
	TOKEN_OWNER *tokOwner;
	TOKEN_PRIMARY_GROUP *tokPrimGroup;
	TOKEN_DEFAULT_DACL *tokDACL;
	TOKEN_SOURCE *tokSource;
	TOKEN_TYPE *tokType;
	SECURITY_IMPERSONATION_LEVEL *tokImpersonationLvl;
	TOKEN_STATISTICS *tokStats;
	DWORD *tokSessionID;
	TOKEN_GROUPS_AND_PRIVILEGES *tokGrpPrivs;
	DWORD *dwSandboxInert;
	TOKEN_ORIGIN *tokOrigin;
	TOKEN_ELEVATION_TYPE *tokElevType;
	TOKEN_LINKED_TOKEN *tokLinkedToken;
	TOKEN_ELEVATION *tokElev;
	DWORD tokHasRestrictions;
	TOKEN_ACCESS_INFORMATION *tokAccessInformation;
	DWORD tokVirtAllowed;
	DWORD tokVirtEnabled;
	DWORD tokIntegrityLevel;
	DWORD tokUIAccess;
	TOKEN_MANDATORY_POLICY *tokMandaPolicy;
	TOKEN_GROUPS *tokLogonSid;
	DWORD tokAppContainer;
	TOKEN_GROUPS *tokCapabilities;
	//TOKEN_APPCONTAINER_INFORMATION tokAppContainerNfo;
	DWORD tokContainerNumber;
	//CLAIM_SECURITY_ATTRIBUTES_INFORMATION tokClaimAttributes;

	fprintf(stdout,"[i] +-+-> Token [%08x]\n",hToken);

	
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

	return true;
}
