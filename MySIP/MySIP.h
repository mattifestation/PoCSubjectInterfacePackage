#pragma once
// Disable warnings about nameless structs/unions in Windows SDK headers
#pragma warning( disable : 4201 )

#include <windows.h>
#include <Mssip.h>
#include <WinTrust.h>
#include <Softpub.h>
#include "resource.h"

// e59b6e68-3312-4738-961f-db9405b2ddcb
// Note: This can be any GUID. I don't advise creating an IOC off this.
#define CRYPT_SUBJTYPE_MY_IMAGE                                  \
            { 0xe59b6e68,                                        \
              0x3312,                                            \
              0x4738,                                            \
              { 0x96, 0x1f, 0xdb, 0x94, 0x05, 0xb2, 0xdd, 0xcb } \
            }

#define SUPPORTED_EXTENSION_COUNT 3

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

STDAPI DllRegisterServer(void);
STDAPI DllUnregisterServer(void);

// All of these function names are extremely sigable.
// These function signatures are present in mssip.h
BOOL WINAPI MyPutSignature(_In_ SIP_SUBJECTINFO *pSubjectInfo, _In_ DWORD dwEncodingType, _Out_ DWORD *pdwIndex, _In_ DWORD cbSignedDataMsg, _In_ BYTE *pbSignedDataMsg);
BOOL WINAPI MyCreateHash(_In_ SIP_SUBJECTINFO *pSubjectInfo, _Inout_ DWORD *pcbIndirectData, _Out_ SIP_INDIRECT_DATA *pIndirectData);
BOOL WINAPI MyDelSignature(_In_ SIP_SUBJECTINFO *pSubjectInfo, _In_ DWORD dwIndex);
BOOL WINAPI IsMyFileExtension(_In_ WCHAR *pwszFileName, _Out_ GUID *pgSubject);
BOOL WINAPI AutoApproveHash(_In_ SIP_SUBJECTINFO *pSubjectInfo, _In_ SIP_INDIRECT_DATA *pIndirectData);
BOOL WINAPI GetLegitMSSignature(_In_ SIP_SUBJECTINFO *pSubjectInfo, _Out_ DWORD *pdwEncodingType, _In_ DWORD dwIndex, _Inout_ DWORD *pcbSignedDataMsg, _Out_ BYTE *pbSignedDataMsg);
