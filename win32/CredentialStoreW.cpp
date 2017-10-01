#include <iostream>
#include <iomanip>
#include <cstring>
#include <cstdlib>

#include <windows.h>
#include <wincred.h>
#include <strsafe.h>

#include "CredentialStore.h"

void SLCS_PrintSecErrorW(LPCWSTR Description, const long Status)
{
  PRECONDITION(Description != 0);

  LPWSTR MessageBuffer = 0;
  size_t MessageBufferSize =  FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, 0, Status, 
                                            MAKELCID(LANG_NEUTRAL, SUBLANG_NEUTRAL), (LPWSTR)&MessageBuffer, 0, 0);
  if(MessageBufferSize > 0)
  {
    std::wcout << Description << L", rc = " << Status << L", " << MessageBuffer << std::endl;
  }

  if(MessageBuffer != 0)
  {
    LocalFree(MessageBuffer);
    MessageBuffer = 0;
  }

  MessageBufferSize = 0;
}

int32_t SLCS_CreateCredentialsW(LPCWSTR ServiceName, const size_t ServiceNameLength,
                                LPCWSTR LoginName, const size_t LoginNameLength,
                                const void *pPassword,
                                const size_t PasswordLength)
{
  PRECONDITION_RETURN(ServiceName != NULL, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(ServiceNameLength > 0, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(LoginName != NULL, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(LoginNameLength > 0, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(pPassword != NULL, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(PasswordLength > 0, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(PasswordLength <= CRED_MAX_CREDENTIAL_BLOB_SIZE, SLCS_INVALID_PARAMETER);

  int32_t result = SLCS_FAILURE;

  PCREDENTIALW pCredential = {0};
  if(CredReadW(ServiceName, CRED_TYPE_GENERIC, 0, &pCredential) == FALSE)
  {
    CREDENTIALW Credential = {0};
    Credential.Type = CRED_TYPE_GENERIC;
    Credential.TargetName = (LPWSTR)ServiceName;
    Credential.Comment = L"Created by StudioLink credential store";
    Credential.CredentialBlobSize = (DWORD)PasswordLength;
    Credential.CredentialBlob = (LPBYTE)pPassword;
    Credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    Credential.UserName = (LPWSTR)LoginName;

    if(CredWriteW(&Credential, 0) != FALSE)
    {
      result = SLCS_SUCCESS;
    }
    else
    {
      SLCS_PrintSecErrorW(L"CredWrite failed", GetLastError());

      result = SLCS_FAILURE;
    }
  }
  else
  {
    CredFree(pCredential);
    pCredential = 0;

    SLCS_PrintSecErrorW(L"CredWrite failed", ERROR_ALREADY_EXISTS);

    result = SLCS_ITEM_ALREADY_EXISTS;
  }

  return result;
}

int32_t SLCS_ReadCredentialsW(LPCWSTR ServiceName, const size_t ServiceNameLength,
                              LPCWSTR LoginName, const size_t LoginNameLength,
                              void **ppPassword, size_t *pPasswordLength)
{
  PRECONDITION_RETURN(ServiceName != NULL, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(ServiceNameLength > 0, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(LoginName != NULL, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(LoginNameLength > 0, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(ppPassword != NULL, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(pPasswordLength != NULL, SLCS_INVALID_PARAMETER);

  int32_t result = SLCS_FAILURE;

  *ppPassword = 0;
  *pPasswordLength = 0;

  PCREDENTIALW pCredential = {0};
  if(CredReadW(ServiceName, CRED_TYPE_GENERIC, 0, &pCredential) != FALSE)
  {
    result = SLCS_AllocPassword(ppPassword, pCredential->CredentialBlobSize);
    if(SLCS_SUCCESS == result)
    {
      memmove(*ppPassword, pCredential->CredentialBlob, pCredential->CredentialBlobSize);
      *pPasswordLength = pCredential->CredentialBlobSize;

      result = SLCS_SUCCESS;
    }

    CredFree(pCredential);
    pCredential = 0;

    result = SLCS_SUCCESS;
  }
  else
  {
    const long Status = GetLastError();
    SLCS_PrintSecErrorW(L"CredRead failed", Status);

    if(ERROR_NOT_FOUND == Status)
    {
      result = SLCS_ITEM_NOT_FOUND;
    }
    else
    {
      result = SLCS_FAILURE;
    }
  }

  return result;
}

int32_t SLCS_UpdateCredentialsW(LPCWSTR ServiceName, const size_t ServiceNameLength,
                                LPCWSTR LoginName, const size_t LoginNameLength,
                                const void *pPassword,
                                const size_t PasswordLength)
{
  PRECONDITION_RETURN(ServiceName != NULL, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(ServiceNameLength > 0, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(LoginName != NULL, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(LoginNameLength > 0, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(pPassword != NULL, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(PasswordLength > 0, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(PasswordLength <= CRED_MAX_CREDENTIAL_BLOB_SIZE, SLCS_INVALID_PARAMETER);

  int32_t result = SLCS_FAILURE;

  PCREDENTIALW pCredential = {0};
  if(CredReadW(ServiceName, CRED_TYPE_GENERIC, 0, &pCredential) != FALSE)
  {
    CredFree(pCredential);
    pCredential = 0;

    CREDENTIALW Credential = {0};
    Credential.Type = CRED_TYPE_GENERIC;
    Credential.TargetName = (LPWSTR)ServiceName;
    Credential.Comment = L"Created by StudioLink credential store";
    Credential.CredentialBlobSize = (DWORD)PasswordLength;
    Credential.CredentialBlob = (LPBYTE)pPassword;
    Credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    Credential.UserName = (LPWSTR)LoginName;

    if(CredWriteW(&Credential, 0) != FALSE)
    {
      result = SLCS_SUCCESS;
    }
    else
    {
      SLCS_PrintSecErrorW(L"CredWrite failed", GetLastError());

      result = SLCS_FAILURE;
    }
  }
  else
  {
    SLCS_PrintSecErrorW(L"CredWrite failed", ERROR_NOT_FOUND);

    result = SLCS_ITEM_NOT_FOUND;
  }

  return result;
}

int32_t SLCS_DeleteCredentialsW(LPCWSTR ServiceName, const size_t ServiceNameLength,
                                LPCWSTR LoginName, const size_t LoginNameLength)
{
  PRECONDITION_RETURN(ServiceName != NULL, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(ServiceNameLength > 0, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(LoginName != NULL, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(LoginNameLength > 0, SLCS_INVALID_PARAMETER);

  int32_t result = SLCS_FAILURE;

  if(CredDeleteW(ServiceName, CRED_TYPE_GENERIC, 0) != FALSE)
  {
    result = SLCS_SUCCESS;
  }
  else
  {
    const long Status = GetLastError();
    SLCS_PrintSecErrorW(L"CredDelete failed", Status);

    if(ERROR_NOT_FOUND == Status)
    {
      result = SLCS_ITEM_NOT_FOUND;
    }
    else
    {
      result = SLCS_FAILURE;
    }
  }

  return result;
}

