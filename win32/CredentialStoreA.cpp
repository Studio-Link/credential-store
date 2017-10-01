#include <iostream>
#include <iomanip>
#include <cstring>
#include <cstdlib>

#include <windows.h>
#include <wincred.h>
#include <strsafe.h>

#include "CredentialStore.h"

extern void SLCS_PrintSecErrorW(LPCWSTR Description, const long Status);

void SLCS_FreeUnicodeString(LPWSTR* ppUnicodeString, const size_t UnicodeStringLength)
{
  PRECONDITION(ppUnicodeString != 0);
  PRECONDITION(*ppUnicodeString != 0);
  PRECONDITION(UnicodeStringLength > 0);

  memset((void*)*ppUnicodeString, 0, UnicodeStringLength);
  free((void*)*ppUnicodeString);
  *ppUnicodeString = 0;
}


int32_t SLCS_AnsiStringToUnicodeString(LPCSTR AnsiString, const size_t AnsiStringLength, 
                                       LPWSTR* pUnicodeString, size_t* pUnicodeStringLength)
{
  PRECONDITION_RETURN(AnsiString != 0, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(AnsiStringLength > 0, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(pUnicodeString != 0, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(pUnicodeStringLength != 0, SLCS_INVALID_PARAMETER);

  int32_t result = SLCS_FAILURE;

  int UnicodeStringLength = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, AnsiString, (int)AnsiStringLength, 0, 0);
  if(UnicodeStringLength > 0)
  {
    LPWSTR UnicodeString = (LPWSTR)calloc(UnicodeStringLength + 1, sizeof(WCHAR));
    if(UnicodeString != 0)
    {
      int ConvertedChars = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, AnsiString, (int)AnsiStringLength, UnicodeString, UnicodeStringLength);
      if(ConvertedChars > 0)
      {
        *pUnicodeString = UnicodeString;
        *pUnicodeStringLength = UnicodeStringLength;

        result = SLCS_SUCCESS;
      }
      else
      {
        SLCS_FreeUnicodeString(&UnicodeString, UnicodeStringLength);

        result = SLCS_FAILURE;
      }
    }
    else
    {
      result = SLCS_OUT_OF_MEMORY;
    }
  }

  return result;
}

void SLCS_PrintSecErrorA(LPCSTR Description, const long Status)
{
  PRECONDITION(Description != 0);

  const size_t DescriptionLength = strlen(Description);
  if(DescriptionLength > 0)
  {
    LPWSTR UnicodeString = 0;
    size_t UnicodeStringLength = 0;
    int32_t result = SLCS_AnsiStringToUnicodeString(Description, DescriptionLength, &UnicodeString, &UnicodeStringLength);
    if(SLCS_SUCCESS == result)
    {
      SLCS_PrintSecErrorW(UnicodeString, Status);

      SLCS_FreeUnicodeString(&UnicodeString, UnicodeStringLength);
    }
  }
}

int32_t SLCS_CreateCredentialsA(LPCSTR ServiceName, const size_t ServiceNameLength,
                                LPCSTR LoginName, const size_t LoginNameLength,
                               const void *pPassword,
                               const size_t PasswordLength)
{
   PRECONDITION_RETURN(ServiceName != 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(ServiceNameLength > 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginName != 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginNameLength > 0, SLCS_INVALID_PARAMETER);
   
   LPWSTR ServiceNameBuffer = 0;
   size_t ServiceNameBufferLength = 0;
   int32_t result = SLCS_AnsiStringToUnicodeString(ServiceName, ServiceNameLength, &ServiceNameBuffer, &ServiceNameBufferLength);
   if(SLCS_SUCCESS == result)
   {
     LPWSTR LoginNameBuffer = 0;
     size_t LoginNameBufferLength = 0;
     result = SLCS_AnsiStringToUnicodeString(LoginName, LoginNameLength, &LoginNameBuffer, &LoginNameBufferLength);
     if(SLCS_SUCCESS == result)
     {
       result = SLCS_CreateCredentialsW(ServiceNameBuffer, ServiceNameBufferLength, LoginNameBuffer, LoginNameBufferLength, pPassword, PasswordLength);

       SLCS_FreeUnicodeString(&LoginNameBuffer, LoginNameBufferLength);
     }

     SLCS_FreeUnicodeString(&ServiceNameBuffer, ServiceNameBufferLength);
   }

   return result;
}

int32_t SLCS_ReadCredentialsA(LPCSTR ServiceName, const size_t ServiceNameLength,
                              LPCSTR LoginName, const size_t LoginNameLength,
                             void** ppPassword, size_t* pPasswordLength)
{
   PRECONDITION_RETURN(ServiceName != NULL, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(ServiceNameLength > 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginName != NULL, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginNameLength > 0, SLCS_INVALID_PARAMETER);
   
   LPWSTR ServiceNameBuffer = 0;
   size_t ServiceNameBufferLength = 0;
   int32_t result = SLCS_AnsiStringToUnicodeString(ServiceName, ServiceNameLength, &ServiceNameBuffer, &ServiceNameBufferLength);
   if(SLCS_SUCCESS == result)
   {
     LPWSTR LoginNameBuffer = 0;
     size_t LoginNameBufferLength = 0;
     result = SLCS_AnsiStringToUnicodeString(LoginName, LoginNameLength, &LoginNameBuffer, &LoginNameBufferLength);
     if(SLCS_SUCCESS == result)
     {
       result = SLCS_ReadCredentialsW(ServiceNameBuffer, ServiceNameBufferLength, LoginNameBuffer, LoginNameBufferLength, ppPassword, pPasswordLength);

       SLCS_FreeUnicodeString(&LoginNameBuffer, LoginNameBufferLength);
     }

     SLCS_FreeUnicodeString(&ServiceNameBuffer, ServiceNameBufferLength);
   }

   return result;
}

int32_t SLCS_UpdateCredentialsA(LPCSTR ServiceName, const size_t ServiceNameLength,
                                LPCSTR LoginName, const size_t LoginNameLength,
                               const void* pPassword,
                               const size_t PasswordLength)
{
   PRECONDITION_RETURN(ServiceName != NULL, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(ServiceNameLength > 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginName != NULL, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginNameLength > 0, SLCS_INVALID_PARAMETER);
   
   LPWSTR ServiceNameBuffer = 0;
   size_t ServiceNameBufferLength = 0;
   int32_t result = SLCS_AnsiStringToUnicodeString(ServiceName, ServiceNameLength, &ServiceNameBuffer, &ServiceNameBufferLength);
   if(SLCS_SUCCESS == result)
   {
     LPWSTR LoginNameBuffer = 0;
     size_t LoginNameBufferLength = 0;
     result = SLCS_AnsiStringToUnicodeString(LoginName, LoginNameLength, &LoginNameBuffer, &LoginNameBufferLength);
     if(SLCS_SUCCESS == result)
     {
       result = SLCS_UpdateCredentialsW(ServiceNameBuffer, ServiceNameBufferLength, LoginNameBuffer, LoginNameBufferLength, pPassword, PasswordLength);

       SLCS_FreeUnicodeString(&LoginNameBuffer, LoginNameBufferLength);
     }

     SLCS_FreeUnicodeString(&ServiceNameBuffer, ServiceNameBufferLength);
   }

   return result;
}

int32_t SLCS_DeleteCredentialsA(LPCSTR ServiceName, const size_t ServiceNameLength,
                                LPCSTR LoginName, const size_t LoginNameLength)
{
   PRECONDITION_RETURN(ServiceName != NULL, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(ServiceNameLength > 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginName != NULL, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginNameLength > 0, SLCS_INVALID_PARAMETER);

   LPWSTR ServiceNameBuffer = 0;
   size_t ServiceNameBufferLength = 0;
   int32_t result = SLCS_AnsiStringToUnicodeString(ServiceName, ServiceNameLength, &ServiceNameBuffer, &ServiceNameBufferLength);
   if(SLCS_SUCCESS == result)
   {
     LPWSTR LoginNameBuffer = 0;
     size_t LoginNameBufferLength = 0;
     result = SLCS_AnsiStringToUnicodeString(LoginName, LoginNameLength, &LoginNameBuffer, &LoginNameBufferLength);
     if(SLCS_SUCCESS == result)
     {
       result = SLCS_DeleteCredentialsW(ServiceNameBuffer, ServiceNameBufferLength, LoginNameBuffer, LoginNameBufferLength);

       SLCS_FreeUnicodeString(&LoginNameBuffer, LoginNameBufferLength);
     }

     SLCS_FreeUnicodeString(&ServiceNameBuffer, ServiceNameBufferLength);
   }

   return result;
}

