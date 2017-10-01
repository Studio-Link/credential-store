#include <iostream>
#include <iomanip>
#include <cstring>
#include <cstdlib>

#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>
#include <Security/Security.h>

#include "CredentialStore.h"

void SLCS_PrintSecError(const char* Description, const OSStatus Status)
{
   PRECONDITION(Description != 0);
   
   CFStringRef ErrorMessage = SecCopyErrorMessageString(Status, 0);
   if (ErrorMessage != 0)
   {
      CFIndex MinBufferLength = CFStringGetLength(ErrorMessage);
      CFIndex MaxBufferLength = CFStringGetMaximumSizeForEncoding(MinBufferLength, kCFStringEncodingUTF8) + 1;
      char *Buffer = (char *)calloc(MaxBufferLength, sizeof(char));
      if (Buffer != 0)
      {
         if (CFStringGetCString(ErrorMessage, Buffer, MaxBufferLength,
                                kCFStringEncodingUTF8) != FALSE)
         {
            std::cout << Description << ", rc = " << (int32_t)Status << ", '" << Buffer << "'" << std::endl;
         }
         
         free(Buffer);
         Buffer = 0;
      }
      
      CFRelease(ErrorMessage);
      ErrorMessage = 0;
   }
}

int32_t SLCS_CreateCredentials(const char* ServiceName, const size_t ServiceNameLength,
                               const char* LoginName, const size_t LoginNameLength,
                               const void* Password,
                               const size_t PasswordLength)
{
   PRECONDITION_RETURN(ServiceName != 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(ServiceNameLength > 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginName != 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginNameLength > 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(Password != 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(PasswordLength > 0, SLCS_INVALID_PARAMETER);
   
   int32_t Result = SLCS_FAILURE;
   
   OSStatus Status = SecKeychainAddGenericPassword(0, (UInt32)ServiceNameLength, ServiceName, (UInt32)LoginNameLength,
                                                   LoginName, (UInt32)PasswordLength, Password, 0);
   if (errSecSuccess == Status)
   {
      Result = SLCS_SUCCESS;
   }
   else
   {
      SLCS_PrintSecError("SecKeychainAddGenericPassword() failed", Status);
      
      if(errSecDuplicateItem == Status)
      {
         Result = SLCS_ITEM_ALREADY_EXISTS;
      }
      else
      {
         Result = SLCS_FAILURE;
      }
   }
   
   return Result;
}

int32_t SLCS_ReadCredentials(const char* ServiceName, const size_t ServiceNameLength,
                             const char* LoginName, const size_t LoginNameLength,
                             void** pPassword, size_t* pPasswordLength)
{
   PRECONDITION_RETURN(ServiceName != 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(ServiceNameLength > 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginName != 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginNameLength > 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(pPassword != 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(pPasswordLength != 0, SLCS_INVALID_PARAMETER);
   
   int32_t Result = SLCS_FAILURE;
   
   *pPasswordLength = 0;
   *pPassword = 0;
   
   void* PasswordBuffer = 0;
   SecKeychainItemRef Item = 0;
   OSStatus Status =
   SecKeychainFindGenericPassword(0, (UInt32)ServiceNameLength, ServiceName, (UInt32)LoginNameLength,
                                  LoginName, (UInt32*)pPasswordLength, &PasswordBuffer, &Item);
   if (errSecSuccess == Status)
   {
      Result = SLCS_AllocPassword(pPassword, *pPasswordLength);
      if ((SLCS_SUCCESS == Result) && (*pPassword != 0))
      {
         memmove(*pPassword, PasswordBuffer, *pPasswordLength);
         Result = SLCS_SUCCESS;
      }
      
      SecKeychainItemFreeContent(0, PasswordBuffer);
      PasswordBuffer = 0;
      
      CFRelease(Item);
      Item = 0;
   }
   else
   {
      SLCS_PrintSecError("SecKeychainFindGenericPassword() failed", Status);
      
      if(errSecItemNotFound == Status)
      {
         Result = SLCS_ITEM_NOT_FOUND;
      }
      else
      {
         Result = SLCS_FAILURE;
      }
   }
   
   return Result;
}

int32_t SLCS_UpdateCredentials(const char* ServiceName, const size_t ServiceNameLength,
                               const char* LoginName, const size_t LoginNameLength,
                               const void* Password,
                               const size_t PasswordLength)
{
   PRECONDITION_RETURN(ServiceName != 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(ServiceNameLength > 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginName != 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginNameLength > 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(Password != 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(PasswordLength > 0, SLCS_INVALID_PARAMETER);
   
   int32_t Result = SLCS_FAILURE;
   
   SecKeychainItemRef Item = 0;
   OSStatus Status = SecKeychainFindGenericPassword(0, (UInt32)ServiceNameLength, ServiceName,
                                                    (UInt32)LoginNameLength, LoginName, 0, 0, &Item);
   if (errSecSuccess == Status)
   {
      Status = SecKeychainItemModifyAttributesAndData(Item, 0, (UInt32)PasswordLength,
                                                      Password);
      if (errSecSuccess == Status)
      {
         Result = SLCS_SUCCESS;
      }
      else
      {
         SLCS_PrintSecError("SecKeychainItemModifyAttributesAndData() failed",
                            Status);
      }
   }
   else
   {
      SLCS_PrintSecError("SecKeychainFindGenericPassword() failed", Status);
      
      if(errSecItemNotFound == Status)
      {
         Result = SLCS_ITEM_NOT_FOUND;
      }
      else
      {
         Result = SLCS_FAILURE;
      }
   }
   
   return Result;
}

int32_t SLCS_DeleteCredentials(const char *ServiceName, const size_t ServiceNameLength,
                               const char* LoginName, const size_t LoginNameLength)
{
   PRECONDITION_RETURN(ServiceName != 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(ServiceNameLength > 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginName != 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginNameLength > 0, SLCS_INVALID_PARAMETER);

   int32_t Result = SLCS_FAILURE;
   
   SecKeychainItemRef Item = 0;
   OSStatus Status = SecKeychainFindGenericPassword(0, (UInt32)ServiceNameLength, ServiceName,
                                                    (UInt32)LoginNameLength, LoginName, 0, 0, &Item);
   if (errSecSuccess == Status)
   {
      Status = SecKeychainItemDelete(Item);
      if (errSecSuccess == Status)
      {
         Result = SLCS_SUCCESS;
      }
      else
      {
         SLCS_PrintSecError("SecKeychainItemModifyAttributesAndData() failed",
                            Status);
      }
   }
   else
   {
      SLCS_PrintSecError("SecKeychainFindGenericPassword() failed", Status);
      
      if(errSecItemNotFound == Status)
      {
         Result = SLCS_ITEM_NOT_FOUND;
      }
      else
      {
         Result = SLCS_FAILURE;
      }
   }

   return Result;
}

int32_t SLCS_AllocPassword(void** pPassword, const size_t PasswordLength)
{
   PRECONDITION_RETURN(pPassword != 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(*pPassword == 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(PasswordLength > 0, SLCS_INVALID_PARAMETER);
   
   int32_t Result = SLCS_FAILURE;
   
   *pPassword = calloc(PasswordLength, sizeof(char));
   if(*pPassword != 0)
   {
      Result = SLCS_SUCCESS;
   }
   else
   {
      Result = SLCS_OUT_OF_MEMORY;
   }
   
   return Result;
}

void SLCS_DeletePassword(void** pPassword, const size_t PasswordLength)
{
   PRECONDITION(pPassword != 0);
   PRECONDITION(*pPassword != 0);
   PRECONDITION(PasswordLength > 0);
   
   memset(*pPassword, 0, PasswordLength);
   free(*pPassword);
   *pPassword = 0;
}
