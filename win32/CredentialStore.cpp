#include <iostream>
#include <iomanip>
#include <cstring>
#include <cstdlib>

#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>
#include <Security/Security.h>

#include "CredentialStore.h"

void SLCS_PrintSecError(const char *description, const OSStatus status)
{
   PRECONDITION(description != NULL);
   
   CFStringRef errorMessage = SecCopyErrorMessageString(status, NULL);
   if (errorMessage != NULL)
   {
      CFIndex minBufferLength = CFStringGetLength(errorMessage);
      CFIndex maxBufferLength = CFStringGetMaximumSizeForEncoding(minBufferLength, kCFStringEncodingUTF8) + 1;
      char *buffer = (char *)calloc(maxBufferLength, sizeof(char));
      if (buffer != NULL)
      {
         if (CFStringGetCString(errorMessage, buffer, maxBufferLength,
                                kCFStringEncodingUTF8) != FALSE)
         {
            std::cout << description << ", rc = " << (int32_t)status << ", '" << buffer << "'" << std::endl;
         }
         
         free(buffer);
         buffer = NULL;
      }
      
      CFRelease(errorMessage);
      errorMessage = NULL;
   }
}

int32_t SLCS_CreateCredentials(const char *id, const uint32_t idLength,
                               const char *login, const uint32_t loginLength,
                               const void *password,
                               const uint32_t passwordLength)
{
   PRECONDITION_RETURN(id != NULL, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(idLength > 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(login != NULL, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(loginLength > 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(password != NULL, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(passwordLength > 0, SLCS_INVALID_PARAMETER);
   
   int32_t result = SLCS_FAILURE;
   
   OSStatus status = SecKeychainAddGenericPassword(NULL, idLength, id, loginLength, login, passwordLength, password, NULL);
   if (errSecSuccess == status)
   {
      result = SLCS_SUCCESS;
   }
   else
   {
      SLCS_PrintSecError("SecKeychainAddGenericPassword() failed", status);
      
      if(errSecDuplicateItem == status)
      {
         result = SLCS_ITEM_ALREADY_EXISTS;
      }
      else
      {
         result = SLCS_FAILURE;
      }
   }
   
   return result;
}

int32_t SLCS_ReadCredentials(const char *id, const uint32_t idLength,
                             const char *login, const uint32_t loginLength,
                             void **password, uint32_t *passwordLength)
{
   PRECONDITION_RETURN(id != NULL, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(idLength > 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(login != NULL, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(loginLength > 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(password != NULL, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(passwordLength != NULL, SLCS_INVALID_PARAMETER);
   
   int32_t result = SLCS_FAILURE;
   
   *passwordLength = 0;
   *password = NULL;
   
   void *passwordBuffer = NULL;
   SecKeychainItemRef item = NULL;
   OSStatus status =
   SecKeychainFindGenericPassword(NULL, (UInt32)idLength, id, (UInt32)loginLength, login,
                                  (UInt32*)passwordLength, &passwordBuffer, &item);
   if (errSecSuccess == status)
   {
      result = SLCS_AllocPassword(password, *passwordLength);
      if ((SLCS_SUCCESS == result) && (*password != NULL))
      {
         memmove(*password, passwordBuffer, *passwordLength);
         result = SLCS_SUCCESS;
      }
      
      SecKeychainItemFreeContent(NULL, passwordBuffer);
      passwordBuffer = NULL;
      
      CFRelease(item);
      item = NULL;
   }
   else
   {
      SLCS_PrintSecError("SecKeychainFindGenericPassword() failed", status);
      
      if(errSecItemNotFound == status)
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

int32_t SLCS_UpdateCredentials(const char *id, const uint32_t idLength,
                               const char *login, const uint32_t loginLength,
                               const void *password,
                               const uint32_t passwordLength)
{
   PRECONDITION_RETURN(id != NULL, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(idLength > 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(login != NULL, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(loginLength > 0, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(password != NULL, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(passwordLength > 0, SLCS_INVALID_PARAMETER);
   
   int32_t result = SLCS_FAILURE;
   
   SecKeychainItemRef item = NULL;
   OSStatus status = SecKeychainFindGenericPassword(NULL, idLength, id, loginLength, login, 0, NULL, &item);
   if (errSecSuccess == status)
   {
      status = SecKeychainItemModifyAttributesAndData(item, NULL, passwordLength,
                                                      password);
      if (errSecSuccess == status)
      {
         result = SLCS_SUCCESS;
      }
      else
      {
         SLCS_PrintSecError("SecKeychainItemModifyAttributesAndData() failed",
                            status);
      }
   }
   else
   {
      SLCS_PrintSecError("SecKeychainFindGenericPassword() failed", status);
      
      if(errSecItemNotFound == status)
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

int32_t SLCS_DeleteCredentials(const char *id, const uint32_t idLength, const char* login, const uint32_t loginLength)
{
   
   PRECONDITION_RETURN(id != NULL, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(idLength > 0, SLCS_INVALID_PARAMETER);
   
   int32_t result = SLCS_FAILURE;
   
   SecKeychainItemRef item = NULL;
   OSStatus status = SecKeychainFindGenericPassword(NULL, idLength, id, loginLength, login, 0, NULL, &item);
   if (errSecSuccess == status)
   {
      status = SecKeychainItemDelete(item);
      if (errSecSuccess == status)
      {
         result = SLCS_SUCCESS;
      }
      else
      {
         SLCS_PrintSecError("SecKeychainItemModifyAttributesAndData() failed",
                            status);
      }
   }
   else
   {
      SLCS_PrintSecError("SecKeychainFindGenericPassword() failed", status);
      
      if(errSecItemNotFound == status)
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

int32_t SLCS_AllocPassword(void** password, const uint32_t passwordLength)
{
   PRECONDITION_RETURN(password != NULL, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(*password == NULL, SLCS_INVALID_PARAMETER);
   PRECONDITION_RETURN(passwordLength > 0, SLCS_INVALID_PARAMETER);
   
   int32_t result = SLCS_FAILURE;
   
   *password = calloc(passwordLength, sizeof(char));
   if(*password != NULL)
   {
      result = SLCS_SUCCESS;
   }
   else
   {
      result = SLCS_OUT_OF_MEMORY;
   }
   
   return result;
}

void SLCS_DeletePassword(void** password, const uint32_t passwordLength)
{
   PRECONDITION(password != NULL);
   PRECONDITION(*password != NULL);
   PRECONDITION(passwordLength > 0);
   
   memset(*password, 0, passwordLength);
   free(*password);
   *password = NULL;
}
