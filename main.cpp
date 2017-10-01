#include <iostream>
#include <cstdlib>

#include "CredentialStore.h"

int main(int argc, char **argv)
{
   void* password = NULL;
   size_t passwordLength = 0;
   
   int32_t result = SLCS_ReadCredentials("SLCS", 4, "User", 4, (void**)&password, &passwordLength);
   if(SLCS_SUCCESS == result)
   {
      result = SLCS_DeleteCredentials("SLCS", 4, "User", 4);
      SLCS_DeletePassword(&password, passwordLength);
   }
   
   result = SLCS_CreateCredentials("SLCS", 4, "User", 4, (void**)"Password", 8);
   if(SLCS_SUCCESS == result)
   {
      result = SLCS_ReadCredentials("SLCS", 4, "User", 4, (void**)&password, &passwordLength);
      if(SLCS_SUCCESS == result)
      {
         std::cout << "'" << (char*)password << "'" << std::endl;
         SLCS_DeletePassword(&password, passwordLength);
      }
      
      result = SLCS_UpdateCredentials("SLCS", 4, "User", 4, (void**)"0123456789", 10);
      if(SLCS_SUCCESS == result)
      {
         result = SLCS_ReadCredentials("SLCS", 4, "User", 4, (void**)&password, &passwordLength);
         if(SLCS_SUCCESS == result)
         {
            std::cout << "'" << (char*)password << "'" << std::endl;
            SLCS_DeletePassword(&password, passwordLength);
         }
         
         result = SLCS_CreateCredentials("SLCS", 4, "User", 4, (void**)"Password", 8);
         if(SLCS_ITEM_ALREADY_EXISTS == result)
         {
            std::cout << "\\o/" << std::endl;
         }

         result = SLCS_DeleteCredentials("SLCS", 4, "User", 4);
      }
   }

   return 0;
}

