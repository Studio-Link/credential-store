#include <iostream>
#include <cstdlib>

#include "CredentialStore.h"

int main(int argc, char **argv)
{
   void* Password = 0;
   size_t PasswordLength = 0;
   
   int32_t Result = SLCS_ReadCredentials("SLCS", 4, "User", 4, (void**)&Password, &PasswordLength);
   if(SLCS_SUCCESS == Result)
   {
      Result = SLCS_DeleteCredentials("SLCS", 4, "User", 4);
      SLCS_DeletePassword(&Password, PasswordLength);
   }
   
   Result = SLCS_CreateCredentials("SLCS", 4, "User", 4, (void**)"Password", 8);
   if(SLCS_SUCCESS == Result)
   {
      Result = SLCS_ReadCredentials("SLCS", 4, "User", 4, (void**)&Password, &PasswordLength);
      if(SLCS_SUCCESS == Result)
      {
         std::cout << "'" << (char*)Password << "'" << std::endl;
         SLCS_DeletePassword(&Password, PasswordLength);
      }
      
      Result = SLCS_UpdateCredentials("SLCS", 4, "User", 4, (void**)"0123456789", 10);
      if(SLCS_SUCCESS == Result)
      {
         Result = SLCS_ReadCredentials("SLCS", 4, "User", 4, (void**)&Password, &PasswordLength);
         if(SLCS_SUCCESS == Result)
         {
            std::cout << "'" << (char*)Password << "'" << std::endl;
            SLCS_DeletePassword(&Password, PasswordLength);
         }
         
         Result = SLCS_CreateCredentials("SLCS", 4, "User", 4, (void**)"Password", 8);
         if(SLCS_ITEM_ALREADY_EXISTS == Result)
         {
            std::cout << "\\o/" << std::endl;
         }

         Result = SLCS_DeleteCredentials("SLCS", 4, "User", 4);
      }
   }

   return 0;
}

