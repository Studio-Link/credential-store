#include <windows.h>
#include "CredentialStore.h"

int32_t SLCS_AllocPassword(void** ppPassword, const size_t PasswordLength)
{
  PRECONDITION_RETURN(ppPassword != NULL, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(*ppPassword == NULL, SLCS_INVALID_PARAMETER);
  PRECONDITION_RETURN(PasswordLength > 0, SLCS_INVALID_PARAMETER);

  int32_t result = SLCS_FAILURE;

  *ppPassword = calloc(PasswordLength, sizeof(char));
  if(*ppPassword != NULL)
  {
    result = SLCS_SUCCESS;
  }
  else
  {
    result = SLCS_OUT_OF_MEMORY;
  }

  return result;
}

void SLCS_DeletePassword(void** ppPassword, const size_t PasswordLength)
{
  PRECONDITION(ppPassword != NULL);
  PRECONDITION(*ppPassword != NULL);
  PRECONDITION(PasswordLength > 0);

  memset(*ppPassword, 0, PasswordLength);
  free(*ppPassword);
  *ppPassword = NULL;
}
