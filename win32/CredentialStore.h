#ifndef __CREDENTIAL_STORE_H_INCL__
#define __CREDENTIAL_STORE_H_INCL__

#include <stdint.h>

#define PRECONDITION(a)                                                        \
   if (!(a)) {                                                                  \
      return;                                                                    \
   }
#define PRECONDITION_RETURN(a, b)                                              \
   if (!(a)) {                                                                  \
      return (b);                                                                \
   }

#define SAFE_DELETE(a) \
if ((a)) {     \
free((a));  \
a = NULL;  \
}

#define SLCS_SUCCESS 0
#define SLCS_FAILURE 0x80000000
#define SLCS_INVALID_PARAMETER 0x80000001
#define SLCS_ITEM_NOT_FOUND 0x80000002
#define SLCS_ITEM_ALREADY_EXISTS 0x80000003
#define SLCS_OUT_OF_MEMORY 0x80000004

#ifndef __cplusplus__
extern "C" {
#endif // #ifndef __cplusplus__
   
int32_t SLCS_CreateCredentials(const char *id, const uint32_t idLength,
                               const char *login, const uint32_t loginLength,
                               const void *password,
                               const uint32_t passwordLength);

int32_t SLCS_ReadCredentials(const char *id, const uint32_t idLength,
                             const char *login, const uint32_t loginLength,
                             void **password, uint32_t *passwordLength);

int32_t SLCS_UpdateCredentials(const char *id, const uint32_t idLength,
                               const char *login, const uint32_t loginLength,
                               const void *password,
                               const uint32_t passwordLength);

int32_t SLCS_DeleteCredentials(const char *id, const uint32_t idLength,
                               const char* login, const uint32_t loginLength);
   
int32_t SLCS_AllocPassword(void** password, const uint32_t passwordLength);
   
void SLCS_DeletePassword(void** password, const uint32_t passwordLength);

#ifndef __cplusplus__
}
#endif // #ifndef __cplusplus__

#endif // #ifndef __CREDENTIAL_STORE_H_INCLonstcon,
