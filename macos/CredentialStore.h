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
a = 0;  \
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
   
int32_t SLCS_CreateCredentials(const char* ServiceName, const size_t ServiceNameLength,
                               const char* LoginName, const size_t LoginNameLength,
                               const void* Password,
                               const size_t PasswordLength);

int32_t SLCS_ReadCredentials(const char* ServiceName, const size_t ServiceNameLength,
                             const char* LoginName, const size_t LoginNameLength,
                             void** pPassword, size_t* pPasswordLength);

int32_t SLCS_UpdateCredentials(const char* ServiceName, const size_t ServiceNameLength,
                               const char* LoginName, const size_t LoginNameLength,
                               const void* Password,
                               const size_t PasswordLength);

int32_t SLCS_DeleteCredentials(const char* ServiceName, const size_t ServiceNameLength,
                               const char* LoginName, const size_t LoginNameLength);
   
int32_t SLCS_AllocPassword(void** pPassword, const size_t PasswordLength);
   
void SLCS_DeletePassword(void** pPassword, const size_t PasswordLength);

#ifndef __cplusplus__
}
#endif // #ifndef __cplusplus__

#endif // #ifndef __CREDENTIAL_STORE_H_INCLonstcon,
