#ifndef __CREDENTIAL_STORE_H_INCL__
#define __CREDENTIAL_STORE_H_INCL__

#include <stdint.h>
#include <windows.h>

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

int32_t SLCS_CreateCredentialsW(LPCWSTR ServiceName, const size_t ServiceNameLength,
                                LPCWSTR LoginName, const size_t LoginNameLength,
                                const void *pPassword,
                                const size_t PasswordLength);

int32_t SLCS_CreateCredentialsA(LPCSTR ServiceName, const size_t ServiceNameLength,
                                LPCSTR LoginName, const size_t LoginNameLength,
                                const void *pPassword,
                                const size_t PasswordLength);

int32_t SLCS_ReadCredentialsW(LPCWSTR ServiceName, const size_t ServiceNameLength,
                              LPCWSTR LoginName, const size_t LoginNameLength,
                              void **ppPassword, size_t *pPasswordLength);

int32_t SLCS_ReadCredentialsA(LPCSTR ServiceName, const size_t ServiceNameLength,
                              LPCSTR LoginName, const size_t LoginNameLength,
                              void **ppPassword, size_t *pPasswordLength);

int32_t SLCS_UpdateCredentialsW(LPCWSTR ServiceName, const size_t ServiceNameLength,
                                LPCWSTR LoginName, const size_t LoginNameLength,
                                const void *pPassword,
                                const size_t PasswordLength);

int32_t SLCS_UpdateCredentialsA(LPCSTR ServiceName, const size_t ServiceNameLength,
                                LPCSTR LoginName, const size_t LoginNameLength,
                                const void *pPassword,
                                const size_t PasswordLength);

int32_t SLCS_DeleteCredentialsW(LPCWSTR ServiceName, const size_t ServiceNameLength,
                                LPCWSTR LoginName, const size_t LoginNameLength);

int32_t SLCS_DeleteCredentialsA(LPCSTR ServiceName, const size_t ServiceNameLength,
                                LPCSTR LoginName, const size_t LoginNameLength);

#ifdef UNICODE
#define SLCS_CreateCredentials  SLCS_CreateCredentialsW
#define SLCS_ReadCredentials    SLCS_ReadCredentialsW
#define SLCS_UpdateCredentials  SLCS_UpdateCredentialsW
#define SLCS_DeleteCredentials  SLCS_DeleteCredentialsW
#else
#define SLCS_CreateCredentials  SLCS_CreateCredentialsA
#define SLCS_ReadCredentials    SLCS_ReadCredentialsA
#define SLCS_UpdateCredentials  SLCS_UpdateCredentialsA
#define SLCS_DeleteCredentials  SLCS_DeleteCredentialsA
#endif // #ifdef UNICODE


int32_t SLCS_AllocPassword(void** ppPassword, const size_t PasswordLength);

void SLCS_DeletePassword(void** ppPassword, const size_t PasswordLength);

#ifndef __cplusplus__
}
#endif // #ifndef __cplusplus__

#endif // #ifndef __CREDENTIAL_STORE_H_INCLonstcon,
