#ifndef _PKICERTEXHSM_
#define _PKICERTEXHSM_
#include "pkcs11t.h"

#ifdef _WIN32
#define PKCSLIB "c:\\temp\\hsm\\certexpkcs11.dll"
#endif
#ifdef __linux__
#define PKCSLIB "libcertex-rcsp_r.so.1.0.0"
#endif
#ifdef __FreeBSD__
#define PKCSLIB "libcertex-rcsp_r.so.1"
#endif

extern unsigned int nsignSize;

#define DEBUG_OUT 1

#define CKR_KZNAC_BASE						0x8aa00000
#define CKR_KZNAC_MEMORY_ERROR 				0x8aa00001
#define CKR_KZNAC_INIT_HSM_ERROR 			0x8aa00002
#define CKR_KZNAC_CONF_PATH_ISNULL 			0x8aa00003
#define CKR_KZNAC_RCSPLIB_OPEN 				0x8aa00004
#define CKR_KZNAC_NOF_RCSP_CONNECT 			0x8aa00005
#define CKR_KZNAC_C_GETFUNCTIONLIST			0x8aa00006
#define CKR_KZNAC_GOST_RSA_ISNULL 			0x8aa00007
#define CKR_KZNAC_CONTAINER_ISNULL 			0x8aa00008
#define CKR_KZNAC_DATA_SIZE_ISNULL 			0x8aa00009
#define CKR_KZNAC_NO_OUTMEM 				0x8aa0000a
#define CKR_KZNAC_TMPHASH_ISNULL 			0x8aa0000b
#define CKR_KZNAC_HASH_ISNULL 				0x8aa0000c
#define CKR_KZNAC_UNKNOWN_ALG 				0x8aa0000d
#define CKR_KZNAC_KEYID_ISNULL				0x8aa0000e
#define CKR_NO_KEYS_FOUND					0x8aa0000f

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
__declspec(dllexport) int fInitHSM(const char * inConfPath, unsigned char *passHSM, int passHSMLen);

__declspec(dllexport) int fsignData(const char *GOSTorRSA, CK_CHAR *nkeyAlias,
			  unsigned char *hashBlob, unsigned long hashSize,
			  unsigned char *signBlob, int *signSize);
#else
int fInitHSM(const char * inConfPath, unsigned char *passHSM, int passHSMLen);

int fsignData(const char *GOSTorRSA,   CK_CHAR *nkeyAlias,
			  unsigned char *hashBlob, unsigned long hashSize,
			  unsigned char *signBlob, int *signSize);
#endif


#ifdef __cplusplus
}
#endif

#endif 
