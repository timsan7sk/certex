#ifndef _PKCS11_DEF_
#define _PKCS11_DEF_

#ifdef __cplusplus
extern "C" {
#endif



/* Define CRYPTOKI_EXPORTS during the build of cryptoki libraries. Do
 * not define it in applications.
 */
#ifdef WIN32
/* Ensures the calling convention for Win32 builds */
#define CK_CALL_SPEC __cdecl
/* Specifies that the function is a DLL entry point. */
#define CK_IMPORT_SPEC __declspec(dllimport)
#ifdef CRYPTOKI_EXPORTS
/* Specified that the function is an exported DLL entry point. */
#define CK_EXPORT_SPEC __declspec(dllexport) 
#else
#define CK_EXPORT_SPEC CK_IMPORT_SPEC 
#endif
#else
#define CK_EXPORT_SPEC
#define CK_IMPORT_SPEC
#define CK_CALL_SPEC
#endif

#define CK_PTR *

//#define CK_DEFINE_FUNCTION(returnType, name) returnType CK_EXPORT_SPEC CK_CALL_SPEC name

//#define CK_DECLARE_FUNCTION(returnType, name) returnType CK_EXPORT_SPEC CK_CALL_SPEC name

//#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType CK_IMPORT_SPEC (CK_CALL_SPEC CK_PTR name)

//#define CK_CALLBACK_FUNCTION(returnType, name) returnType (CK_CALL_SPEC CK_PTR name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif


#define CERTEX_DEF_BASE						0x8E000000


/* Certex HSM certificate*/

#define CKC_CERTEX_HSM_CA	 		          (CERTEX_DEF_BASE + 0x00000001)
#define CKC_CERTEX_HSM_SRV	 		        (CERTEX_DEF_BASE + 0x00000002)


/* Key types: */

	/* GOST 28147.89 */
#define CKK_CERTEX_GOST_28147_89				(CERTEX_DEF_BASE + 0x00000001)

/* RDS - GOST R 34.10-2001 */
#define CKK_CERTEX_RDS                  (CERTEX_DEF_BASE + 0x00000002)
	
	

/*  Attributes: */
#define CKA_CERTEX_GET_LOG_LEVEL				(CERTEX_DEF_BASE + 0x00000000)
#define CKA_CERTEX_SET_LOG_LEVEL				(CERTEX_DEF_BASE + 0x00000001)

// of type CK_CERTEX_DATETIME
#define CKA_CERTEX_KEY_GENERATION_DATE  (CERTEX_DEF_BASE + 0x00000002)
	
/* Substitution block for GOST 28147.89   */
#define CKA_CERTEX_SBLOCK               (CERTEX_DEF_BASE + 0x00000003)


/* GOST R 34.10-2001 attributes: */
#define CKA_CERTEX_RDS_PRM_P					(CERTEX_DEF_BASE + 0x0000000B)
#define CKA_CERTEX_RDS_PRM_A					(CERTEX_DEF_BASE + 0x0000000C)
#define CKA_CERTEX_RDS_PRM_B					(CERTEX_DEF_BASE + 0x0000000D)
#define CKA_CERTEX_RDS_PRM_Q					(CERTEX_DEF_BASE + 0x0000000E)
#define CKA_CERTEX_RDS_PRM_X					(CERTEX_DEF_BASE + 0x0000000F)
#define CKA_CERTEX_RDS_PRM_Y					(CERTEX_DEF_BASE + 0x00000010)
#define CKA_CERTEX_RDS_TYPE 					(CERTEX_DEF_BASE + 0x00000011)

/* Mechanisms */

/* GOST 28147.89 */
#define CKM_CERTEX_GOST_28147_89_KEY_GEN              (CERTEX_DEF_BASE + 0x00000000)
#define CKM_CERTEX_GOST_28147_89_ECB	                (CERTEX_DEF_BASE + 0x00000001)
#define CKM_CERTEX_GOST_28147_89_OFB    	            (CERTEX_DEF_BASE + 0x00000002)
#define CKM_CERTEX_GOST_28147_89_CFB        	        (CERTEX_DEF_BASE + 0x00000003)
#define CKM_CERTEX_GOST_28147_89_MAC            	    (CERTEX_DEF_BASE + 0x00000004)
	            

/* Hash for GOST R 34.11-94 / 2012 */               
#define CKM_CERTEX_GOSTR3411                              (CERTEX_DEF_BASE + 0x0000000A)              // соответствует  "1.2.398.3.10.1.3.1.1.0"
#define CKM_CERTEX_GOSTR3411_2012_32                       (CERTEX_DEF_BASE + 0x00000010)    // соответствует  "1.2.398.3.10.1.3.2"
#define CKM_CERTEX_GOSTR3411_2012_64                       (CERTEX_DEF_BASE + 0x00000011)    // соответствует  "1.2.398.3.10.1.3.3"


/* GOST R 34.10-2001/2012  keypair generation mechanism */
#define CKM_CERTEX_GOSTR3410_2001_KEY_PAIR_GEN          (CERTEX_DEF_BASE + 0x0000000B)
#define CKM_CERTEX_GOSTR3410_2012_KEY_PAIR_GEN          (CERTEX_DEF_BASE + 0x00000012)


/* GOST R 34.10-2001/2012 'raw' mechanism */
#define CKM_CERTEX_GOSTR3410_2001                       (CERTEX_DEF_BASE + 0x0000000C)     // соответствует "1.2.398.3.10.1.1.1.2"
#define CKM_CERTEX_GOSTR3410_2012                       (CERTEX_DEF_BASE + 0x00000013)     // соответствует "1.2.398.3.10.1.1.2.3"
#define CKM_CERTEX_GOSTR3410_2015                       CKM_CERTEX_GOSTR3410_2012


/* GOST R 34.11-94(2012) hash with GOST R 34.10-2001/2012 mechanism */
#define CKM_CERTEX_GOSTR3411_94_GOSTR3410_2001         (CERTEX_DEF_BASE + 0x0000000D)    
#define CKM_CERTEX_GOSTR3411_GOSTR3410_2012            (CERTEX_DEF_BASE + 0x00000014)        
#define CKM_CERTEX_GOSTR3411_GOSTR3410_2015            CKM_CERTEX_GOSTR3411_GOSTR3410_2012   

 
 	

/* CK_CERTEX_DATETIME is a structure that defines a date and time */
typedef struct CK_CERTEX_DATETIME{
  CK_CHAR       year[4];     /* the year    ("1900" - "9999") */
  CK_CHAR       month[2];    /* the month   ("01" - "12") */
  CK_CHAR       day[2];      /* the day     ("01" - "31") */
  CK_CHAR       hour[2];     /* the hours   ("00" - "23") */
  CK_CHAR       minute[2];   /* the minutes ("00" - "59") */
  CK_CHAR       second[2];   /* the seconds ("00" - "59") */
} CK_CERTEX_DATETIME;

/* Pointer for  CK_CERTEX_DATETIME */
typedef CK_CERTEX_DATETIME CK_PTR CK_CERTEX_DATETIME_PTR;


/* GOST R 34.11-94   Mechanism parameter structure */
typedef struct CK_CERTEX_RHF_PARAM {
	  CK_BYTE_PTR   pSBox;           // S-Box for digest (128 bytes)
	  CK_ULONG      SBoxLength;      // 0 or 128
	  CK_BYTE_PTR   pH0;             // Start digest value (32 bytes)
	  CK_ULONG      H0Length;        // 0 or 32
} CK_CERTEX_RHF_PARAM;

/* Pointer for  CK_CERTEX_RHF_PARAM */
typedef CK_CERTEX_RHF_PARAM CK_PTR CK_CERTEX_RHF_PARAM_PTR;

	
/* Token Functions  */


CK_RV CK_EXPORT_SPEC CK_CALL_SPEC CERTEX_TokenParameters
(
	CK_SESSION_HANDLE hSession,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount 
);


typedef CK_RV (CK_CALL_SPEC *CK_CERTEX_TokenParameters)
(
	CK_SESSION_HANDLE hSession,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount 
);


CK_RV CK_EXPORT_SPEC CK_CALL_SPEC CERTEX_GetTokenLog(
  CK_SLOT_ID     slotID,       /* ID of the token's slot */
  CK_CHAR_PTR    pPin,         /* the SO's PIN */
  CK_ULONG       ulPinLen,     /* length in bytes of the PIN */
  CK_VOID_PTR    pBuffer,      /* Buffer to read token log */
  CK_ULONG_PTR   pulBufferLen   /* in bytes */
);

typedef CK_RV (CK_CALL_SPEC *CK_CERTEX_GetTokenLog)
(
  CK_SLOT_ID     slotID,       /* ID of the token's slot */
  CK_CHAR_PTR    pPin,         /* the SO's PIN */
  CK_ULONG       ulPinLen,     /* length in bytes of the PIN */
  CK_VOID_PTR    pBuffer,      /* Buffer to read token log */
  CK_ULONG_PTR   ulBufferLen   /* in bytes */
);


#ifdef __cplusplus
}
#endif

#endif 
