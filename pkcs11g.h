//------------------------------------------------------------------------------
// Tumar CSP
// Copyright (c) 2009 Scientific Lab. Gamma Technologies. All rights reserved.
//
// Definitions for PKCS11 API
//------------------------------------------------------------------------------
#ifndef _PKCS11G_H_
#define _PKCS11G_H_
//------------------------------------------------------------------------------
#define CK_GAMMA_VENDOR_DEFINED               0x0F000000
//------------------------------------------------------------------------------
#define CKA_TUM_DEFINED                      (CKA_VENDOR_DEFINED | CK_GAMMA_VENDOR_DEFINED)
#define CKA_TUM_KEY_OID                      (CKA_TUM_DEFINED + 1)
#define CKA_TUM_KEY_STATE                    (CKA_TUM_DEFINED + 2)
//------------------------------------------------------------------------------
#define CKK_TUM_DEFINED                      (CKK_VENDOR_DEFINED | CK_GAMMA_VENDOR_DEFINED)
#define CKK_TUMAR                            (CKK_TUM_DEFINED + 1)
#define CKK_TUM_GOST28147                    (CKK_TUM_DEFINED + 2)
#define CKK_TUM_GOST3410                     (CKK_TUM_DEFINED + 3)
#define CKK_NONE                              0xFFFFFFFF
//------------------------------------------------------------------------------
#define CKM_TUM_DEFINED                      (CKM_VENDOR_DEFINED | CK_GAMMA_VENDOR_DEFINED)

#define CKM_TUM_DH_DERIVE                    (CKM_TUM_DEFINED + 98)
#define CKM_TUM_DH_DERIVE_VKO                (CKM_TUM_DEFINED + 99)

#define CKM_TUM_GR3410                       (CKM_TUM_DEFINED + 100)

#define CKM_TUM_EXCH_KEY_GEN_DH256_1024_A    (CKM_TUM_DEFINED + 502)
#define CKM_TUM_EXCH_KEY_GEN_DH256_1024_B    (CKM_TUM_DEFINED + 503)
#define CKM_TUM_EXCH_KEY_GEN_DH256_1024_C    (CKM_TUM_DEFINED + 504)
#define CKM_TUM_EXCH_KEY_GEN_DH512_512T      (CKM_TUM_DEFINED + 506)
#define CKM_TUM_EXCH_KEY_GEN_EC256_512G_A    (CKM_TUM_DEFINED + 510)
#define CKM_TUM_EXCH_KEY_GEN_EC256_512G_B    (CKM_TUM_DEFINED + 511)
#define CKM_TUM_EXCH_KEY_GEN_EC256_512F      (CKM_TUM_DEFINED + 512)
#define CKM_TUM_EXCH_KEY_GEN_EC384_768F      (CKM_TUM_DEFINED + 514)
#define CKM_TUM_EXCH_KEY_GEN_EC521_1042F     (CKM_TUM_DEFINED + 515)

#define CKM_RSA_PKCS_KEY_PAIR_GEN_X          (CKM_TUM_DEFINED + 520)

#define CKM_TUM_SIGN_KEY_GEN_DH256_1024_T    (CKM_TUM_DEFINED + 601)
#define CKM_TUM_SIGN_KEY_GEN_DH256_1024_A    (CKM_TUM_DEFINED + 602)
#define CKM_TUM_SIGN_KEY_GEN_DH256_1024_B    (CKM_TUM_DEFINED + 603)
#define CKM_TUM_SIGN_KEY_GEN_DH256_1024_C    (CKM_TUM_DEFINED + 604)
#define CKM_TUM_SIGN_KEY_GEN_DH256_1024_D    (CKM_TUM_DEFINED + 605)
#define CKM_TUM_SIGN_KEY_GEN_DH512_512T      (CKM_TUM_DEFINED + 606)
#define CKM_TUM_SIGN_KEY_GEN_EC160_320F      (CKM_TUM_DEFINED + 607)
#define CKM_TUM_SIGN_KEY_GEN_EC192_384F      (CKM_TUM_DEFINED + 608)
#define CKM_TUM_SIGN_KEY_GEN_EC224_448F      (CKM_TUM_DEFINED + 609)
#define CKM_TUM_SIGN_KEY_GEN_EC256_512G_A    (CKM_TUM_DEFINED + 610)
#define CKM_TUM_SIGN_KEY_GEN_EC256_512G_B    (CKM_TUM_DEFINED + 611)
#define CKM_TUM_SIGN_KEY_GEN_EC256_512G_C    (CKM_TUM_DEFINED + 612)
#define CKM_TUM_SIGN_KEY_GEN_EC256_512F      (CKM_TUM_DEFINED + 613)
#define CKM_TUM_SIGN_KEY_GEN_EC384_768F      (CKM_TUM_DEFINED + 614)
#define CKM_TUM_SIGN_KEY_GEN_EC521_1042F     (CKM_TUM_DEFINED + 615)

#define CKM_TUM_KEY_GEN_RC2                  CKM_RC2_KEY_GEN
#define CKM_TUM_CRYPT_RC2_ECB                CKM_RC2_ECB
#define CKM_TUM_CRYPT_RC2_OFB                (CKM_TUM_DEFINED + 302)
#define CKM_TUM_CRYPT_RC2_CNT                (CKM_TUM_DEFINED + 303)
#define CKM_TUM_CRYPT_RC2_CFB                (CKM_TUM_DEFINED + 304)
#define CKM_TUM_CRYPT_RC2_CBC                CKM_RC2_CBC
#define CKM_TUM_CRYPT_RC2_CBC_PAD            CKM_RC2_CBC_PAD
#define CKM_TUM_CRYPT_RC2_MAC                CKM_RC2_MAC
#define CKM_TUM_CRYPT_RC2_MAC_GENERAL        CKM_RC2_MAC_GENERAL

#define CKM_TUM_KEY_GEN_RC4                  CKM_RC4_KEY_GEN
#define CKM_TUM_CRYPT_RC4                    CKM_RC4

#define CKM_TUM_KEY_GEN_RC5                  CKM_RC5_KEY_GEN
#define CKM_TUM_CRYPT_RC5_ECB                CKM_RC5_ECB
#define CKM_TUM_CRYPT_RC5_OFB                (CKM_TUM_DEFINED + 322)
#define CKM_TUM_CRYPT_RC5_CNT                (CKM_TUM_DEFINED + 323)
#define CKM_TUM_CRYPT_RC5_CFB                (CKM_TUM_DEFINED + 324)
#define CKM_TUM_CRYPT_RC5_CBC                CKM_RC5_CBC
#define CKM_TUM_CRYPT_RC5_CBC_PAD            CKM_RC5_CBC_PAD
#define CKM_TUM_CRYPT_RC5_MAC                CKM_RC5_MAC
#define CKM_TUM_CRYPT_RC5_MAC_GENERAL        CKM_RC5_MAC_GENERAL

#define CKM_TUM_KEY_GEN_DES                  CKM_DES_KEY_GEN
#define CKM_TUM_CRYPT_DES_ECB                CKM_DES_ECB
#define CKM_TUM_CRYPT_DES_OFB                (CKM_TUM_DEFINED + 332)
#define CKM_TUM_CRYPT_DES_CNT                (CKM_TUM_DEFINED + 333)
#define CKM_TUM_CRYPT_DES_CFB                (CKM_TUM_DEFINED + 334)
#define CKM_TUM_CRYPT_DES_CBC                CKM_DES_CBC
#define CKM_TUM_CRYPT_DES_CBC_PAD            CKM_DES_CBC_PAD
#define CKM_TUM_CRYPT_DES_MAC                CKM_DES_MAC
#define CKM_TUM_CRYPT_DES_MAC_GENERAL        CKM_DES_MAC_GENERAL
#define CKM_TUM_CRYPT_DES_X919_MAC           (CKM_TUM_DEFINED + 339)
#define CKM_TUM_CRYPT_DES_X919_MAC_GENERAL   (CKM_TUM_DEFINED + 340)

#define CKM_TUM_KEY_GEN_DES2                 CKM_DES2_KEY_GEN
#define CKM_TUM_KEY_GEN_DES3                 CKM_DES3_KEY_GEN
#define CKM_TUM_CRYPT_DES3_ECB               CKM_DES3_ECB
#define CKM_TUM_CRYPT_DES3_OFB               (CKM_TUM_DEFINED + 352)
#define CKM_TUM_CRYPT_DES3_CNT               (CKM_TUM_DEFINED + 353)
#define CKM_TUM_CRYPT_DES3_CFB               (CKM_TUM_DEFINED + 354)
#define CKM_TUM_CRYPT_DES3_CBC               CKM_DES3_CBC
#define CKM_TUM_CRYPT_DES3_CBC_PAD           CKM_DES3_CBC_PAD
#define CKM_TUM_CRYPT_DES3_MAC               CKM_DES3_MAC
#define CKM_TUM_CRYPT_DES3_MAC_GENERAL       CKM_DES3_MAC_GENERAL

#define CKM_TUM_KEY_GEN_AES                  CKM_AES_KEY_GEN
#define CKM_TUM_CRYPT_AES_ECB                CKM_AES_ECB
#define CKM_TUM_CRYPT_AES_OFB                (CKM_TUM_DEFINED + 102)
#define CKM_TUM_CRYPT_AES_CNT                CKM_AES_CTR
#define CKM_TUM_CRYPT_AES_CFB                (CKM_TUM_DEFINED + 104)
#define CKM_TUM_CRYPT_AES_CBC                CKM_AES_CBC
#define CKM_TUM_CRYPT_AES_CBC_PAD            CKM_AES_CBC_PAD
#define CKM_TUM_CRYPT_AES_MAC                CKM_AES_MAC
#define CKM_TUM_CRYPT_AES_MAC_GENERAL        CKM_AES_MAC_GENERAL

#define CKM_TUM_KEY_GEN_GOST                 (CKM_TUM_DEFINED + 95)
#define CKM_TUM_KEY_GEN_TUMAR                (CKM_TUM_DEFINED + 96)

#define CKM_TUM_CRYPT_TUMAR_ECB              (CKM_TUM_DEFINED + 111)
#define CKM_TUM_CRYPT_TUMAR_OFB              (CKM_TUM_DEFINED + 112)
#define CKM_TUM_CRYPT_TUMAR_CNT              (CKM_TUM_DEFINED + 113)
#define CKM_TUM_CRYPT_TUMAR_CFB              (CKM_TUM_DEFINED + 114)
#define CKM_TUM_CRYPT_TUMAR_CBC              (CKM_TUM_DEFINED + 115)
#define CKM_TUM_CRYPT_TUMAR_CBC_PAD          (CKM_TUM_DEFINED + 116)
#define CKM_TUM_CRYPT_TUMAR_MAC              (CKM_TUM_DEFINED + 117)
#define CKM_TUM_CRYPT_TUMAR_MAC_GENERAL      (CKM_TUM_DEFINED + 118)

#define CKM_TUM_CRYPT_GOST_G_ECB             (CKM_TUM_DEFINED + 121)
#define CKM_TUM_CRYPT_GOST_G_OFB             (CKM_TUM_DEFINED + 122)
#define CKM_TUM_CRYPT_GOST_G_CNT             (CKM_TUM_DEFINED + 123)
#define CKM_TUM_CRYPT_GOST_G_CFB             (CKM_TUM_DEFINED + 124)
#define CKM_TUM_CRYPT_GOST_G_CBC             (CKM_TUM_DEFINED + 125)
#define CKM_TUM_CRYPT_GOST_G_CBC_PAD         (CKM_TUM_DEFINED + 126)
#define CKM_TUM_CRYPT_GOST_G_MAC             (CKM_TUM_DEFINED + 127)
#define CKM_TUM_CRYPT_GOST_G_MAC_GENERAL     (CKM_TUM_DEFINED + 128)
#define CKM_TUM_CRYPT_GOST_G_MAC_OLD         (CKM_TUM_DEFINED + 298)
#define CKM_TUM_CRYPT_GOST_G_MAC_OLD_GENERAL (CKM_TUM_DEFINED + 299)

#define CKM_TUM_CRYPT_GOST_A_ECB             (CKM_TUM_DEFINED + 131)
#define CKM_TUM_CRYPT_GOST_A_OFB             (CKM_TUM_DEFINED + 132)
#define CKM_TUM_CRYPT_GOST_A_CNT             (CKM_TUM_DEFINED + 133)
#define CKM_TUM_CRYPT_GOST_A_CFB             (CKM_TUM_DEFINED + 134)
#define CKM_TUM_CRYPT_GOST_A_CBC             (CKM_TUM_DEFINED + 135)
#define CKM_TUM_CRYPT_GOST_A_CBC_PAD         (CKM_TUM_DEFINED + 136)
#define CKM_TUM_CRYPT_GOST_A_MAC             (CKM_TUM_DEFINED + 137)
#define CKM_TUM_CRYPT_GOST_A_MAC_GENERAL     (CKM_TUM_DEFINED + 138)

#define CKM_TUM_CRYPT_GOST_B_ECB             (CKM_TUM_DEFINED + 141)
#define CKM_TUM_CRYPT_GOST_B_OFB             (CKM_TUM_DEFINED + 142)
#define CKM_TUM_CRYPT_GOST_B_CNT             (CKM_TUM_DEFINED + 143)
#define CKM_TUM_CRYPT_GOST_B_CFB             (CKM_TUM_DEFINED + 144)
#define CKM_TUM_CRYPT_GOST_B_CBC             (CKM_TUM_DEFINED + 145)
#define CKM_TUM_CRYPT_GOST_B_CBC_PAD         (CKM_TUM_DEFINED + 146)
#define CKM_TUM_CRYPT_GOST_B_MAC             (CKM_TUM_DEFINED + 147)
#define CKM_TUM_CRYPT_GOST_B_MAC_GENERAL     (CKM_TUM_DEFINED + 148)

#define CKM_TUM_CRYPT_GOST_C_ECB             (CKM_TUM_DEFINED + 151)
#define CKM_TUM_CRYPT_GOST_C_OFB             (CKM_TUM_DEFINED + 152)
#define CKM_TUM_CRYPT_GOST_C_CNT             (CKM_TUM_DEFINED + 153)
#define CKM_TUM_CRYPT_GOST_C_CFB             (CKM_TUM_DEFINED + 154)
#define CKM_TUM_CRYPT_GOST_C_CBC             (CKM_TUM_DEFINED + 155)
#define CKM_TUM_CRYPT_GOST_C_CBC_PAD         (CKM_TUM_DEFINED + 156)
#define CKM_TUM_CRYPT_GOST_C_MAC             (CKM_TUM_DEFINED + 157)
#define CKM_TUM_CRYPT_GOST_C_MAC_GENERAL     (CKM_TUM_DEFINED + 158)

#define CKM_TUM_CRYPT_GOST_D_ECB             (CKM_TUM_DEFINED + 161)
#define CKM_TUM_CRYPT_GOST_D_OFB             (CKM_TUM_DEFINED + 162) 
#define CKM_TUM_CRYPT_GOST_D_CNT             (CKM_TUM_DEFINED + 163)
#define CKM_TUM_CRYPT_GOST_D_CFB             (CKM_TUM_DEFINED + 164)
#define CKM_TUM_CRYPT_GOST_D_CBC             (CKM_TUM_DEFINED + 165)
#define CKM_TUM_CRYPT_GOST_D_CBC_PAD         (CKM_TUM_DEFINED + 166)
#define CKM_TUM_CRYPT_GOST_D_MAC             (CKM_TUM_DEFINED + 167)
#define CKM_TUM_CRYPT_GOST_D_MAC_GENERAL     (CKM_TUM_DEFINED + 168)

#define CKM_TUM_CRYPT_ELGAMAL                (CKM_TUM_DEFINED + 190)
#define CKM_TUM_CRYPT_ELGAMAL_PAD            (CKM_TUM_DEFINED + 191)

#define CKM_TUM_HASH_MD2                     CKM_MD2
#define CKM_TUM_HASH_MD2_HMAC                CKM_MD2_HMAC
#define CKM_TUM_HASH_MD2_HMAC_GENERAL        CKM_MD2_HMAC_GENERAL

#define CKM_TUM_HASH_MD4                     (CKM_TUM_DEFINED + 206)
#define CKM_TUM_HASH_MD4_HMAC                (CKM_TUM_DEFINED + 207)
#define CKM_TUM_HASH_MD4_HMAC_GENERAL        (CKM_TUM_DEFINED + 208)

#define CKM_TUM_HASH_MD5                     CKM_MD5
#define CKM_TUM_HASH_MD5_HMAC                CKM_MD5_HMAC
#define CKM_TUM_HASH_MD5_HMAC_GENERAL        CKM_MD5_HMAC_GENERAL

#define CKM_TUM_HASH_SHA_1                   CKM_SHA_1
#define CKM_TUM_HASH_SHA_1_HMAC              CKM_SHA_1_HMAC
#define CKM_TUM_HASH_SHA_1_HMAC_GENERAL      CKM_SHA_1_HMAC_GENERAL

#define CKM_TUM_HASH_SHA_256                 CKM_SHA256
#define CKM_TUM_HASH_SHA_256_HMAC            CKM_SHA256_HMAC
#define CKM_TUM_HASH_SHA_256_HMAC_GENERAL    CKM_SHA256_HMAC_GENERAL

#define CKM_TUM_HASH_SHA_384                 CKM_SHA384
#define CKM_TUM_HASH_SHA_384_HMAC            CKM_SHA384_HMAC
#define CKM_TUM_HASH_SHA_384_HMAC_GENERAL    CKM_SHA384_HMAC_GENERAL

#define CKM_TUM_HASH_SHA_512                 CKM_SHA512
#define CKM_TUM_HASH_SHA_512_HMAC            CKM_SHA512_HMAC
#define CKM_TUM_HASH_SHA_512_HMAC_GENERAL    CKM_SHA512_HMAC_GENERAL

#define CKM_TUM_HASH_TUMAR                   (CKM_TUM_DEFINED + 261)

#define CKM_TUM_HASH_GOST                    (CKM_TUM_DEFINED + 271)
#define CKM_TUM_HASH_GOST_HMAC               (CKM_TUM_DEFINED + 272)
#define CKM_TUM_HASH_GOST_HMAC_GENERAL       (CKM_TUM_DEFINED + 273)

#define CKM_TUM_HASH_GOSTCP                  (CKM_TUM_DEFINED + 281)
#define CKM_TUM_HASH_GOSTCP_HMAC             (CKM_TUM_DEFINED + 282)
#define CKM_TUM_HASH_GOSTCP_HMAC_GENERAL     (CKM_TUM_DEFINED + 283)

#define CKM_TUM_SIGN_R3410                   (CKM_TUM_DEFINED + 700)
#define CKM_TUM_SIGN_MD2_R3410               (CKM_TUM_DEFINED + 701)
#define CKM_TUM_SIGN_MD4_R3410               (CKM_TUM_DEFINED + 702)
#define CKM_TUM_SIGN_MD5_R3410               (CKM_TUM_DEFINED + 703)
#define CKM_TUM_SIGN_SHA_1_R3410             (CKM_TUM_DEFINED + 704)
#define CKM_TUM_SIGN_SHA_256_R3410           (CKM_TUM_DEFINED + 705)
#define CKM_TUM_SIGN_SHA_384_R3410           (CKM_TUM_DEFINED + 706)
#define CKM_TUM_SIGN_SHA_512_R3410           (CKM_TUM_DEFINED + 707)
#define CKM_TUM_SIGN_TUMAR_R3410             (CKM_TUM_DEFINED + 708)
#define CKM_TUM_SIGN_GOST3411_R3410          (CKM_TUM_DEFINED + 709)
#define CKM_TUM_SIGN_GOST3411CP_R3410        (CKM_TUM_DEFINED + 710)

#define CKM_TUM_SIGN_MD2_RSA                 CKM_MD2_RSA_PKCS
#define CKM_TUM_SIGN_MD4_RSA                 (CKM_TUM_DEFINED + 802)
#define CKM_TUM_SIGN_MD5_RSA                 CKM_MD5_RSA_PKCS
#define CKM_TUM_SIGN_SHA_1_RSA               CKM_SHA1_RSA_PKCS
#define CKM_TUM_SIGN_SHA_256_RSA             CKM_SHA256_RSA_PKCS
#define CKM_TUM_SIGN_SHA_384_RSA             CKM_SHA384_RSA_PKCS
#define CKM_TUM_SIGN_SHA_512_RSA             CKM_SHA512_RSA_PKCS
#define CKM_TUM_SIGN_TUMAR_RSA               (CKM_TUM_DEFINED + 808)
#define CKM_TUM_SIGN_GOST3411_RSA            (CKM_TUM_DEFINED + 809)
#define CKM_TUM_SIGN_GOST3411CP_RSA          (CKM_TUM_DEFINED + 810)
//------------------------------------------------------------------------------
#endif
