#ifndef _CRYPTOKI_H_
#define _CRYPTOKI_H_


#ifndef CK_PTR
#define CK_PTR *
#endif
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#ifndef CK_CALLBACK_FUNCTION
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#endif
#ifndef CK_DEFINE_FUNCTION
#define CK_DEFINE_FUNCTION(returnType, name)           returnType name
#endif
#ifndef CK_DECLARE_FUNCTION
#define CK_DECLARE_FUNCTION(returnType, name)          returnType name
#endif
#ifndef CK_DECLARE_FUNCTION_POINTER
#define CK_DECLARE_FUNCTION_POINTER(returnType, name)  returnType (* name)
#endif


#include "pkcs11.h"
/*#ifndef HINSTANCE
#define HINSTANCE void*
#endif*/

#endif
