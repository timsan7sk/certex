package certex

/*
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>

#include "cryptoki.h"
#include "pkcs11def.h"
#include "pkcs11t.h"
#include "PKICertexHSM.h"


*/
import "C"

var returnValues = map[C.CK_ULONG]string{
	// awk '/#define CKR_/{ print $3":\""$2"\"," }' pkcs11t.h
	0x00000000: "CKR_OK",
	0x00000001: "CKR_CANCEL",
	0x00000002: "CKR_HOST_MEMORY",
	0x00000003: "CKR_SLOT_ID_INVALID",
	0x00000005: "CKR_GENERAL_ERROR",
	0x00000006: "CKR_FUNCTION_FAILED",
	0x00000007: "CKR_ARGUMENTS_BAD",
	0x00000008: "CKR_NO_EVENT",
	0x00000009: "CKR_NEED_TO_CREATE_THREADS",
	0x0000000A: "CKR_CANT_LOCK",
	0x00000010: "CKR_ATTRIBUTE_READ_ONLY",
	0x00000011: "CKR_ATTRIBUTE_SENSITIVE",
	0x00000012: "CKR_ATTRIBUTE_TYPE_INVALID",
	0x00000013: "CKR_ATTRIBUTE_VALUE_INVALID",
	0x00000020: "CKR_DATA_INVALID",
	0x00000021: "CKR_DATA_LEN_RANGE",
	0x00000030: "CKR_DEVICE_ERROR",
	0x00000031: "CKR_DEVICE_MEMORY",
	0x00000032: "CKR_DEVICE_REMOVED",
	0x00000040: "CKR_ENCRYPTED_DATA_INVALID",
	0x00000041: "CKR_ENCRYPTED_DATA_LEN_RANGE",
	0x00000050: "CKR_FUNCTION_CANCELED",
	0x00000051: "CKR_FUNCTION_NOT_PARALLEL",
	0x00000054: "CKR_FUNCTION_NOT_SUPPORTED",
	0x00000060: "CKR_KEY_HANDLE_INVALID",
	0x00000062: "CKR_KEY_SIZE_RANGE",
	0x00000063: "CKR_KEY_TYPE_INCONSISTENT",
	0x00000064: "CKR_KEY_NOT_NEEDED",
	0x00000065: "CKR_KEY_CHANGED",
	0x00000066: "CKR_KEY_NEEDED",
	0x00000067: "CKR_KEY_INDIGESTIBLE",
	0x00000068: "CKR_KEY_FUNCTION_NOT_PERMITTED",
	0x00000069: "CKR_KEY_NOT_WRAPPABLE",
	0x0000006A: "CKR_KEY_UNEXTRACTABLE",
	0x00000070: "CKR_MECHANISM_INVALID",
	0x00000071: "CKR_MECHANISM_PARAM_INVALID",
	0x00000082: "CKR_OBJECT_HANDLE_INVALID",
	0x00000090: "CKR_OPERATION_ACTIVE",
	0x00000091: "CKR_OPERATION_NOT_INITIALIZED",
	0x000000A0: "CKR_PIN_INCORRECT",
	0x000000A1: "CKR_PIN_INVALID",
	0x000000A2: "CKR_PIN_LEN_RANGE",
	0x000000A3: "CKR_PIN_EXPIRED",
	0x000000A4: "CKR_PIN_LOCKED",
	0x000000B0: "CKR_SESSION_CLOSED",
	0x000000B1: "CKR_SESSION_COUNT",
	0x000000B3: "CKR_SESSION_HANDLE_INVALID",
	0x000000B4: "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
	0x000000B5: "CKR_SESSION_READ_ONLY",
	0x000000B6: "CKR_SESSION_EXISTS",
	0x000000B7: "CKR_SESSION_READ_ONLY_EXISTS",
	0x000000B8: "CKR_SESSION_READ_WRITE_SO_EXISTS",
	0x000000C0: "CKR_SIGNATURE_INVALID",
	0x000000C1: "CKR_SIGNATURE_LEN_RANGE",
	0x000000D0: "CKR_TEMPLATE_INCOMPLETE",
	0x000000D1: "CKR_TEMPLATE_INCONSISTENT",
	0x000000E0: "CKR_TOKEN_NOT_PRESENT",
	0x000000E1: "CKR_TOKEN_NOT_RECOGNIZED",
	0x000000E2: "CKR_TOKEN_WRITE_PROTECTED",
	0x000000F0: "CKR_UNWRAPPING_KEY_HANDLE_INVALID",
	0x000000F1: "CKR_UNWRAPPING_KEY_SIZE_RANGE",
	0x000000F2: "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT",
	0x00000100: "CKR_USER_ALREADY_LOGGED_IN",
	0x00000101: "CKR_USER_NOT_LOGGED_IN",
	0x00000102: "CKR_USER_PIN_NOT_INITIALIZED",
	0x00000103: "CKR_USER_TYPE_INVALID",
	0x00000104: "CKR_USER_ANOTHER_ALREADY_LOGGED_IN",
	0x00000105: "CKR_USER_TOO_MANY_TYPES",
	0x00000110: "CKR_WRAPPED_KEY_INVALID",
	0x00000112: "CKR_WRAPPED_KEY_LEN_RANGE",
	0x00000113: "CKR_WRAPPING_KEY_HANDLE_INVALID",
	0x00000114: "CKR_WRAPPING_KEY_SIZE_RANGE",
	0x00000115: "CKR_WRAPPING_KEY_TYPE_INCONSISTENT",
	0x00000120: "CKR_RANDOM_SEED_NOT_SUPPORTED",
	0x00000121: "CKR_RANDOM_NO_RNG",
	0x00000130: "CKR_DOMAIN_PARAMS_INVALID",
	0x00000150: "CKR_BUFFER_TOO_SMALL",
	0x00000160: "CKR_SAVED_STATE_INVALID",
	0x00000170: "CKR_INFORMATION_SENSITIVE",
	0x00000180: "CKR_STATE_UNSAVEABLE",
	0x00000190: "CKR_CRYPTOKI_NOT_INITIALIZED",
	0x00000191: "CKR_CRYPTOKI_ALREADY_INITIALIZED",
	0x000001A0: "CKR_MUTEX_BAD",
	0x000001A1: "CKR_MUTEX_NOT_LOCKED",
	0x000001B0: "CKR_NEW_PIN_MODE",
	0x000001B1: "CKR_NEXT_OTP",
	0x00000200: "CKR_FUNCTION_REJECTED",
	0x80000000: "CKR_VENDOR_DEFINED",

	// Certex HSM
	0x8aa00000: "CKR_KZNAC_BASE",
	0x8aa00001: "CKR_KZNAC_MEMORY_ERROR",
	0x8aa00002: "CKR_KZNAC_INIT_HSM_ERROR",
	0x8aa00003: "CKR_KZNAC_CONF_PATH_ISNULL",
	0x8aa00004: "CKR_KZNAC_RCSPLIB_OPEN",
	0x8aa00005: "CKR_KZNAC_NOF_RCSP_CONNECT",
	0x8aa00006: "CKR_KZNAC_C_GETFUNCTIONLIST",
	0x8aa00007: "CKR_KZNAC_GOST_RSA_ISNULL",
	0x8aa00008: "CKR_KZNAC_CONTAINER_ISNULL",
	0x8aa00009: "CKR_KZNAC_DATA_SIZE_ISNULL",
	0x8aa0000a: "CKR_KZNAC_NO_OUTMEM",
	0x8aa0000b: "CKR_KZNAC_TMPHASH_ISNULL",
	0x8aa0000c: "CKR_KZNAC_HASH_ISNULL",
	0x8aa0000d: "CKR_KZNAC_UNKNOWN_ALG",
	0x8aa0000e: "CKR_KZNAC_KEYID_ISNULL",
	0x8aa0000f: "CKR_NO_KEYS_FOUND",

	// Возможные ошибки при работе CERTEX с HSM
	0xFFFFFFFFFF008001: "Ошибка подключения к HSM (нет связи по сети)",
	0xFF008002:         "Не создан SSL-контекст (возможно, ошибка настроек SSL)",
	0xFF008003:         "Ошибка SSL-подключения к HSM (неверные ключи, невалидные сертификаты и т.д.)",
	0xFF008004:         "Ошибка DN-имени владельца сертификата",
	0xFF008005:         "Ошибка отправки запроса команды",
	0xFF008006:         "Ошибка получения ответа команды",
	0xFF008007:         "Ошибочный формат данных ответа",
	0xFF008008:         "Ошибка в параметрах команд",
	0xFF008009:         "Ошибка выполнения команды Bind (запрос на соединение)",
	0xFFFFFFFFFF00800A: "Ошибка загрузки/чтения файла конфигурации rcsp.conf (по умолчанию размещен в каталоге /etc)",
	0xFF00800B:         "Нет доступных HSM",
	0xFF008028:         "ERR_SSL_PARAM 40",
	0xFF008029:         "ERR_SSL_CREATE_CTX 41",
	0xFF00802A:         "ERR_SSL_SET_OPTION 42",
	0xFF00802B:         "ERR_SSL_SET_CERT_CA 43",
	0xFF00802C:         "ERR_SSL_SET_CERT_MY 44",
	0xFF00802D:         "ERR_SSL_SET_PKEY 45",
	0xFF00802F:         "ERR_SSL_SESSION_CLOSE 47",
	0xFF008030:         "ERR_SSL_CONNECT 48",
	0xFF008031:         "ERR_SSL_ACCEPT 49",
	0xFF008032:         "ERR_SSL_CREATE_SSL 50",
	0xFF008033:         "ERR_SSL_SET_FD 51",
	0xFF008034:         "ERR_SSL_IO 52",
	0xFF008035:         "ERR_SSL_LOAD_LIB 53",
	0xFF008036:         "ERR_SSL_CHECK_PKEY 54",
	0xFF002007:         "Истекло время ожидания ответа",
	0xFF002008:         "(3005 для SCEP) Библиотека rcsp_HSMx64 применена к HSMx32",
}
