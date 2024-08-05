|[![Scheme](images/nca_icon.png)](https://pki.gov.kz/)| **Go wrapper for the [Gamma Technologies](https://gamma.kz/) Cryptoki(PKCS#11) library of Certex HSM** |
|:-------------------------------------------------:|:-------------------------------------------------------------------------------------------------------|

#### Example ####
```go
const (
    // Library file name
    libName = "libcertex-rcsp_r.so.1"
	// Path to the configuration file
	confPath = "/etc/rcsp.conf"
    // PIN Code of HSM (bad practice, don't do that in production code)
    PIN    = "25032016"
    // Slot identificator
	slotID = 0
)
func init() {
	mod, err = certex.Open(libName, confPath)
	if err != nil {
		fmt.Println("Open module error: ", err)
		os.Exit(1)
	}
	mod.Lock()
	defer mod.Unlock()

	opts := certex.Options{
		PIN:       PIN,
		ReadWrite: true,
	}
	slot, err = mod.Slot(slotID, opts)
	if err != nil {
		fmt.Println("Open slot error: ", err)
		os.Exit(1)
	}
    info, _ := slot.GetSlotInfo()
    fmt.Printf("Slot Info: %+v\n", info)
}

```
#### Functionality ####
| CK_FUNCTION_LIST:      | C | Go | Test | Comment|
|:-----------------------|:-:|:--:|:----:|:-----------------------------------------------------------------------------------------------------------------------------------------|
| connect                | + | +  | +    | Connectiong to the Certex HSM|
| C_Initialize:          | + | +  | +    | Initializes the Cryptoki library.|
| C_Finalize:            | + | +  | +    | Indicates that an application is done with the Cryptoki library.|
| C_GetInfo:             | + | +  | +    | Returns general information about Cryptoki.|
| C_GetFunctionList:     | + | +  | +    | Returns the function list.|
| C_GetSlotList:         | + | +  | +    | Obtains a list of slots in the system.|
| C_GetSlotInfo:         | + | +  | +    | Obtains information about a particular slot in the system.|
| C_GetTokenInfo:        | + | +  | +    | Obtains information about a particular token in the system.|
| C_GetMechanismList:    | + | +  | +    | Obtains a list of mechanism types supported by a token|
| C_GetMechanismInfo:    | + | +  | +    | Obtains information about a particular mechanism possibly supported by a token.|
| C_InitToken:           | + | +  | -    | Initializes a token.|
| C_InitPIN:             | + | +  | -    | Initializes the normal user's pin.|
| C_SetPIN:              | + | +  | +    | Modifies the pin of the user who is logged in.|
| C_OpenSession:         | + | +  | +    | Opens a session between an application and a token.|
| C_CloseSession:        | + | +  | +    | Closes a session between an application and a token.|
| C_CloseAllSessions:    | + | +  | +    | Closes all sessions with a token.|
| C_GetSessionInfo:      | + | +  | +    | Obtains information about the session.|
| C_GetOperationState:   | + | +  | -    | Obtains the state of the cryptographic operation in a session.|
| C_SetOperationState:   | + | +  | -    | Restores the state of the cryptographic operation in a session.|
| C_Login:               | + | +  | +    | Logs a user into a token.|
| C_Logout:              | + | +  | +    | Logs a user out from a token.|
| C_CreateObject:        | + | +  | +    | Creates a new object.|
| C_CopyObject:          | + | +  | -    | Copies an object, creating a new object for the copy.|
| C_DestroyObject:       | + | +  | +    | Destroys an object.|
| C_GetObjectSize:       | + | +  | +    | Gets the size of an object in bytes.|
| C_GetAttributeValue:   | + | +  | -    | Obtains the value of one or more object attributes.|
| C_SetAttributeValue:   | + | +  | -    | Modifies the value of one or more object attributes.|
| C_FindObjectsInit:     | + | +  | +    | Initializes a search for token and session objects that match a template.|
| C_FindObjects:         | + | +  | +    | Continues a search for token and session objects that match a template, obtaining additional object handles.|
| C_FindObjectsFinal:    | + | +  | +    | Finishes a search for token and session objects.|
| C_EncryptInit:         | + | +  | +    | Initializes an encryption operation.|
| C_Encrypt:             | + | +  | +    | Encrypts single-part data.|
| C_EncryptUpdate:       | + | +  | -    | Continues a multiple-part encryption operation.|
| C_EncryptFinal:        | + | +  | -    | Finishes a multiple-part encryption operation.|
| C_DecryptInit:         | + | +  | -    | Initializes a decryption operation.|
| C_Decrypt:             | + | +  | -    | Decrypts encrypted data in a single part.|
| C_DecryptUpdate:       | + | +  | -    | Continues a multiple-part decryption operation.|
| C_DecryptFinal:        | + | +  | -    | Finishes a multiple-part decryption operation.|
| C_DigestInit:          | + | +  | +    | Initializes a message-digesting operation.|
| C_Digest:              | + | +  | +    | Digests data in a single part.|
| C_DigestUpdate:        | + | +  | +    | Continues a multiple-part message-digesting operation.|
| C_DigestKey:           | + | +  | -    | Continues a multi-part message-digesting operation, by digesting the value of a secret key as part of the data already digested.|
| C_DigestFinal:         | + | +  | +    | Finishes a multiple-part message-digesting operation.
| C_SignInit:            | + | +  | +    | Initializes a signature (private key encryption) operation, where the signature is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.|
| C_Sign:                | + | +  | +    | Signs (encrypts with private key) data in a single part, where the signature is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.|
| C_SignUpdate:          | + | +  | +    | Continues a multiple-part signature operation, where the signature is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.|
| C_SignFinal:           | + | +  | +    | Finishes a multiple-part signature operation, returning the signature.|
| C_SignRecoverInit:     | + | +  | +    | Initializes a signature operation, where the data can be recovered from the signature.|
| C_SignRecover:         | + | +  | +    | Signs data in a single operation, where the data can be recovered from the signature.|
| C_VerifyInit:          | + | +  | +    | Initializes a verification operation, where the signature is an appendix to the data, and plaintext cannot be recovered from the signature (e.g. DSA).|
| C_Verify:              | + | +  | +    | Verifies a signature in a single-part operation, where the signature is an appendix to the data, and plaintext cannot be recovered from the signature.|
| C_VerifyUpdate:        | + | +  | -    | Continues a multiple-part verification operation, where the signature is an appendix to the data, and plaintext cannot be recovered from the signature.|
| C_VerifyFinal:         | + | +  | -    | Finishes a multiple-part verification operation, checking the signature.|
| C_VerifyRecoverInit:   | + | +  | +    | Initializes a signature verification operation, where the data is recovered from the signature.|
| C_VerifyRecover:       | + | +  | +    | Verifies a signature in a single-part operation, where the data is recovered from the signature.|
| C_DigestEncryptUpdate: | + | +  | -    | Continues a multiple-part digesting and encryption operation.|
| C_DecryptDigestUpdate: | + | +  | -    | Continues a multiple-part decryption and digesting operation.|
| C_SignEncryptUpdate:   | + | +  | -    | Continues a multiple-part signing and encryption operation.|
| C_DecryptVerifyUpdate: | + | +  | -    | Continues a multiple-part decryption and verify operation.|
| C_GenerateKey:         | + | +  | +    | Generates a secret key, creating a new key object.|
| C_GenerateKeyPair:     | + | +  | +    | Generates a public-key/private-key pair, creating new key objects.|
| C_WrapKey:             | + | +  | -    | Wraps (i.e., encrypts) a key.|
| C_UnwrapKey:           | + | +  | -    | Unwraps (decrypts) a wrapped key, creating a new key object.|
| C_DeriveKey:           | + | +  | -    | Derives a key from a base key, creating a new key object.|
| C_SeedRandom:          | + | +  | +    | Mixes additional seed material into the token's random number generator.|
| C_GenerateRandom:      | + | +  | +    | Generates random data.|
| C_GetFunctionStatus:   | + | -  | -    | Legacy function; it obtains an updated status of a function running in parallel with an application.|
| C_CancelFunction:      | + | -  | -    | Legacy function; it cancels a function running in parallel.|
| C_WaitForSlotEvent:    | + | +  | -    | Waits for a slot event (token insertion, removal, etc.) to occur.|