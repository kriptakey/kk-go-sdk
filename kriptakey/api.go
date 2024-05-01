package kriptakey

/*
#include <stdint.h>
#include <stdlib.h>

#cgo LDFLAGS: -ldl -lkk-core

#define SG_FAULTCODE_T uint32_t

typedef void* OpaqueConnectionHandlerPtr;
typedef void* OpaqueOutputPtr;

typedef size_t (*AssignerCallback)(void*, size_t, void**);
int32_t kk_gosdk_assign(void*, int32_t, void*);

SG_FAULTCODE_T kk_nativesdk_initializeConnection(char const* host, uint16_t port,
	char const* clientCertificatePath, char const* privateKeyPath,
	OpaqueConnectionHandlerPtr* connectionData);
SG_FAULTCODE_T kk_nativesdk_initializeWithCertificatePEMBuffer(char const* host, uint16_t port,
	char const* clientCertificate, char const* privateKey,
	OpaqueConnectionHandlerPtr* connectionData);

void kk_nativesdk_freeConnection(OpaqueConnectionHandlerPtr connectionData);

SG_FAULTCODE_T kk_nativesdk_login(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* password, OpaqueOutputPtr allocatedPtr, AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_refreshSession(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, OpaqueOutputPtr allocatedPtr,
	AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_generateRandomNumber(OpaqueConnectionHandlerPtr const connectionData,
	uint32_t slotId, char const* sessionToken, uint32_t length,
	OpaqueOutputPtr allocatedPtr, AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_generateMAC(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* keyId, char const* hashAlgo,
	char const** dataVec, size_t dataVecSize, OpaqueOutputPtr allocatedPtr,
	AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_verifyMAC(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* keyId, char const* hashAlgo,
	uint8_t const* serializedRequest, size_t serializedRequestSize,
	OpaqueOutputPtr allocatedPtr, AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_encrypt(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* keyId, _Bool useSessionKeyOptState,
	_Bool useSessionKey, uint8_t const* serializedRequest,
	size_t serializedRequestSize, OpaqueOutputPtr allocatedPtr,
	AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_decrypt(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, uint8_t const* serializedRequest,
	size_t serializedRequestSize, OpaqueOutputPtr allocatedPtr,
	AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_reencrypt(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
    char const* sessionToken, char const* sourceKeyId,
    char const* destinationKeyId, uint8_t const* serializedRequest,
    size_t serializedRequestSize, OpaqueOutputPtr allocatedPtr,
    AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_seal(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
    char const* sessionToken, char const* keyId, char const** plaintextVec,
    size_t plaintextVecSize, OpaqueOutputPtr allocatedPtr,
    AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_unseal(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const** ciphertextVec,
	size_t ciphertextVecSize, OpaqueOutputPtr allocatedPtr,
	AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_tokenize(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* keyId,
	uint8_t const* serializedRequest, size_t serializedRequestSize,
	OpaqueOutputPtr allocatedPtr, AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_detokenize(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, uint8_t const* serializedRequest,
	size_t serializedRequestSize, OpaqueOutputPtr allocatedPtr,
	AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_sign(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
    char const* sessionToken, char const* keyId, char const* inputType,
    char const* hashAlgo, char const* signatureScheme, char const* data,
    OpaqueOutputPtr allocatedPtr, AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_verify(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* keyId, char const* inputType,
	char const* hashAlgo, char const* signatureScheme, char const* data,
	char const* signature, OpaqueOutputPtr allocatedPtr,
	AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_signCertificate(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* keyId,
	uint32_t validityPeriod, char const* hashAlgo, char const* csr,
	OpaqueOutputPtr allocatedPtr, AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_verifyCertificate(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* keyId,
    char const* certificate, OpaqueOutputPtr allocatedPtr,
    AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_getKeyInfo(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* keyId, _Bool keyVersionOptState,
	uint32_t keyVersion, OpaqueOutputPtr allocatedPtr,
	AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_getSecret(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* secretId,
	OpaqueOutputPtr allocatedPtr, AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_externalGenerateKeypair(
    OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId, char const* sessionToken,
    char const* wrappingMethod, char const* externalPublicKeyOrWrappingKeyId, char const* keyAlgo,
    _Bool keyLengthOptState, uint32_t keyLength, _Bool withCert, OpaqueOutputPtr allocatedPtr, AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_externalGenerateKey(OpaqueConnectionHandlerPtr const connectionData,
	uint32_t slotId, char const* sessionToken,
	char const* wrappingMethod, char const* internalWrappingKeyId,
	char const* externalPublicKey, uint32_t keyLength,
	OpaqueOutputPtr allocatedPtr, AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_externalGenerateMAC(OpaqueConnectionHandlerPtr const connectionData,
	uint32_t slotId, char const* sessionToken,
	char const* wrappingKeyId, char const* wrappedKey,
	char const* hashAlgo, char const* data,
	OpaqueOutputPtr allocatedPtr, AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_externalVerifyMAC(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* wrappingKeyId,
	char const* wrappedKey, char const* hashAlgo, char const* data,
	char const* mac, char const* iv, OpaqueOutputPtr allocatedPtr,
	AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_externalEncrypt(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* wrappingKeyId,
	char const* wrappedKey, char const* publicKeyOrCert,
	_Bool useSessionKeyOptState, _Bool useSessionKey,
	uint8_t const* serializedRequest, size_t serializedRequestSize,
	OpaqueOutputPtr allocatedPtr, AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_externalDecrypt(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* wrappingKeyId,
	char const* wrappedKey, uint8_t const* serializedRequest,
	size_t serializedRequestSize, OpaqueOutputPtr allocatedPtr,
	AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_externalSeal(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* wrappingKeyId,
	char const* wrappedKey, char const* publicKeyOrCert,
	char const** plaintextVec, size_t plaintextVecSize,
	OpaqueOutputPtr allocatedPtr, AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_externalUnseal(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* wrappingKeyId,
	char const* wrappedKey, char const** ciphertextVec,
	size_t ciphertextSize, OpaqueOutputPtr allocatedPtr,
	AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_externalTokenize(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* wrappingKeyId,
	char const* wrappedKey, uint8_t const* serializedRequest,
	size_t serializedRequestSize, OpaqueOutputPtr allocatedPtr,
	AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_externalDetokenize(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* wrappingKeyId,
	char const* wrappedKey, uint8_t const* serializedRequest,
	size_t serializedRequestSize, OpaqueOutputPtr allocatedPtr,
	AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_externalSign(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* wrappingKeyId,
	char const* wrappedKey, char const* inputType, char const* hashAlgo,
	char const* data, OpaqueOutputPtr allocatedPtr,
	AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_externalVerify(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* publicKeyOrCert,
	char const* inputType, char const* hashAlgo, char const* data,
	char const* signature, OpaqueOutputPtr allocatedPtr,
	AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_fileEncrypt(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* keyId,
	char const* plaintextInputFilePath,
	char const* ciphertextOutputFilePath, OpaqueOutputPtr allocatedPtr,
	AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_fileDecrypt(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* keyId, uint32_t keyVersion,
	uint8_t const* ivVec, size_t ivSize, uint8_t const* tagVec,
	size_t tagSize, char const* plaintextInputFilePath,
	char const* ciphertextOutputFilePath);
SG_FAULTCODE_T kk_nativesdk_sealForTransit(uint8_t const* plaintext, size_t plaintextSize, char const* publicKeyOrCert, OpaqueOutputPtr allocatedPtr,
	AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_unsealDataFromTransit(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* wrappingKeyId, char const* wrappedPrivateKey, uint8_t const* ciphertext, size_t ciphertextSize, OpaqueOutputPtr allocatedPtr,
	AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_fileGenerateHMAC(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* keyId,
	char const* inputFilePath, OpaqueOutputPtr allocatedPtr,
	AssignerCallback callback);
SG_FAULTCODE_T kk_nativesdk_fileVerifyHMAC(OpaqueConnectionHandlerPtr const connectionData, uint32_t slotId,
	char const* sessionToken, char const* keyId,
	char const* inputFilePath, uint8_t const* tagVec, size_t tagSize,
	OpaqueOutputPtr allocatedPtr, AssignerCallback callback);
char const* kk_nativesdk_getVersion();
*/
import "C"
import (
	"fmt"
	"runtime"
	"unsafe"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
	kkreq "github.com/kriptakey/kk-go-sdk/kriptakey/request"
	kkresp "github.com/kriptakey/kk-go-sdk/kriptakey/response"
)

//export kk_gosdk_assign
func kk_gosdk_assign(sourcePtr unsafe.Pointer, sourceSize C.int, targetPtr unsafe.Pointer) C.int {
	array := (*[]byte)(targetPtr)
	*array = C.GoBytes(sourcePtr, sourceSize)
	return C.int(len(*array))
}

type ConnectionHandler struct {
	handler *C.OpaqueConnectionHandlerPtr
}

type faultCodeError struct {
	faultcode uint
}

func (e *faultCodeError) Error() string {
	return fmt.Sprintf("KK SDK FaultResponseCode: %d", e.faultcode)
}

func newFaultCode(faultcode uint) error {
	return &faultCodeError{faultcode: faultcode}
}

func GetSDKVersion() string {
	c_version := C.kk_nativesdk_getVersion()
	return C.GoString(c_version)
}

//  NOTE: `caCertPath` parameter is unused and will be ignored
func InitializeConnection(host string, port uint16, clientCertificatePath string, privateKeyPath string, caCertPath string) (*ConnectionHandler, error) {
	instance := &ConnectionHandler{
		handler: new(C.OpaqueConnectionHandlerPtr),
	}

	c_host := C.CString(host)
	defer C.free(unsafe.Pointer(c_host))
	c_clientCertificatePath := C.CString(clientCertificatePath)
	defer C.free(unsafe.Pointer(c_clientCertificatePath))
	c_privateKeyPath := C.CString(privateKeyPath)
	defer C.free(unsafe.Pointer(c_privateKeyPath))

	ret := C.kk_nativesdk_initializeConnection(c_host, C.ushort(port), c_clientCertificatePath, c_privateKeyPath, instance.handler)
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	runtime.SetFinalizer(instance, func(connection *ConnectionHandler) {
		defer C.kk_nativesdk_freeConnection(*connection.handler)
	})

	return instance, nil
}

//  NOTE: `caCertBuffer` parameter is unused and will be ignored
func InitializeConnectionUsingPEMBuffer(host string, port uint16, clientCertificateBuffer string, privateKeyBuffer string, caCertBuffer string) (*ConnectionHandler, error) {
	instance := &ConnectionHandler{
		handler: new(C.OpaqueConnectionHandlerPtr),
	}

	c_host := C.CString(host)
	defer C.free(unsafe.Pointer(c_host))
	c_clientCertificateBuffer := C.CString(clientCertificateBuffer)
	defer C.free(unsafe.Pointer(c_clientCertificateBuffer))
	c_privateKeyBuffer := C.CString(privateKeyBuffer)
	defer C.free(unsafe.Pointer(c_privateKeyBuffer))

	ret := C.kk_nativesdk_initializeWithCertificatePEMBuffer(c_host, C.ushort(port), c_clientCertificateBuffer, c_privateKeyBuffer, instance.handler)
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	runtime.SetFinalizer(instance, func(connection *ConnectionHandler) {
		defer C.kk_nativesdk_freeConnection(*connection.handler)
	})

	return instance, nil
}

func (x *ConnectionHandler) Login(slotId uint32, password string) (*kkresp.APIResponse_SessionInformation, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_password := C.CString(password)
	defer C.free(unsafe.Pointer(c_password))

	ret := C.kk_nativesdk_login(*x.handler, C.uint(slotId), c_password, C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_SessionInformation{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) RefreshSession(slotId uint32, sessionToken string) (*kkresp.APIResponse_SessionInformation, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))

	ret := C.kk_nativesdk_refreshSession(*x.handler, C.uint(slotId), c_sessionToken, C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_SessionInformation{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) GenerateRandomNumber(slotId uint32, sessionToken string, length uint32) (*kkresp.APIResponse_RandomGenerator, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))

	ret := C.kk_nativesdk_generateRandomNumber(*x.handler, C.uint(slotId), c_sessionToken, C.uint(length), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_RandomGenerator{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) GenerateMAC(slotId uint32, sessionToken string, keyId string, hashAlgo string, data []string) (*kkresp.APIResponse_GenerateMAC, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_keyId := C.CString(keyId)
	defer C.free(unsafe.Pointer(c_keyId))
	c_hashAlgo := C.CString(hashAlgo)
	defer C.free(unsafe.Pointer(c_hashAlgo))

	c_data := make([]*C.char, len(data))
	for i, el := range data {
		c_data[i] = C.CString(el)
		defer C.free(unsafe.Pointer(c_data[i]))
	}

	ret := C.kk_nativesdk_generateMAC(*x.handler, C.uint(slotId), c_sessionToken, c_keyId, c_hashAlgo, (**C.char)(unsafe.Pointer(&c_data[0])), C.ulong(len(c_data)), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_GenerateMAC{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) VerifyMAC(slotId uint32, sessionToken string, keyId string, hashAlgo string, verifyMACRequest *kkreq.APIRequest_VerifyMAC) (*kkresp.APIResponse_VerifyMAC, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_keyId := C.CString(keyId)
	defer C.free(unsafe.Pointer(c_keyId))
	c_hashAlgo := C.CString(hashAlgo)
	defer C.free(unsafe.Pointer(c_hashAlgo))

	req, err := proto.Marshal(verifyMACRequest)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_verifyMAC(*x.handler, C.uint(slotId), c_sessionToken, c_keyId, c_hashAlgo, (*C.uchar)(unsafe.Pointer(&req[0])), C.ulong(len(req)), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_VerifyMAC{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) EncryptAES(slotId uint32, sessionToken string, keyId string, encryptRequest *kkreq.APIRequest_Encrypt) (*kkresp.APIResponse_Encrypt, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_keyId := C.CString(keyId)
	defer C.free(unsafe.Pointer(c_keyId))

	req, err := proto.Marshal(encryptRequest)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_encrypt(*x.handler, C.uint(slotId), c_sessionToken, c_keyId, false, false, (*C.uchar)(unsafe.Pointer(&req[0])), C.ulong(len(req)), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_Encrypt{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) EncryptRSA(slotId uint32, sessionToken string, keyId string, useSessionKey bool, encryptRequest *kkreq.APIRequest_Encrypt) (*kkresp.APIResponse_Encrypt, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_keyId := C.CString(keyId)
	defer C.free(unsafe.Pointer(c_keyId))

	req, err := proto.Marshal(encryptRequest)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_encrypt(*x.handler, C.uint(slotId), c_sessionToken, c_keyId, true, C._Bool(useSessionKey), (*C.uchar)(unsafe.Pointer(&req[0])), C.ulong(len(req)), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_Encrypt{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) Decrypt(slotId uint32, sessionToken string, keyId string, decryptRequest *kkreq.APIRequest_Decrypt) (*kkresp.APIResponse_Decrypt, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))

	req, err := proto.Marshal(decryptRequest)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_decrypt(*x.handler, C.uint(slotId), c_sessionToken, (*C.uchar)(unsafe.Pointer(&req[0])), C.ulong(len(req)), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_Decrypt{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) Reencrypt(slotId uint32, sessionToken string, sourceKeyId string, destinationKeyId string, decryptRequest *kkreq.APIRequest_Reencrypt) (*kkresp.APIResponse_Reencrypt, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_sourceKeyId := C.CString(sourceKeyId)
	defer C.free(unsafe.Pointer(c_sourceKeyId))
	c_destinationKeyId := C.CString(destinationKeyId)
	defer C.free(unsafe.Pointer(c_destinationKeyId))

	req, err := proto.Marshal(decryptRequest)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_reencrypt(*x.handler, C.uint(slotId), c_sessionToken, c_sourceKeyId, c_destinationKeyId, (*C.uchar)(unsafe.Pointer(&req[0])), C.ulong(len(req)), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_Reencrypt{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) Seal(slotId uint32, sessionToken string, keyId string, plaintext []string) (*kkresp.APIResponse_Seal, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_keyId := C.CString(keyId)
	defer C.free(unsafe.Pointer(c_keyId))

	c_plaintext := make([]*C.char, len(plaintext))
	for i, el := range plaintext {
		c_plaintext[i] = C.CString(el)
		defer C.free(unsafe.Pointer(c_plaintext[i]))
	}

	ret := C.kk_nativesdk_seal(*x.handler, C.uint(slotId), c_sessionToken, c_keyId, (**C.char)(unsafe.Pointer(&c_plaintext[0])), C.ulong(len(c_plaintext)), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_Seal{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) Unseal(slotId uint32, sessionToken string, ciphertext []string) (*kkresp.APIResponse_Unseal, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))

	c_ciphertext := make([]*C.char, len(ciphertext))
	for i, el := range ciphertext {
		c_ciphertext[i] = C.CString(el)
		defer C.free(unsafe.Pointer(c_ciphertext[i]))
	}

	ret := C.kk_nativesdk_unseal(*x.handler, C.uint(slotId), c_sessionToken, (**C.char)(unsafe.Pointer(&c_ciphertext[0])), C.ulong(len(c_ciphertext)), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_Unseal{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) Tokenize(slotId uint32, sessionToken string, keyId string, tokenizeRequest *kkreq.APIRequest_Tokenize) (*kkresp.APIResponse_Tokenize, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_keyId := C.CString(keyId)
	defer C.free(unsafe.Pointer(c_keyId))

	req, err := proto.Marshal(tokenizeRequest)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_tokenize(*x.handler, C.uint(slotId), c_sessionToken, c_keyId, (*C.uchar)(unsafe.Pointer(&req[0])), C.ulong(len(req)), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_Tokenize{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) Detokenize(slotId uint32, sessionToken string, detokenizeRequest *kkreq.APIRequest_Detokenize) (*kkresp.APIResponse_Detokenize, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))

	req, err := proto.Marshal(detokenizeRequest)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_detokenize(*x.handler, C.uint(slotId), c_sessionToken, (*C.uchar)(unsafe.Pointer(&req[0])), C.ulong(len(req)), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_Detokenize{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) SignData(slotId uint32, sessionToken string, keyId string, hashAlgo string, signatureScheme string, data string) (*kkresp.APIResponse_Sign, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_keyId := C.CString(keyId)
	defer C.free(unsafe.Pointer(c_keyId))
	c_inputType := C.CString("raw")
	defer C.free(unsafe.Pointer(c_inputType))
	c_hashAlgo := C.CString(hashAlgo)
	defer C.free(unsafe.Pointer(c_hashAlgo))
	c_signatureScheme := C.CString(signatureScheme)
	defer C.free(unsafe.Pointer(c_signatureScheme))
	c_data := C.CString(data)
	defer C.free(unsafe.Pointer(c_data))

	ret := C.kk_nativesdk_sign(*x.handler, C.uint(slotId), c_sessionToken, c_keyId, c_inputType, c_hashAlgo, c_signatureScheme, c_data, C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_Sign{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) SignDigest(slotId uint32, sessionToken string, keyId string, inputType string, signatureScheme string, digest string) (*kkresp.APIResponse_Sign, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_keyId := C.CString(keyId)
	defer C.free(unsafe.Pointer(c_keyId))
	c_inputType := C.CString(inputType)
	defer C.free(unsafe.Pointer(c_inputType))
	c_signatureScheme := C.CString(signatureScheme)
	defer C.free(unsafe.Pointer(c_signatureScheme))
	c_data := C.CString(digest)
	defer C.free(unsafe.Pointer(c_data))

	ret := C.kk_nativesdk_sign(*x.handler, C.uint(slotId), c_sessionToken, c_keyId, c_inputType, nil, c_signatureScheme, c_data, C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_Sign{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) VerifyData(slotId uint32, sessionToken string, keyId string, hashAlgo string, signatureScheme string, data string, signature string) (*kkresp.APIResponse_Verify, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_keyId := C.CString(keyId)
	defer C.free(unsafe.Pointer(c_keyId))
	c_inputType := C.CString("raw")
	defer C.free(unsafe.Pointer(c_inputType))
	c_hashAlgo := C.CString(hashAlgo)
	defer C.free(unsafe.Pointer(c_hashAlgo))
	c_signatureScheme := C.CString(signatureScheme)
	defer C.free(unsafe.Pointer(c_signatureScheme))
	c_data := C.CString(data)
	defer C.free(unsafe.Pointer(c_data))
	c_signature := C.CString(signature)
	defer C.free(unsafe.Pointer(c_signature))

	ret := C.kk_nativesdk_verify(*x.handler, C.uint(slotId), c_sessionToken, c_keyId, c_inputType, c_hashAlgo, c_signatureScheme, c_data, c_signature, C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_Verify{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) VerifyDigest(slotId uint32, sessionToken string, keyId string, inputType string, signatureScheme string, data string, signature string) (*kkresp.APIResponse_Verify, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_keyId := C.CString(keyId)
	defer C.free(unsafe.Pointer(c_keyId))
	c_inputType := C.CString(inputType)
	defer C.free(unsafe.Pointer(c_inputType))
	c_signatureScheme := C.CString(signatureScheme)
	defer C.free(unsafe.Pointer(c_signatureScheme))
	c_data := C.CString(data)
	defer C.free(unsafe.Pointer(c_data))
	c_signature := C.CString(signature)
	defer C.free(unsafe.Pointer(c_signature))

	ret := C.kk_nativesdk_verify(*x.handler, C.uint(slotId), c_sessionToken, c_keyId, c_inputType, nil, c_signatureScheme, c_data, c_signature, C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_Verify{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) SignCertificate(slotId uint32, sessionToken string, keyId string, validityPeriod uint32, hashAlgo string, csr string) (*kkresp.APIResponse_CertificateSign, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_keyId := C.CString(keyId)
	defer C.free(unsafe.Pointer(c_keyId))
	c_hashAlgo := C.CString(hashAlgo)
	defer C.free(unsafe.Pointer(c_hashAlgo))
	c_csr := C.CString(csr)
	defer C.free(unsafe.Pointer(c_csr))

	ret := C.kk_nativesdk_signCertificate(*x.handler, C.uint(slotId), c_sessionToken, c_keyId, C.uint(validityPeriod), c_hashAlgo, c_csr, C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_CertificateSign{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) VerifyCertificate(slotId uint32, sessionToken string, keyId string, certificate string) (*kkresp.APIResponse_CertificateVerify, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_keyId := C.CString(keyId)
	defer C.free(unsafe.Pointer(c_keyId))
	c_certificate := C.CString(certificate)
	defer C.free(unsafe.Pointer(c_certificate))

	ret := C.kk_nativesdk_verifyCertificate(*x.handler, C.uint(slotId), c_sessionToken, c_keyId, c_certificate, C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_CertificateVerify{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) GetKeyInfo(slotId uint32, sessionToken string, keyId string, keyVersion *uint) (*kkresp.APIResponse_KeyInfo, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_keyId := C.CString(keyId)
	defer C.free(unsafe.Pointer(c_keyId))

	ret := C.kk_nativesdk_getKeyInfo(*x.handler, C.uint(slotId), c_sessionToken, c_keyId,
		func() C._Bool {
			return keyVersion != nil
		}(),
		func() C.uint {
			if keyVersion != nil {
				return C.uint(*keyVersion)
			}
			return 0
		}(), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_KeyInfo{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) GetSecret(slotId uint32, sessionToken string, secretId string) (*kkresp.APIResponse_GetSecret, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_secretId := C.CString(secretId)
	defer C.free(unsafe.Pointer(c_secretId))

	ret := C.kk_nativesdk_getSecret(*x.handler, C.uint(slotId), c_sessionToken, c_secretId, C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_GetSecret{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) FileEncrypt(slotId uint32, sessionToken string, keyId string, plaintextOutputFilePath string, ciphertextInputFilePath string) (*kkresp.APIResponse_FileEncrypt, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_keyId := C.CString(keyId)
	defer C.free(unsafe.Pointer(c_keyId))
	c_plaintextOutputFilePath := C.CString(plaintextOutputFilePath)
	defer C.free(unsafe.Pointer(c_plaintextOutputFilePath))
	c_ciphertextInputFilePath := C.CString(ciphertextInputFilePath)
	defer C.free(unsafe.Pointer(c_ciphertextInputFilePath))

	ret := C.kk_nativesdk_fileEncrypt(*x.handler, C.uint(slotId), c_sessionToken, c_keyId, c_plaintextOutputFilePath, c_ciphertextInputFilePath, C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_FileEncrypt{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) FileDecryptWithoutIntegrity(slotId uint32, sessionToken string, keyId string, keyVersion uint32, iv []byte, ciphertextOutputFilePath string, plaintextInputFilePath string) error {
	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_keyId := C.CString(keyId)
	defer C.free(unsafe.Pointer(c_keyId))
	c_ciphertextOutputFilePath := C.CString(ciphertextOutputFilePath)
	defer C.free(unsafe.Pointer(c_ciphertextOutputFilePath))
	c_plaintextInputFilePath := C.CString(plaintextInputFilePath)
	defer C.free(unsafe.Pointer(c_plaintextInputFilePath))

	ret := C.kk_nativesdk_fileDecrypt(*x.handler, C.uint(slotId), c_sessionToken, c_keyId, C.uint(keyVersion), (*C.uchar)(unsafe.Pointer(&iv[0])), C.ulong(len(iv)), nil, 0, c_ciphertextOutputFilePath, c_plaintextInputFilePath)
	if ret != 1 {
		return newFaultCode(uint(ret))
	}
	return nil
}

func (x *ConnectionHandler) FileDecryptWithIntegrity(slotId uint32, sessionToken string, keyId string, keyVersion uint32, iv []byte, tag []byte, ciphertextOutputFilePath string, plaintextInputFilePath string) error {
	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_keyId := C.CString(keyId)
	defer C.free(unsafe.Pointer(c_keyId))
	c_ciphertextOutputFilePath := C.CString(ciphertextOutputFilePath)
	defer C.free(unsafe.Pointer(c_ciphertextOutputFilePath))
	c_plaintextInputFilePath := C.CString(plaintextInputFilePath)
	defer C.free(unsafe.Pointer(c_plaintextInputFilePath))

	ret := C.kk_nativesdk_fileDecrypt(*x.handler, C.uint(slotId), c_sessionToken, c_keyId, C.uint(keyVersion), (*C.uchar)(unsafe.Pointer(&iv[0])), C.ulong(len(iv)), (*C.uchar)(unsafe.Pointer(&tag[0])), C.ulong(len(tag)), c_ciphertextOutputFilePath, c_plaintextInputFilePath)
	if ret != 1 {
		return newFaultCode(uint(ret))
	}
	return nil
}

func (x *ConnectionHandler) FileGenerateHMAC(slotId uint32, sessionToken string, keyId string, inputFilePath string) (*kkresp.APIResponse_FileGenerateHMAC, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_keyId := C.CString(keyId)
	defer C.free(unsafe.Pointer(c_keyId))
	c_inputFilePath := C.CString(inputFilePath)
	defer C.free(unsafe.Pointer(c_inputFilePath))

	ret := C.kk_nativesdk_fileGenerateHMAC(*x.handler, C.uint(slotId), c_sessionToken, c_keyId, c_inputFilePath, C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_FileGenerateHMAC{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) FileVerifyHMAC(slotId uint32, sessionToken string, keyId string, inputFilePath string, tag []byte) (*kkresp.APIResponse_FileVerifyHMAC, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_keyId := C.CString(keyId)
	defer C.free(unsafe.Pointer(c_keyId))
	c_inputFilePath := C.CString(inputFilePath)
	defer C.free(unsafe.Pointer(c_inputFilePath))

	ret := C.kk_nativesdk_fileVerifyHMAC(*x.handler, C.uint(slotId), c_sessionToken, c_keyId, c_inputFilePath, (*C.uchar)(unsafe.Pointer(&tag[0])), C.ulong(len(tag)), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_FileVerifyHMAC{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) GenerateExternalKeypair(slotId uint32, sessionToken string, wrappingMethod string, externalPublicKeyorWrappingKeyId string, keyAlgo string, keyLength *uint32, withCert bool) (*kkresp.APIResponse_GenerateKeypair, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_wrappingMethod := C.CString(wrappingMethod)
	defer C.free(unsafe.Pointer(c_wrappingMethod))
	c_externalPublicKeyorWrappingKeyId := C.CString(externalPublicKeyorWrappingKeyId)
	defer C.free(unsafe.Pointer(c_externalPublicKeyorWrappingKeyId))
	c_keyAlgo := C.CString(keyAlgo)
	defer C.free(unsafe.Pointer(c_keyAlgo))

	ret := C.kk_nativesdk_externalGenerateKeypair(*x.handler, C.uint(slotId), c_sessionToken, c_wrappingMethod, c_externalPublicKeyorWrappingKeyId, c_keyAlgo,
		func() C._Bool {
			return keyLength != nil
		}(),
		func() C.uint {
			if keyLength != nil {
				return C.uint(*keyLength)
			}
			return 0
		}(), C._Bool(withCert), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_GenerateKeypair{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) GenerateExternalKey(slotId uint32, sessionToken string, wrappingMethod string, internalWrappingKeyId string, externalPublicKey string, keyLength uint32) (*kkresp.APIResponse_GenerateKey, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_wrappingMethod := C.CString(wrappingMethod)
	defer C.free(unsafe.Pointer(c_wrappingMethod))
	c_internalWrappingKeyId := C.CString(internalWrappingKeyId)
	defer C.free(unsafe.Pointer(c_internalWrappingKeyId))
	c_externalPublicKey := C.CString(externalPublicKey)
	defer C.free(unsafe.Pointer(c_externalPublicKey))

	ret := C.kk_nativesdk_externalGenerateKey(*x.handler, C.uint(slotId), c_sessionToken, c_wrappingMethod, c_internalWrappingKeyId, c_externalPublicKey, C.uint(keyLength), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_GenerateKey{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) ExternalGenerateMAC(slotId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, hashAlgo string, data string) (*kkresp.APIResponse_ExternalGenerateMAC, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_wrappingKeyId := C.CString(wrappingKeyId)
	defer C.free(unsafe.Pointer(c_wrappingKeyId))
	c_wrappedKey := C.CString(wrappedKey)
	defer C.free(unsafe.Pointer(c_wrappedKey))
	c_hashAlgo := C.CString(hashAlgo)
	defer C.free(unsafe.Pointer(c_hashAlgo))
	c_data := C.CString(data)
	defer C.free(unsafe.Pointer(c_data))

	ret := C.kk_nativesdk_externalGenerateMAC(*x.handler, C.uint(slotId), c_sessionToken, c_wrappingKeyId, c_wrappedKey, c_hashAlgo, c_data, C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_ExternalGenerateMAC{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) ExternalVerifyMAC(slotId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, hashAlgo string, data string, mac string, iv *string) (*kkresp.APIResponse_ExternalVerifyMAC, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_wrappingKeyId := C.CString(wrappingKeyId)
	defer C.free(unsafe.Pointer(c_wrappingKeyId))
	c_wrappedKey := C.CString(wrappedKey)
	defer C.free(unsafe.Pointer(c_wrappedKey))
	c_hashAlgo := C.CString(hashAlgo)
	defer C.free(unsafe.Pointer(c_hashAlgo))
	c_data := C.CString(data)
	defer C.free(unsafe.Pointer(c_data))
	c_mac := C.CString(mac)
	defer C.free(unsafe.Pointer(c_mac))
	var c_iv *C.char = nil
	if iv != nil {
		c_iv = C.CString(*iv)
		defer C.free(unsafe.Pointer(c_iv))
	}

	ret := C.kk_nativesdk_externalVerifyMAC(*x.handler, C.uint(slotId), c_sessionToken, c_wrappingKeyId, c_wrappedKey, c_hashAlgo, c_data, c_mac, c_iv, C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_ExternalVerifyMAC{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) ExternalEncryptAES(slotId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, encryptRequest *kkreq.APIRequest_Encrypt) (*kkresp.APIResponse_ExternalEncrypt, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_wrappingKeyId := C.CString(wrappingKeyId)
	defer C.free(unsafe.Pointer(c_wrappingKeyId))
	c_wrappedKey := C.CString(wrappedKey)
	defer C.free(unsafe.Pointer(c_wrappedKey))

	req, err := proto.Marshal(encryptRequest)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_externalEncrypt(*x.handler, C.uint(slotId), c_sessionToken, c_wrappingKeyId, c_wrappedKey, nil, false, false, (*C.uchar)(unsafe.Pointer(&req[0])), C.ulong(len(req)), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_ExternalEncrypt{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) ExternalEncryptRSA(slotId uint32, sessionToken string, publicKeyOrCert string, useSessionKey bool, encryptRequest *kkreq.APIRequest_Encrypt) (*kkresp.APIResponse_ExternalEncrypt, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_publicKeyOrCert := C.CString(publicKeyOrCert)
	defer C.free(unsafe.Pointer(c_publicKeyOrCert))

	req, err := proto.Marshal(encryptRequest)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_externalEncrypt(*x.handler, C.uint(slotId), c_sessionToken, nil, nil, c_publicKeyOrCert, true, C._Bool(useSessionKey), (*C.uchar)(unsafe.Pointer(&req[0])), C.ulong(len(req)), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_ExternalEncrypt{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) ExternalDecrypt(slotId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, decryptRequest *kkreq.APIRequest_ExternalDecrypt) (*kkresp.APIResponse_ExternalDecrypt, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_wrappingKeyId := C.CString(wrappingKeyId)
	defer C.free(unsafe.Pointer(c_wrappingKeyId))
	c_wrappedKey := C.CString(wrappedKey)
	defer C.free(unsafe.Pointer(c_wrappedKey))

	req, err := proto.Marshal(decryptRequest)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_externalDecrypt(*x.handler, C.uint(slotId), c_sessionToken, c_wrappingKeyId, c_wrappedKey, (*C.uchar)(unsafe.Pointer(&req[0])), C.ulong(len(req)), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_ExternalDecrypt{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) ExternalSealAES(slotId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, plaintext []string) (*kkresp.APIResponse_ExternalSeal, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_wrappingKeyId := C.CString(wrappingKeyId)
	defer C.free(unsafe.Pointer(c_wrappingKeyId))
	c_wrappedKey := C.CString(wrappedKey)
	defer C.free(unsafe.Pointer(c_wrappedKey))

	c_plaintext := make([]*C.char, len(plaintext))
	for i, el := range plaintext {
		c_plaintext[i] = C.CString(el)
		defer C.free(unsafe.Pointer(c_plaintext[i]))
	}

	ret := C.kk_nativesdk_externalSeal(*x.handler, C.uint(slotId), c_sessionToken, c_wrappingKeyId, c_wrappedKey, nil, (**C.char)(unsafe.Pointer(&c_plaintext[0])), C.ulong(len(c_plaintext)), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_ExternalSeal{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) ExternalSealRSA(slotId uint32, sessionToken string, publicKeyOrCert string, plaintext []string) (*kkresp.APIResponse_ExternalSeal, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_publicKeyOrCert := C.CString(publicKeyOrCert)
	defer C.free(unsafe.Pointer(c_publicKeyOrCert))

	c_plaintext := make([]*C.char, len(plaintext))
	for i, el := range plaintext {
		c_plaintext[i] = C.CString(el)
		defer C.free(unsafe.Pointer(c_plaintext[i]))
	}

	ret := C.kk_nativesdk_externalSeal(*x.handler, C.uint(slotId), c_sessionToken, nil, nil, c_publicKeyOrCert, (**C.char)(unsafe.Pointer(&c_plaintext[0])), C.ulong(len(c_plaintext)), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_ExternalSeal{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) ExternalUnseal(slotId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, ciphertext []string) (*kkresp.APIResponse_ExternalUnseal, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_wrappingKeyId := C.CString(wrappingKeyId)
	defer C.free(unsafe.Pointer(c_wrappingKeyId))
	c_wrappedKey := C.CString(wrappedKey)
	defer C.free(unsafe.Pointer(c_wrappedKey))

	c_ciphertext := make([]*C.char, len(ciphertext))
	for i, el := range ciphertext {
		c_ciphertext[i] = C.CString(el)
		defer C.free(unsafe.Pointer(c_ciphertext[i]))
	}

	ret := C.kk_nativesdk_externalUnseal(*x.handler, C.uint(slotId), c_sessionToken, c_wrappingKeyId, c_wrappedKey, (**C.char)(unsafe.Pointer(&c_ciphertext[0])), C.ulong(len(c_ciphertext)), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_ExternalUnseal{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) ExternalTokenize(slotId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, tokenizeRequest *kkreq.APIRequest_Tokenize) (*kkresp.APIResponse_ExternalTokenize, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_wrappingKeyId := C.CString(wrappingKeyId)
	defer C.free(unsafe.Pointer(c_wrappingKeyId))
	c_wrappedKey := C.CString(wrappedKey)
	defer C.free(unsafe.Pointer(c_wrappedKey))

	req, err := proto.Marshal(tokenizeRequest)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_externalTokenize(*x.handler, C.uint(slotId), c_sessionToken, c_wrappingKeyId, c_wrappedKey, (*C.uchar)(unsafe.Pointer(&req[0])), C.ulong(len(req)), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_ExternalTokenize{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) ExternalDetokenize(slotId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, detokenizeRequest *kkreq.APIRequest_Detokenize) (*kkresp.APIResponse_ExternalDetokenize, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_wrappingKeyId := C.CString(wrappingKeyId)
	defer C.free(unsafe.Pointer(c_wrappingKeyId))
	c_wrappedKey := C.CString(wrappedKey)
	defer C.free(unsafe.Pointer(c_wrappedKey))

	req, err := proto.Marshal(detokenizeRequest)
	if err != nil {
		return nil, err
	}

	ret := C.kk_nativesdk_externalDetokenize(*x.handler, C.uint(slotId), c_sessionToken, c_wrappingKeyId, c_wrappedKey, (*C.uchar)(unsafe.Pointer(&req[0])), C.ulong(len(req)), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_ExternalDetokenize{}
	err = proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) ExternalSignData(slotId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, hashAlgo string, data string) (*kkresp.APIResponse_ExternalSign, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_wrappingKeyId := C.CString(wrappingKeyId)
	defer C.free(unsafe.Pointer(c_wrappingKeyId))
	c_wrappedKey := C.CString(wrappedKey)
	defer C.free(unsafe.Pointer(c_wrappedKey))
	c_inputType := C.CString("raw")
	defer C.free(unsafe.Pointer(c_inputType))
	c_hashAlgo := C.CString(hashAlgo)
	defer C.free(unsafe.Pointer(c_hashAlgo))
	c_data := C.CString(data)
	defer C.free(unsafe.Pointer(c_data))

	ret := C.kk_nativesdk_externalSign(*x.handler, C.uint(slotId), c_sessionToken, c_wrappingKeyId, c_wrappedKey, c_inputType, c_hashAlgo, c_data, C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_ExternalSign{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) ExternalSignDigest(slotId uint32, sessionToken string, wrappingKeyId string, wrappedKey string, inputType string, data string) (*kkresp.APIResponse_ExternalSign, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_wrappingKeyId := C.CString(wrappingKeyId)
	defer C.free(unsafe.Pointer(c_wrappingKeyId))
	c_wrappedKey := C.CString(wrappedKey)
	defer C.free(unsafe.Pointer(c_wrappedKey))
	c_inputType := C.CString(inputType)
	defer C.free(unsafe.Pointer(c_inputType))
	c_data := C.CString(data)
	defer C.free(unsafe.Pointer(c_data))

	ret := C.kk_nativesdk_externalSign(*x.handler, C.uint(slotId), c_sessionToken, c_wrappingKeyId, c_wrappedKey, c_inputType, nil, c_data, C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_ExternalSign{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) ExternalVerifyData(slotId uint32, sessionToken string, publicKeyOrCert string, hashAlgo string, data string, signature string) (*kkresp.APIResponse_ExternalVerify, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_publicKeyOrCert := C.CString(publicKeyOrCert)
	defer C.free(unsafe.Pointer(c_publicKeyOrCert))
	c_inputType := C.CString("raw")
	defer C.free(unsafe.Pointer(c_inputType))
	c_hashAlgo := C.CString(hashAlgo)
	defer C.free(unsafe.Pointer(c_hashAlgo))
	c_data := C.CString(data)
	defer C.free(unsafe.Pointer(c_data))
	c_signature := C.CString(signature)
	defer C.free(unsafe.Pointer(c_signature))

	ret := C.kk_nativesdk_externalVerify(*x.handler, C.uint(slotId), c_sessionToken, c_publicKeyOrCert, c_inputType, c_hashAlgo, c_data, c_signature, C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_ExternalVerify{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) ExternalVerifyDigest(slotId uint32, sessionToken string, publicKeyOrCert string, inputType string, data string, signature string) (*kkresp.APIResponse_ExternalVerify, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_publicKeyOrCert := C.CString(publicKeyOrCert)
	defer C.free(unsafe.Pointer(c_publicKeyOrCert))
	c_inputType := C.CString(inputType)
	defer C.free(unsafe.Pointer(c_inputType))
	c_data := C.CString(data)
	defer C.free(unsafe.Pointer(c_data))
	c_signature := C.CString(signature)
	defer C.free(unsafe.Pointer(c_signature))

	ret := C.kk_nativesdk_externalVerify(*x.handler, C.uint(slotId), c_sessionToken, c_publicKeyOrCert, c_inputType, nil, c_data, c_signature, C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &kkresp.APIResponse_ExternalVerify{}
	err := proto.Unmarshal(array, instance)
	return instance, err
}

func (x *ConnectionHandler) SealForTransit(plaintext []byte, publicKeyOrCert string) ([]byte, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_publicKeyOrCert := C.CString(publicKeyOrCert)
	defer C.free(unsafe.Pointer(c_publicKeyOrCert))

	ret := C.kk_nativesdk_sealForTransit((*C.uchar)(unsafe.Pointer(&plaintext[0])), C.ulong(len(plaintext)), c_publicKeyOrCert, C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &wrapperspb.BytesValue{}
	err := proto.Unmarshal(array, instance)

	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(array)
	runtime.KeepAlive(allocPtr)

	return instance.GetValue(), err
}

func (x *ConnectionHandler) UnsealDataFromTransit(slotId uint32, sessionToken string, wrappingKeyId string, wrappedPrivateKey string, ciphertext []byte) ([]byte, error) {
	array := []byte{}
	allocPtr := unsafe.Pointer(&array)

	c_sessionToken := C.CString(sessionToken)
	defer C.free(unsafe.Pointer(c_sessionToken))
	c_wrappingKeyId := C.CString(wrappingKeyId)
	defer C.free(unsafe.Pointer(c_wrappingKeyId))
	c_wrappedPrivateKey := C.CString(wrappedPrivateKey)
	defer C.free(unsafe.Pointer(c_wrappedPrivateKey))

	ret := C.kk_nativesdk_unsealDataFromTransit(*x.handler, C.uint(slotId), c_sessionToken, c_wrappingKeyId, c_wrappedPrivateKey, (*C.uchar)(unsafe.Pointer(&ciphertext[0])), C.ulong(len(ciphertext)), C.OpaqueOutputPtr(allocPtr), C.AssignerCallback(C.kk_gosdk_assign))
	if ret != 1 {
		return nil, newFaultCode(uint(ret))
	}

	instance := &wrapperspb.BytesValue{}
	err := proto.Unmarshal(array, instance)

	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(array)
	runtime.KeepAlive(allocPtr)
	runtime.KeepAlive(x)

	return instance.GetValue(), err
}