//Std imports
#include <string>
#include <iostream>
#include <exception>
#include <stdexcept>
#include <fstream>
#include <sstream>
#include <utility>

//Crypto++ imports
#include <cryptopp/base64.h>
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <cryptopp/filters.h>
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include <cryptopp/sha.h>
using CryptoPP::SHA1;
using CryptoPP::SHA256;

#include <cryptopp/eccrypto.h>
using CryptoPP::ECP;
using CryptoPP::EC2N;
using CryptoPP::ECPPoint;
using CryptoPP::EC2NPoint;
using CryptoPP::ECDSA;
using CryptoPP::ECIES;
using CryptoPP::ECDH;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::DL_GroupPrecomputation;
using CryptoPP::DL_FixedBasePrecomputation;

#include <cryptopp/rsa.h>
using CryptoPP::RSA;
using CryptoPP::RSAFunction;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSASS;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include <cryptopp/pssr.h>
using CryptoPP::PSS;

#include <cryptopp/dsa.h>
using CryptoPP::DSA;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::AutoSeededX917RNG;

#include <cryptopp/asn.h>
using CryptoPP::OID;
#include <cryptopp/oids.h>

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

#include <cryptopp/pwdbased.h>
using CryptoPP::PKCS5_PBKDF2_HMAC;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/modes.h>
using CryptoPP::CFB_Mode;

//Node and class headers import
#include <node.h>
#include "keyring.h"

using namespace v8;
using namespace std;

Persistent<Function> KeyRing::constructor;

KeyRing::KeyRing(string filename, string passphrase) : filename_(filename), keyPair(0){
	//If filename is not null, try to load the key at the given filename
	if (filename != ""){
		if (!doesFileExist(filename)){
			//Throw a V8 error, I don't know how
			return;
		}
		if (passphrase != ""){
			loadKeyPair(filename, false, passphrase);
		} else {
			loadKeyPair(filename);
		}
	}
}

KeyRing::~KeyRing(){
	if (keyPair != 0){
		delete keyPair;
		keyPair = 0;
	}
}

void KeyRing::Init(Handle<Object> exports){
	//Prepare constructor template
	Local<FunctionTemplate> tpl = FunctionTemplate::New(New);
	tpl->SetClassName(String::NewSymbol("KeyRing"));
	tpl->InstanceTemplate()->SetInternalFieldCount(2);
	//Prototype
	tpl->PrototypeTemplate()->Set(String::NewSymbol("decrypt"), FunctionTemplate::New(Decrypt)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("sign"), FunctionTemplate::New(Sign)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("agree"), FunctionTemplate::New(Agree)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("publicKeyInfo"), FunctionTemplate::New(PublicKeyInfo)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("createKeyPair"), FunctionTemplate::New(CreateKeyPair)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("load"), FunctionTemplate::New(Load)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("save"), FunctionTemplate::New(Save)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("clear"), FunctionTemplate::New(Clear)->GetFunction());
	constructor = Persistent<Function>::New(tpl->GetFunction());
	exports->Set(String::NewSymbol("KeyRing"), constructor);
}


/*
* Constructor signature :
* String filename, optional
*/
Handle<Value> KeyRing::New(const Arguments& args){
	HandleScope scope;
	if (args.IsConstructCall()){
		//Invoked as a constructor
		if (args.Length() > 2){
			ThrowException(Exception::TypeError(String::New("Invalid number of arguments on KeyRing constructor call")));
			return scope.Close(Undefined());
		}
		string filename;
		if (args[0]->IsUndefined()){
			filename = "";
		} else {
			String::Utf8Value filenameVal(args[0]->ToString());
			filename = string(*filenameVal);
		}
		if (args.Length() == 2){
			String::Utf8Value passphraseVal(args[1]->ToString());
			string passphrase(*passphraseVal);
			KeyRing* newInstance = new KeyRing(filename, passphrase);
			newInstance->Wrap(args.This());
		} else {
			KeyRing* newInstance = new KeyRing(filename);
			newInstance->Wrap(args.This());
		}
		return args.This();
	} else {
		//Invoked as a plain function, turn into construct call
		if (args.Length() > 2){
			ThrowException(Exception::TypeError(String::New("Invalid number of arguments on KeyRing constructor call")));
			return scope.Close(Undefined());
		}
		if (args.Length() == 1){
			Local<Value> argv[1] = { args[0] };
			return scope.Close(constructor->NewInstance(1, argv));
		} else if (args.Length() == 2){
			Local<Value> argv[2] = { args[0], args[1] };
			return scope.Close(constructor->NewInstance(2, argv));
		} else {
			return scope.Close(constructor->NewInstance());
		}
	}
}

/*Handle<Value> KeyRing::Plus(const Arguments& args){
	HandleScope scope;
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());
	instance->value_ += 1;
	return scope.Close(Number::New(instance->value_));
}*/

/*
* Signature :
* String message, String encoding (defaults to hex), Function callback (optional)
*/
Handle<Value> KeyRing::Decrypt(const Arguments& args){
	HandleScope scope;
	//Checking the number of arguments given to the method
	if (!(args.Length() >= 1 && args.Length() <= 3)){
		ThrowException(Exception::TypeError(String::New("Invalid number of parameters. Please check the module's documentation")));
		return scope.Close(Undefined());
	}
	//Unwrapping current instance and checking that a key pair is loaded
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());
	if (instance->keyPair == 0){
		ThrowException(Exception::TypeError(String::New("No key has been loaded in the keyring. Either load a key on instanciation or by calling the Load() method")));
		return scope.Close(Undefined());
	}
	//Checking the key type
	string keyType = instance->keyPair->at("keyType");
	if (!(keyType == "rsa" || keyType == "ecies" || keyType == "ecdsa")){
		ThrowException(Exception::TypeError(String::New("The key pair loaded is not one of an asymmetric encryption algorithm.")));
		return scope.Close(Undefined());
	}
	//Casting parameters
	string cipher, plaintext, encoding = "";
	String::Utf8Value cipherVal(args[0]->ToString());
	cipher = string(*cipherVal);
	if (args.Length() == 2){
		String::Utf8Value encodingVal(args[1]->ToString());
		encoding = string(*encodingVal);
		if (!(encoding == "hex" || encoding == "base64")){
			ThrowException(Exception::TypeError(String::New("Unknown encoding. Valid values are \"hex\" and \"base64\"")));
			return scope.Close(Undefined());
		}
	}
	Local<Value> result = Local<Value>::New(Undefined());\
	AutoSeededRandomPool prng;
	if (encoding == "hex" || encoding == ""){
		cipher = strHexDecode(cipher);
	} else if (encoding == "base64"){
		cipher = strBase64Decode(cipher);
	}
	if (keyType == "rsa"){
		InvertibleRSAFunction privateParams;
		privateParams.Initialize(HexStrToInteger(instance->keyPair->at("modulus")), HexStrToInteger(instance->keyPair->at("publicExponent")), HexStrToInteger(instance->keyPair->at("privateExponent")));
		RSA::PrivateKey privateKey(privateParams);
		RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
		StringSource(cipher, true, new PK_DecryptorFilter(prng, decryptor, new StringSink(plaintext)));
	} else {
		OID curve = getPCurveFromName(instance->keyPair->at("curveName"));
		ECIES<ECP>::Decryptor d;
		d.AccessKey().AccessGroupParameters().Initialize(curve);
		d.AccessKey().SetPrivateExponent(HexStrToInteger(instance->keyPair->at("privateKey")));
		try {
			StringSource(cipher, true, new PK_DecryptorFilter(prng, d, new StringSink(plaintext)));
		} catch (CryptoPP::Exception const& ex){
			ThrowException(Exception::TypeError(String::New("Crypto error")));
			return scope.Close(Undefined());
		}
	}
	result = String::New(plaintext.c_str());
	if (args.Length() < 3){
		return scope.Close(result);
	} else {
		if (args[2]->IsUndefined()) return scope.Close(result);
		Local<Function> callback = Local<Function>::Cast(args[2]);
		const unsigned argc = 1;
		Local<Value> argv[argc] = { Local<Value>::New(result) };
		callback->Call(Context::GetCurrent()->Global(), argc, argv);
		return scope.Close(Undefined());
	}
}

/*
* Signature :
* String message, String signatureEncoding (defaults to hex), String hashFunctionName (either "sha1" or "sha256", defaults to "sha1"), Function callback (optional)
*/
Handle<Value> KeyRing::Sign(const Arguments& args){
	HandleScope scope;
	//Checking the number of parameters
	if (!(args.Length() >= 1 && args.Length() <= 4)){
		ThrowException(Exception::TypeError(String::New("Invalid number of parameters. Please check the module's documentation")));
		return scope.Close(Undefined());
	}
	//Checking that a key pair is loaded
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());
	if (instance->keyPair == 0){
		ThrowException(Exception::TypeError(String::New("No key has been loaded in the keyring. Either load a key on instanciation or by calling the Load() method")));
		return scope.Close(Undefined());
	}
	//Checking the key type
	string keyType = instance->keyPair->at("keyType");
	if (!(keyType == "rsa" || keyType == "dsa" || keyType == "ecdsa" || keyType == "ecies")){
		ThrowException(Exception::TypeError(String::New("The key pair loaded is one of a signature algorithm")));
		return scope.Close(Undefined());
	}
	//Casting the parameters
	String::Utf8Value messageVal(args[0]->ToString());
	string message, signature, encoding = "", hashFunctionName = "sha1";
	message = string(*messageVal);
	if (args.Length() >= 2 && !args[1]->IsUndefined()){
		String::Utf8Value encodingVal(args[1]->ToString());
		encoding = string(*encodingVal);
		//Checking that the encoding parameter is valid
		if (!(encoding == "hex" || encoding == "base64")){
			ThrowException(Exception::TypeError(String::New("Invalid encoding. It must be either \"hex\" or \"base64\".")));
			return scope.Close(Undefined());
		}
	}
	if (args.Length() >= 3 && !args[2]->IsUndefined()){
		String::Utf8Value hashFunctionNameVal(args[2]->ToString());
		hashFunctionName = string(*hashFunctionNameVal);
		if (!(hashFunctionName == "sha1" || hashFunctionName == "sha256")){
			ThrowException(Exception::TypeError(String::New("hashFunction must be either \"sha1\" or \"sha256\"")));
			return scope.Close(Undefined());
		}
		if (keyType == "dsa" && hashFunctionName != "sha1"){
			//DSA can be used with SHA1 only
			ThrowException(Exception::TypeError(String::New("DSA can only be used with SHA1. :/")));
			return scope.Close(Undefined());
		}
	}
	Local<Value> result = Local<Value>::New(Undefined());
	AutoSeededRandomPool prng;
	if (keyType == "rsa"){
		InvertibleRSAFunction privateParams;
		privateParams.Initialize(HexStrToInteger(instance->keyPair->at("modulus")), HexStrToInteger(instance->keyPair->at("publicExponent")), HexStrToInteger(instance->keyPair->at("privateExponent")));
		RSA::PrivateKey privateKey(privateParams);
		if (hashFunctionName == "sha1"){
			RSASS<PSS, SHA1>::Signer signer(privateKey);
			StringSource(message, true, new SignerFilter(prng, signer, new StringSink(signature)));
		} else if (hashFunctionName == "sha256") {
			RSASS<PSS, SHA256>::Signer signer(privateKey);
			StringSource(message, true, new SignerFilter(prng, signer, new StringSink(signature)));
		} else {
			ThrowException(Exception::TypeError(String::New("Internal error : unknown hash function")));
			return scope.Close(Undefined());
		}
	} else if (keyType == "dsa"){
		DSA::PrivateKey privateKey;
		privateKey.Initialize(HexStrToInteger(instance->keyPair->at("primeField")), HexStrToInteger(instance->keyPair->at("divider")), HexStrToInteger(instance->keyPair->at("base")), HexStrToInteger(instance->keyPair->at("privateExponent")));
		DSA::Signer signer(privateKey);
		StringSource(message, true, new SignerFilter(prng, signer, new StringSink(signature)));
	} else { //ECDSA / ECIES key pair case
		OID curve = getPCurveFromName(instance->keyPair->at("curveName"));
		if (hashFunctionName == "sha1"){
			ECDSA<ECP, SHA1>::PrivateKey privateKey;
			privateKey.Initialize(prng, curve);
			privateKey.SetPrivateExponent(HexStrToInteger(instance->keyPair->at("privateKey")));
			StringSource(message, true, new SignerFilter(prng, ECDSA<ECP, SHA1>::Signer(privateKey), new StringSink(signature)));
		} else if (hashFunctionName == "sha256"){
			ECDSA<ECP, SHA256>::PrivateKey privateKey;
			privateKey.Initialize(prng, curve);
			privateKey.SetPrivateExponent(HexStrToInteger(instance->keyPair->at("privateKey")));
			StringSource(message, true, new SignerFilter(prng, ECDSA<ECP, SHA256>::Signer(privateKey), new StringSink(signature)));
		} else {
			ThrowException(Exception::TypeError(String::New("Internal error : unknown hash function")));
			return scope.Close(Undefined());
		}
	}
	if (encoding == "hex" || encoding == ""){
		signature = strHexEncode(signature);
	} else if (encoding == "base64"){
		signature = strBase64Encode(signature);
	} else {
		ThrowException(Exception::TypeError(String::New("Internal error : unknown encoding")));
		return scope.Close(Undefined());
	}
	result = String::New(signature.c_str());
	if (args.Length() < 4){
		return scope.Close(result);
	} else {
		if (args[3]->IsUndefined()) return scope.Close(result);
		Local<Function> callback = Local<Function>::Cast(args[3]);
		const unsigned argc = 1;
		Local<Value> argv[argc] = { Local<Value>::New(result) };
		callback->Call(Context::GetCurrent()->Global(), argc, argv);
		return scope.Close(Undefined());
	}
}

/*
* Signature
* Object pubKeyInfo, Function callback (optional)
*/
Handle<Value> KeyRing::Agree(const Arguments& args){
	HandleScope scope;
	if (!(args.Length() == 1 || args.Length() == 2)){
		ThrowException(Exception::TypeError(String::New("Invalid number of parameters. Please check the module's documentation")));
		return scope.Close(Undefined());
	}
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());
	if (instance->keyPair == 0){
		ThrowException(Exception::TypeError(String::New("No key has been loaded in the keyring. Either load a key on instanciation or by calling the Load() method")));
		return scope.Close(Undefined());
	}
	string keyType = instance->keyPair->at("keyType");
	if (keyType != "ecdh"){
		ThrowException(Exception::TypeError(String::New("The \"agree\" method is for a key agreement algorithm. The only one supported here is ECDH.")));
		return scope.Close(Undefined());
	}
	string secretStr;
	Local<Value> result = Local<Value>::New(Undefined());
	//Casting the pubKey parameter and checking that curves are the same
	Local<Object> pubKeyObj;
	pubKeyObj = Local<Object>::Cast(args[0]);
	String::Utf8Value counterpartCurveVal(pubKeyObj->Get(String::NewSymbol("curveName")));
	String::Utf8Value counterpartPubKeyVal(pubKeyObj->Get(String::NewSymbol("publicKey")));
	string counterpartCurve(*counterpartCurveVal);
	string counterpartPubKey(*counterpartPubKeyVal);
	/*if (pubKeyObj->Has(String::NewSymbol("encoding"))){
		string counterpartEncoding = pubKeyObj->Get(String::NewSymbol("encoding"));
		if (counterpartEncoding == "hex"){

		} else if (counterpartEncoding == "base64"){

		} else {
			ThrowException(Exception::TypeError(String::New("")));
		}
	} else {
		counterpartPubKey =
	}*/
	if (counterpartCurve != instance->keyPair->at("curveName")){
		ThrowException(Exception::TypeError(String::New("curves are not the same")));
		return scope.Close(Undefined());
	}
	OID curve = getPCurveFromName(instance->keyPair->at("curveName"));
	ECDH<ECP>::Domain dhDomain(curve);
	SecByteBlock privateKey = HexStrToSecByteBlock(instance->keyPair->at("privateKey"));
	SecByteBlock publicKey = HexStrToSecByteBlock(counterpartPubKey);
	SecByteBlock secret(dhDomain.AgreedValueLength());
	dhDomain.Agree(secret, privateKey, publicKey);
	result = String::New(SecByteBlockToHexStr(secret).c_str());
	if (args.Length() == 1){
		return scope.Close(result);
	} else {
		if (args[1]->IsUndefined()) return scope.Close(result);
		Local<Function> callback = Local<Function>::Cast(args[1]);
		const unsigned argc = 1;
		Local<Value> argv[argc] = { Local<Value>::New(result) };
		callback->Call(Context::GetCurrent()->Global(), argc, argv);
		return scope.Close(Undefined());
	}
}

// Function callback (optional)
Handle<Value> KeyRing::PublicKeyInfo(const Arguments& args){
	HandleScope scope;
	if (args.Length() > 1){
		ThrowException(Exception::TypeError(String::New("Invalid number of parameters")));
		return scope.Close(Undefined());
	}
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());
	if (instance->keyPair == 0){
		ThrowException(Exception::TypeError(String::New("No key has been loaded in the keyring. Either load a key on instanciation or by calling the Load() method")));
		return scope.Close(Undefined());
	}
	if (args.Length() == 0){
		return scope.Close(instance->PPublicKeyInfo());
	} else {
		if (!args[0]->IsUndefined()) return scope.Close(instance->PPublicKeyInfo());
		Local<Function> callback = Local<Function>::Cast(args[0]);
		const unsigned argc = 1;
		Local<Value> argv[argc] = { Local<Value>::New(instance->PPublicKeyInfo()) };
		callback->Call(Context::GetCurrent()->Global(), argc, argv);
		return scope.Close(Undefined());
	}
}

/*
* Signature
* String keyType, Number/String keyOptions, String filename [optional], String passphrase [optional], Function callback [optional]
*/
Handle<Value> KeyRing::CreateKeyPair(const Arguments& args){
	HandleScope scope;
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());
	if (args.Length() < 2){
		//"Invalid number of parameters. Please check the module's documentation"
		ThrowException(Exception::TypeError(String::New("Invalid number of parameters. You must at least specify the key type and related paremters like key size or curve name")));
		return scope.Close(Undefined());
	}
	String::Utf8Value algoTypeVal(args[0]->ToString());
	std::string algoType(*algoTypeVal);
	//Checking that the key type is supported, otherwise throw an exception
	if (!(algoType == "rsa" || algoType == "dsa" || algoType == "ecdsa" || algoType == "ecies" || algoType == "ecdh")){
		ThrowException(Exception::TypeError(String::New("Invalid algo type.")));
		return scope.Close(Undefined());
	}
	//Instanciating a new key map object
	map<string, string>* newKeyPair = new map<string, string>();
	if (instance->keyPair != 0){ //Delete the last key map, if there is one
		delete instance->keyPair;
		instance->keyPair = 0;
	}
	instance->keyPair = newKeyPair;
	//Declaring the public key object
	if (algoType == "rsa"){
		Local<v8::Integer> keySizeVal = Local<v8::Integer>::Cast(args[1]);
		int keySize = keySizeVal->Value();
		if (!(keySize >= 1024 && keySize <= 16384)){
			ThrowException(v8::Exception::TypeError(String::New("Invalid key size. Must be between 1024 and 16384 bits")));
			return scope.Close(Undefined());
		}
		//Generating the key pair
		AutoSeededRandomPool prng;
		InvertibleRSAFunction keyPairParams;
		keyPairParams.GenerateRandomWithKeySize(prng, keySize);
		//Build the key map
		newKeyPair->insert(make_pair("keyType", "rsa"));
		newKeyPair->insert(make_pair("modulus", IntegerToHexStr(keyPairParams.GetModulus())));
		newKeyPair->insert(make_pair("publicExponent", IntegerToHexStr(keyPairParams.GetPublicExponent())));
		newKeyPair->insert(make_pair("privateExponent", IntegerToHexStr(keyPairParams.GetPrivateExponent())));
	} else if (algoType == "dsa"){
		Local<v8::Integer> keySizeVal = Local<v8::Integer>::Cast(args[1]);
		int keySize = keySizeVal->Value();
		if (!(keySize >= 1024 && keySize <= 16384)){
			ThrowException(v8::Exception::TypeError(String::New("Invalid key size. Must be between 1024 aqnd 16384 bits")));
			return scope.Close(Undefined());
		}
		//Generating key pair
		AutoSeededRandomPool prng;
		DSA::PrivateKey privateKey;
		privateKey.GenerateRandomWithKeySize(prng, keySize);
		DSA::PublicKey publicKey;
		privateKey.MakePublicKey(publicKey);
		//Building the key map
		newKeyPair->insert(make_pair("keyType", "dsa"));
		newKeyPair->insert(make_pair("primeField", IntegerToHexStr(privateKey.GetGroupParameters().GetModulus())));
		newKeyPair->insert(make_pair("divider", IntegerToHexStr(privateKey.GetGroupParameters().GetSubgroupOrder())));
		newKeyPair->insert(make_pair("base", IntegerToHexStr(privateKey.GetGroupParameters().GetSubgroupGenerator())));
		newKeyPair->insert(make_pair("privateExponent", IntegerToHexStr(privateKey.GetPrivateExponent())));
		newKeyPair->insert(make_pair("publicElement", IntegerToHexStr(publicKey.GetPublicElement())));
	} else if (algoType == "ecies"){
		//Getting curve name and checking validity
		String::AsciiValue curveNameVal(args[1]->ToString());
		std::string curveName(*curveNameVal);
		if (curveName.find("sect") == 0){
			ThrowException(Exception::TypeError(String::New("Binary curves are not supported yet. Please use prime curves.")));
			return scope.Close(Undefined());
		}
		OID curve;
		try {
			curve = getPCurveFromName(curveName);
		} catch (runtime_error* e){
			ThrowException(Exception::TypeError(String::New("Unknown curve")));
			return scope.Close(Undefined());
		}
		//Generating the key pair
		AutoSeededRandomPool prng;
		ECIES<ECP>::Decryptor d(prng, curve);
		CryptoPP::Integer privateKey = d.GetKey().GetPrivateExponent();
		const DL_GroupParameters_EC<ECP>& params = d.GetKey().GetGroupParameters();
		const DL_FixedBasePrecomputation<ECPPoint>& bpc = params.GetBasePrecomputation();
		const ECPPoint publicKey = bpc.Exponentiate(params.GetGroupPrecomputation(), d.GetKey().GetPrivateExponent());
		//Building the key map
		newKeyPair->insert(make_pair("keyType", "ecies"));
		newKeyPair->insert(make_pair("curveName", curveName));
		newKeyPair->insert(make_pair("publicKeyX", IntegerToHexStr(publicKey.x)));
		newKeyPair->insert(make_pair("publicKeyY", IntegerToHexStr(publicKey.y)));
		newKeyPair->insert(make_pair("privateKey", IntegerToHexStr(privateKey)));
	} else if (algoType == "ecdsa"){
		//Getting curve name and checking validity
		String::AsciiValue curveNameVal(args[1]->ToString());
		std::string curveName(*curveNameVal);
		if (curveName.find("sect") == 0){
			ThrowException(Exception::TypeError(String::New("Binary curves are not supported yet. Please use prime curves.")));
			return scope.Close(Undefined());
		}
		OID curve;
		try {
			curve = getPCurveFromName(curveName);
		} catch (runtime_error* e){
			ThrowException(Exception::TypeError(String::New("Unknown curve")));
			return scope.Close(Undefined());
		}
		//Generating the key pair
		AutoSeededRandomPool prng;
		ECDSA<ECP, SHA256>::PrivateKey privateKey;
		ECDSA<ECP, SHA256>::PublicKey publicKey;
		privateKey.Initialize(prng, curve);
		privateKey.MakePublicKey(publicKey);
		const ECPPoint publicPoint(publicKey.GetPublicElement());
		//Building the key map
		newKeyPair->insert(make_pair("keyType", "ecdsa"));
		newKeyPair->insert(make_pair("curveName", curveName));
		newKeyPair->insert(make_pair("publicKeyX", IntegerToHexStr(publicPoint.x)));
		newKeyPair->insert(make_pair("publicKeyY", IntegerToHexStr(publicPoint.y)));
		newKeyPair->insert(make_pair("privateKey", IntegerToHexStr(privateKey.GetPrivateExponent())));
	} else if (algoType == "ecdh"){
		//Getting curve name and checking validity
		String::AsciiValue curveNameVal(args[1]->ToString());
		std::string curveName(*curveNameVal);
		if (curveName.find("sect") == 0){
			ThrowException(Exception::TypeError(String::New("Binary curves are not supported yet. Please use prime curves.")));
			return scope.Close(Undefined());
		}
		OID curve;
		try {
			curve = getPCurveFromName(curveName);
		} catch (runtime_error* e){
			ThrowException(Exception::TypeError(String::New("Unknown curve")));
			return scope.Close(Undefined());
		}
		//Generating key pair
		AutoSeededX917RNG<AES> prng;
		ECDH<ECP>::Domain dhDomain(curve);
		SecByteBlock privKey(dhDomain.PrivateKeyLength()), publicKey(dhDomain.PublicKeyLength());
		dhDomain.GenerateKeyPair(prng, privKey, publicKey);
		//Building the key map
		newKeyPair->insert(make_pair("keyType", "ecdh"));
		newKeyPair->insert(make_pair("curveName", curveName));
		newKeyPair->insert(make_pair("privateKey", SecByteBlockToHexStr(privKey)));
		newKeyPair->insert(make_pair("publicKey", SecByteBlockToHexStr(publicKey)));
	}
	//Saving the key if asked by the user
	if (args.Length() == 3){
		String::Utf8Value filenameVal(args[2]->ToString());
		string filename(*filenameVal);
		saveKeyPair(filename, newKeyPair);
		instance->filename_ = filename;
	} else if (args.Length() == 4){
		String::Utf8Value filenameVal(args[2]->ToString());
		String::Utf8Value passphraseVal(args[3]->ToString());
		string filename(*filenameVal), passphrase(*passphraseVal);
		saveKeyPair(filename, newKeyPair, passphrase);
		instance->filename_ = filename;
	}
	//Building public key info object
	Local<Object> pubKey = instance->PPublicKeyInfo();
	if (args.Length() < 5){
		return scope.Close(pubKey);
	} else {
		if (args[4]->IsUndefined()) return scope.Close(pubKey);
		Local<Function> callback = Local<Function>::Cast(args[4]);
		const unsigned argc = 1;
		Local<Value> argv[argc] = { Local<Value>::New(pubKey) };
		callback->Call(Context::GetCurrent()->Global(), argc, argv);
		return scope.Close(pubKey);
	}
}

Local<Object> KeyRing::PPublicKeyInfo(){
	Local<Object> pubKeyObj = Object::New();
	if (keyPair == 0){
		throw new runtime_error("No loaded key pair");
	}
	string keyType = keyPair->at("keyType");
	pubKeyObj->Set(String::NewSymbol("keyType"), String::New(keyType.c_str()));
	if (keyType == "rsa"){
		string params[] = {"modulus", "publicExponent"};
		for (int i = 0; i < 2; i++){
			if (!(keyPair->count(params[i]))) throw new runtime_error(params[i] + " parameter is missing from " + keyType + " key pair");
			pubKeyObj->Set(String::NewSymbol(params[i].c_str()), String::New(keyPair->at(params[i]).c_str()));
		}
	} else if (keyType == "dsa"){
		string params[] = {"primeField", "divider", "base", "publicElement"};
		for (int i = 0; i < 4; i++){
			if (!(keyPair->count(params[i]) > 0)) throw new runtime_error(params[i] + " parameter is missing from " + keyType + " key pair");
			pubKeyObj->Set(String::NewSymbol(params[i].c_str()), String::New(keyPair->at(params[i]).c_str()));
		}
	} else if (keyType == "ecies" || keyType == "ecdsa"){
		string params[] = {"curveName", "publicKeyX", "publicKeyY"};
		for (int i = 0; i < 3; i++){
			if (!(keyPair->count(params[i]) > 0)) throw new runtime_error(params[i] + " parameters is missing from " + keyType + " key pair");
		}
		pubKeyObj->Set(String::NewSymbol("curveName"), String::New(keyPair->at("curveName").c_str()));
		Local<Object> publicPoint = Object::New();
		publicPoint->Set(String::NewSymbol("x"), String::New(keyPair->at("publicKeyX").c_str()));
		publicPoint->Set(String::NewSymbol("y"), String::New(keyPair->at("publicKeyY").c_str()));
		pubKeyObj->Set(String::NewSymbol("publicKey"), publicPoint);
	/*} else if (keyType == "ecdsa"){
		string params[] = {"curveName", "publicKeyX", "publicKeyY"};
		for (int i = 0; i < 3; i++){
			if (!(keyPair->count(params[i]) > 0)) throw new runtime_error(params[i] + " parameter is missing from " + keyType + " key pair");
		}
		pubKeyObj*/
	} else if (keyType == "ecdh"){
		string params[] = {"curveName", "publicKey"};
		for (int i = 0; i < 2; i++){
			if (!(keyPair->count(params[i]) > 0)) throw new runtime_error(params[i] + " parameter is missing from " + keyType + " key pair");
			pubKeyObj->Set(String::NewSymbol(params[i].c_str()), String::New(keyPair->at(params[i]).c_str()));
		}
	} else throw new runtime_error("Internal error. Unknown key type");
	return pubKeyObj;
}

/*
* Signature
* String filename, Boolean legacy, String passphrase, Function callback [freaking optional]
*/
Handle<Value> KeyRing::Load(const Arguments& args){
	HandleScope scope;
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());
	if (args.Length() >= 1 && args.Length() <= 4){
		String::Utf8Value filenameVal(args[0]->ToString());
		string filename(*filenameVal);
		if (!doesFileExist(filename)){
			ThrowException(v8::Exception::TypeError(String::New("The given file doesn't exist.")));
			return scope.Close(Undefined());
		}
		//If I put a try block here, what kind of exceptions should I catch. I simply don't get it.
		bool isLegacy = false;
		string passphrase = "";
		if (args.Length() >= 2){
			bool isLegacyVal = args[1]->BooleanValue();
			isLegacy = isLegacyVal;
		}
		if (args.Length() >= 3){
			String::Utf8Value passphraseVal(args[2]->ToString());
			passphrase = string(*passphraseVal);
		}
		/*if (args.Length() == 1){ //If no passphrase is given
			instance->keyPair = loadKeyPair(filename);
		} else { //If a passphrase is given
			String::Utf8Value passphraseVal(args[1]->ToString());
			string passphrase(*passphraseVal);
			instance->keyPair = loadKeyPair(filename, passphrase);
		}*/
		instance->keyPair = loadKeyPair(filename, isLegacy, passphrase);
		Local<Object> pubKey = instance->PPublicKeyInfo();
		if (args.Length() < 4){
			return scope.Close(pubKey);
		} else {
			if (args[2]->IsUndefined()) return scope.Close(pubKey);
			Local<Function> callback = Local<Function>::Cast(args[2]);
			const unsigned argc = 1;
			Local<Value> argv[argc] = { Local<Value>::New (pubKey) };
			callback->Call(Context::GetCurrent()->Global(), argc, argv);
			return scope.Close(Undefined());
		}
	} else {
		ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
		return scope.Close(Undefined());
	}
}

/*
* Signature
* String filename, String passphrase [optional], Function callback [optional]
*/
Handle<Value> KeyRing::Save(const Arguments& args){
	HandleScope scope;
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());
	if (instance->keyPair == 0){
		ThrowException(Exception::TypeError(String::New("No key has been loaded in the keyring. Either load a key on instanciation or by calling the Load() method")));
		return scope.Close(Undefined());
	}
	if (args.Length() >= 1 && args.Length() <= 3){
		String::Utf8Value filenameVal(args[0]->ToString());
		std::string filename(*filenameVal);
		if (args.Length() == 1){
			saveKeyPair(filename, instance->keyPair);
		} else {
			String::Utf8Value passphraseVal(args[1]->ToString());
			std::string passphrase(*passphraseVal);
			saveKeyPair(filename, instance->keyPair, passphrase);
		}
		//a callback is given, then call it |||| Screw the callback hell
		if (args.Length() == 3 && !args[2]->IsUndefined()){
			Local<Function> callback = Local<Function>::Cast(args[2]);
			const unsigned argc = 0;
			Local<Value> argv[argc];
			callback->Call(Context::GetCurrent()->Global(), argc, argv);
		}
		return scope.Close(Undefined());
	} else {
		ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
		return scope.Close(Undefined());
	}
}

//No params
Handle<Value> KeyRing::Clear(const Arguments& args){
	HandleScope scope;
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());
	if (instance->keyPair != 0){
		delete instance->keyPair;
		instance->keyPair = 0;
	}
	return scope.Close(Undefined());
}

map<string, string>* KeyRing::loadKeyPair(string const& filename, bool legacy, string passphrase){
	string fileContent;
	if (passphrase != ""){ //If passphrase is defined, then decrypt file
		fileContent = decryptFile(filename, passphrase);
	} else {
		std::fstream file(filename.c_str(), ios::in);
		std::getline(file, fileContent);
		if (legacy) fileContent = strHexDecode(fileContent);
	}
	map<string, string>* keyPair;
	if (legacy) keyPair = decodeBufferLegacy(fileContent);
	else keyPair = decodeBuffer(fileContent);
	return keyPair;
}

bool KeyRing::saveKeyPair(string const& filename, map<string, string>* keyPair, string passphrase){
	std::string buffer = encodeBuffer(keyPair);
	if (passphrase != ""){
		encryptFile(filename, buffer, passphrase);
	} else {
		std::fstream file(filename.c_str(), std::ios::out | std::ios::trunc);
		file << buffer;
		file.close();
	}
	return true;
}

bool KeyRing::doesFileExist(std::string const& filename){
	std::fstream file(filename.c_str(), std::ios::in);
	bool isGood = file.good();
	file.close();
	return isGood;
}

map<string, string>* KeyRing::decodeBuffer(string const& fileBuffer){
	map<string, string>* keyPair;
	stringstream file(fileBuffer);
	stringbuf* buffer = file.rdbuf();
	char keyType = buffer->sbumpc();
	if (keyType == 0x00 || keyType == 0x04){ //ECDSA / ECIES keys
		char curveID = buffer->sbumpc();
		string curveName = getCurveName(curveID);
		unsigned short publicXLength, publicYLength, privateKeyLength;
		string publicX = "", publicY = "", privateKey = "";
		publicXLength = ((unsigned short) buffer->sbumpc()) << 8;
		publicXLength += (unsigned short) buffer->sbumpc();
		for (int i = 0; i < publicXLength; i++){
			publicX += (char) buffer->sbumpc();
		}
		publicYLength = ((unsigned short) buffer->sbumpc()) << 8;
		publicYLength += (unsigned short) buffer->sbumpc();
		for (int i = 0; i < publicYLength; i++){
			publicY += (char) buffer->sbumpc();
		}
		privateKeyLength = ((unsigned short) buffer->sbumpc()) << 8;
		privateKeyLength += (unsigned short) buffer->sbumpc();
		for (int i = 0; i < privateKeyLength; i++){
			privateKey += (char) buffer->sbumpc();
		}
		keyPair = new map<string, string>();
		if (keyType == 0x00) keyPair->insert(make_pair("keyType", "ecdsa"));
		else keyPair->insert(make_pair("keyType", "ecies"));
		keyPair->insert(make_pair("curveName", curveName));
		keyPair->insert(make_pair("publicKeyX", publicX));
		keyPair->insert(make_pair("publicKeyY", publicY));
		keyPair->insert(make_pair("privateKey", privateKey));
	} else if (keyType == 0x01){ //RSA keys
		unsigned short modulusLength, publicExpLength, privateExpLength;
		string modulus = "", publicExponent = "", privateExponent = "";
		modulusLength = ((unsigned short) buffer->sbumpc()) << 8;
		modulusLength += (unsigned short) buffer->sbumpc();
		for (int i = 0; i < modulusLength; i++){
			modulus += (char) buffer->sbumpc();
		}
		publicExpLength = ((unsigned short) buffer->sbumpc()) << 8;
		publicExpLength += (unsigned short) buffer->sbumpc();
		for (int i = 0; i < publicExpLength; i++){
			publicExponent += (char) buffer->sbumpc();
		}
		privateExpLength = ((unsigned short) buffer->sbumpc()) << 8;
		privateExpLength += (unsigned short) buffer->sbumpc();
		for (int i = 0; i < privateExpLength; i++){
			privateExponent += (char) buffer->sbumpc();
		}
		keyPair = new map<string, string>();
		keyPair->insert(make_pair("keyType", "rsa"));
		keyPair->insert(make_pair("modulus", modulus));
		keyPair->insert(make_pair("publicExponent", publicExponent));
		keyPair->insert(make_pair("privateExponent", privateExponent));
	} else if (keyType == 0x02){ //DSA keys
		unsigned short primeFieldLength, dividerLength, baseLength, publicElementLength, privateExponentLength;
		string primeField = "", divider = "", base = "", publicElement = "", privateExponent = "";
		primeFieldLength = ((unsigned short) buffer->sbumpc()) << 8;
		primeFieldLength += (unsigned short) buffer->sbumpc();
		for (int i = 0; i < primeFieldLength; i++){
			primeField += (char) buffer->sbumpc();
		}
		dividerLength = ((unsigned short) buffer->sbumpc()) << 8;
		dividerLength += (unsigned short) buffer->sbumpc();
		for (int i = 0; i < dividerLength; i++){
			divider += (char) buffer->sbumpc();
		}
		baseLength = ((unsigned short) buffer->sbumpc()) << 8;
		baseLength += (unsigned short) buffer->sbumpc();
		for (int i = 0; i < baseLength; i++){
			base += (char) buffer->sbumpc();
		}
		publicElementLength = ((unsigned short) buffer->sbumpc()) << 8;
		publicElementLength += (unsigned short) buffer->sbumpc();
		for (int i = 0; i < publicElementLength; i++){
			publicElement += (char) buffer->sbumpc();
		}
		privateExponentLength = ((unsigned short) buffer->sbumpc()) << 8;
		privateExponentLength += (unsigned short) buffer->sbumpc();
		for (int i = 0; i < privateExponentLength; i++){
			privateExponent += (char) buffer->sbumpc();
		}
		keyPair = new map<string, string>();
		keyPair->insert(make_pair("keyType", "dsa"));
		keyPair->insert(make_pair("primeField", primeField));
		keyPair->insert(make_pair("divider", divider));
		keyPair->insert(make_pair("base", base));
		keyPair->insert(make_pair("publicElement", publicElement));
		keyPair->insert(make_pair("privateExponent", privateExponent));
	} else if (keyType == 0x03){ //ECDH keys
		char curveID = buffer->sbumpc();
		string curveName = getCurveName(curveID);
		unsigned short publicKeyLength, privateKeyLength;
		string publicKey = "", privateKey = "";
		publicKeyLength = ((unsigned short) buffer->sbumpc()) << 8;
		publicKeyLength += (unsigned short) buffer->sbumpc();
		for (int i = 0; i < publicKeyLength; i++){
			publicKey += (char) buffer->sbumpc();
		}
		privateKeyLength = ((unsigned short) buffer->sbumpc()) << 8;
		privateKeyLength += (unsigned short) buffer->sbumpc();
		for (int i = 0; i < privateKeyLength; i++){
			privateKey += (char) buffer->sbumpc();
		}
		keyPair = new map<string, string>();
		keyPair->insert(make_pair("keyType", "ecdh"));
		keyPair->insert(make_pair("curveName", curveName));
		keyPair->insert(make_pair("publicKey", publicKey));
		keyPair->insert(make_pair("privateKey", privateKey));
	} else throw new runtime_error("Unknown key type");
	return keyPair;
}

map<string, string>* KeyRing::decodeBufferLegacy(string const& fileBuffer){
	map<string, string>* keyPair;
	stringstream file(fileBuffer);
	stringbuf* buffer = file.rdbuf();
	string keyHeader = "";
	for (int i = 0; i < 3; i++){
		keyHeader += buffer->sbumpc();
	}
	if (!(keyHeader == "key")) throw new runtime_error("Invalid key file");
	char keyType = buffer->sbumpc();
	if (keyType == 0x00 || keyType == 0x04){ //ECDSA / ECIES keys
		char curveID = buffer->sbumpc();
		string curveName = getCurveName(curveID);
		unsigned short publicXLength, publicYLength, privateKeyLength;
		string publicX = "", publicY = "", privateKey = "";
		publicXLength = ((int) buffer->sbumpc()) << 8;
		publicXLength += (int) buffer->sbumpc();
		for (int i = 0; i < publicXLength; i++){
			publicX += (char) buffer->sbumpc();
		}
		publicYLength = ((int) buffer->sbumpc()) << 8;
		publicYLength += (int) buffer->sbumpc();
		for (int i = 0; i < publicYLength; i++){
			publicY += (char) buffer->sbumpc();
		}
		privateKeyLength = ((int) buffer->sbumpc()) << 8;
		privateKeyLength += (int) buffer->sbumpc();
		for (int i = 0; i < privateKeyLength; i++){
			privateKey += (char) buffer->sbumpc();
		}
		keyPair = new map<string, string>();
		if (keyType == 0x00) keyPair->insert(make_pair("keyType", "ecdsa"));
		else keyPair->insert(make_pair("keyType", "ecies")); //(ie keyType == 0x04)
		keyPair->insert(make_pair("curveName", curveName));
		keyPair->insert(make_pair("publicKeyX", publicX));
		keyPair->insert(make_pair("publicKeyY", publicY));
		keyPair->insert(make_pair("privateKey", privateKey));
	} else if (keyType == 0x01){ //RSA keys
		//Reading key data
        unsigned short modulusLength, publicExpLength, privateExpLength;
        string modulus = "", publicExponent = "", privateExponent = "";
        modulusLength = ((int) buffer->sbumpc()) << 8;
        modulusLength += (int) buffer->sbumpc();
        for (int i = 0; i < modulusLength; i++){
            modulus += (char) buffer->sbumpc();
        }
        publicExpLength = ((int) buffer->sbumpc()) << 8;
        publicExpLength += (int) buffer->sbumpc();
        for (int i = 0; i < publicExpLength; i++){
            publicExponent += (char) buffer->sbumpc();
        }
        privateExpLength = ((int) buffer->sbumpc()) << 8;
        privateExpLength += (int) buffer->sbumpc();
        for (int i = 0; i < privateExpLength; i++){
            privateExponent += (char) buffer->sbumpc();
        }
        //Building the map object
        keyPair = new map<string, string>();
        keyPair->insert(make_pair("keyType", "rsa"));
        keyPair->insert(make_pair("modulus", modulus));
        keyPair->insert(make_pair("publicExponent", publicExponent));
        keyPair->insert(make_pair("privateExponent", privateExponent));
	} else if (keyType == 0x02){ //DSA keys
        //Reading key data
        unsigned short primeFieldLength, dividerLength, baseLength, publicElementLength, privateExponentLength;
        string primeField = "", divider = "", base = "", publicElement = "", privateExponent = "";
        primeFieldLength = ((int) buffer->sbumpc()) << 8;
        primeFieldLength += (int) buffer->sbumpc();
        for (int i = 0; i < primeFieldLength; i++){
            primeField += (char) buffer->sbumpc();
        }
        dividerLength = ((int) buffer->sbumpc()) << 8;
        dividerLength += (int) buffer->sbumpc();
        for (int i = 0; i < dividerLength; i++){
            divider += (char) buffer->sbumpc();
        }
        baseLength = ((int) buffer->sbumpc()) << 8;
        baseLength += (int) buffer->sbumpc();
        for (int i = 0; i < baseLength; i++){
            base += (char) buffer->sbumpc();
        }
        publicElementLength = ((int) buffer->sbumpc()) << 8;
        publicElementLength += (int) buffer->sbumpc();
        for (int i = 0; i < publicElementLength; i++){
            publicElement += (char) buffer->sbumpc();
        }
        privateExponentLength = ((int) buffer->sbumpc()) << 8;
        privateExponentLength += (int) buffer->sbumpc();
        for (int i = 0; i < privateExponentLength; i++){
            privateExponent += (char) buffer->sbumpc();
        }
        keyPair = new map<string, string>();
        keyPair->insert(make_pair("keyType", "dsa"));
        keyPair->insert(make_pair("primeField", primeField));
        keyPair->insert(make_pair("divider", divider));
        keyPair->insert(make_pair("base", base));
        keyPair->insert(make_pair("publicElement", publicElement));
        keyPair->insert(make_pair("privateExponent", privateExponent));
	} else if (keyType == 0x03){ //ECDH keys
		char curveID = buffer->sbumpc();
		string curveName = getCurveName(curveID);
		unsigned short publicKeyLength, privateKeyLength;
		string publicKey = "", privateKey = "";
		publicKeyLength = ((int) buffer->sbumpc()) << 8;
		publicKeyLength += (int) buffer->sbumpc();
		for (int i = 0; i < publicKeyLength; i++){
			publicKey += (char) buffer->sbumpc();
		}
		privateKeyLength = ((int) buffer->sbumpc()) << 8;
		privateKeyLength += (int) buffer->sbumpc();
		for (int i = 0; i < privateKeyLength; i++){
			privateKey += (char) buffer->sbumpc();
		}
		keyPair = new map<string, string>();
		keyPair->insert(make_pair("keyType", "ecdh"));
		keyPair->insert(make_pair("curveName", curveName));
		keyPair->insert(make_pair("publicKey", publicKey));
		keyPair->insert(make_pair("privateKey", privateKey));
	} else throw new runtime_error("Unknown key type");
	return keyPair;
}

string KeyRing::encodeBuffer(map<string, string>* keyPair){
	stringstream buffer;
	if (!(keyPair->count("keyType") > 0)) throw new runtime_error("keyType not found");
	string keyType = keyPair->at("keyType");
	if (keyType == "ecdsa" || keyType == "ecies"){
		//Checking key pair integrality
		string params[] = {"curveName", "publicKeyX", "publicKeyY", "privateKey"};
		for (int i = 0; i < 4; i++){
			if (!keyPair->count(params[i])) throw new runtime_error("Missing parameter : " + params[i]);
		}
		//Writing key type
		if (keyType == "ecdsa"){
			buffer << (char) 0x00;
		} else {
			buffer << (char) 0x04;
		}
		//Writing the curveID
		char curveID = getCurveID(keyPair->at("curveName"));
		buffer << curveID;
		string publicX = keyPair->at("publicKeyX"), publicY = keyPair->at("publicKeyY"), privateKey = keyPair->at("privateKey");
		//if (publicX.length() > ) //Checking lengths...
		//Writing publicKey.x
		buffer << (unsigned char) (publicX.length() >> 8);
		buffer << (unsigned char) publicX.length();
		buffer << publicX;
		//Writing publicKey.y
		buffer << (unsigned char) (publicY.length() >> 8);
		buffer << (unsigned char) publicY.length();
		buffer << publicY;
		//Writing privateKey
		buffer << (unsigned char) (privateKey.length() >> 8);
		buffer << (unsigned char) privateKey.length();
		buffer << privateKey;
	} else if (keyType == "rsa"){
		//Checking key pair integrality
		string params[] = {"modulus", "publicExponent", "privateExponent"};
		for (int i = 0; i < 3; i++){
			if (!keyPair->count(params[i])) throw new runtime_error("Missing parameter : " + params[i]);
		}
		//Writing the key type
		buffer << (char) 0x01;
		string modulus = keyPair->at("modulus"), publicExponent = keyPair->at("publicExponent"), privateExponent = keyPair->at("privateExponent");
		//Writing the modulus
		buffer << (unsigned char) (modulus.length() >> 8);
		buffer << (unsigned char) modulus.length();
		buffer << modulus;
		//Writing the public exponent
		buffer << (unsigned char) (publicExponent.length() >> 8);
		buffer << (unsigned char) publicExponent.length();
		buffer << publicExponent;
		//Writing the private exponent
		buffer << (unsigned char) (privateExponent.length() >> 8);
		buffer << (unsigned char) privateExponent.length();
		buffer << privateExponent;
	} else if (keyType == "dsa"){
		//Checking key pair integrality
		string params[] = {"primeField", "divider", "base", "publicElement", "privateExponent"};
		for (int i = 0; i < 5; i++){
			if (!(keyPair->count(params[i]) > 0)) throw new runtime_error("Missing parameter : " + params[i]);
		}
		//Writing the key type
		buffer << (char) 0x02;
		string primeField = keyPair->at("primeField"), divider = keyPair->at("divider"), base = keyPair->at("base"), publicElement = keyPair->at("publicElement"), privateExponent = keyPair->at("privateExponent");
		//Writing the primeField
		buffer << (unsigned char) (primeField.length() >> 8);
		buffer << (unsigned char) primeField.length();
		buffer << primeField;
		//Writing the divider
		buffer << (unsigned char) (divider.length() >> 8);
		buffer << (unsigned char) divider.length();
		buffer << divider;
		//Writing the base
		buffer << (unsigned char) (base.length() >> 8);
		buffer << (unsigned char) base.length();
		buffer << base;
		//Writing the publicElement
		buffer << (unsigned char) (publicElement.length() >> 8);
		buffer << (unsigned char) publicElement.length();
		buffer << publicElement;
		//Writing the privateExponent
		buffer << (unsigned char) (privateExponent.length() >> 8);
		buffer << (unsigned char) privateExponent.length();
		buffer << privateExponent;
	} else if (keyType == "ecdh"){
		string params[] = {"curveName", "publicKey", "privateKey"};
		for (int i = 0; i < 3; i++){
			if (!keyPair->count(params[i])) throw new runtime_error("Missing parameter : " + params[i]);
		}
		//Writing the key type
		buffer << (char) 0x03;
		string curveName = keyPair->at("curveName"), publicKey = keyPair->at("publicKey"), privateKey = keyPair->at("privateKey");
		//Writing curveID
		char curveID = getCurveID(curveName);
		buffer << curveID;
		//Writing the public key
		buffer << (unsigned char) (publicKey.length() >> 8);
		buffer << (unsigned char) publicKey.length();
		buffer << publicKey;
		//Writing the private key
		buffer << (unsigned char) (privateKey.length() >> 8);
		buffer << (unsigned char) privateKey.length();
		buffer << privateKey;
	} else throw new runtime_error("Unknown key type");
	return buffer.str();
}

char KeyRing::getCurveID(string curveName){
    //Prime curves
    if (curveName == "secp112r1") return 0x01;
    else if (curveName == "secp112r2") return 0x02;
    else if (curveName == "secp128r1") return 0x03;
    else if (curveName == "secp128r2") return 0x04;
    else if (curveName == "secp160r1") return 0x05;
    else if (curveName == "secp160r2") return 0x06;
    else if (curveName == "secp160k1") return 0x07;
    else if (curveName == "secp192r1") return 0x08;
    else if (curveName == "secp192k1") return 0x09;
    else if (curveName == "secp224r1") return 0x0A;
    else if (curveName == "secp224k1") return 0x0B;
    else if (curveName == "secp256r1") return 0x0C;
    else if (curveName == "secp256k1") return 0x0D;
    else if (curveName == "secp384r1") return 0x0E;
    else if (curveName == "secp521r1") return 0x0F; //End of prime curves, first binary curve
    else if (curveName == "sect113r1") return 0x80;
    else if (curveName == "sect113r2") return 0x81;
    else if (curveName == "sect131r1") return 0x82;
    else if (curveName == "sect131r2") return 0x83;
    else if (curveName == "sect163r1") return 0x84;
    else if (curveName == "sect163r2") return 0x85;
    else if (curveName == "sect163k1") return 0x86;
    else if (curveName == "sect193r1") return 0x87;
    else if (curveName == "sect193r2") return 0x88;
    else if (curveName == "sect233r1") return 0x89;
    else if (curveName == "sect233k1") return 0x8A;
    else if (curveName == "sect239r1") return 0x8B;
    else if (curveName == "sect283r1") return 0x8C;
    else if (curveName == "sect283k1") return 0x8D;
    else if (curveName == "sect409r1") return 0x8E;
    else if (curveName == "sect409k1") return 0x8F;
    else if (curveName == "sect571r1") return 0x90;
    else if (curveName == "sect571k1") return 0x91;
    else throw new runtime_error("Unknown curve name");
}

string KeyRing::getCurveName(char curveID){
    //Prime curves
    if (curveID == 0x01) return "secp112r1";
    else if (curveID == 0x02) return "secp112r2";
    else if (curveID == 0x03) return "secp128r1";
    else if (curveID == 0x04) return "secp128r2";
    else if (curveID == 0x05) return "secp160r1";
    else if (curveID == 0x06) return "secp160r2";
    else if (curveID == 0x07) return "secp160k1";
    else if (curveID == 0x08) return "secp192r1";
    else if (curveID == 0x09) return "secp192k1";
    else if (curveID == 0x0A) return "secp224r1";
    else if (curveID == 0x0B) return "secp224k1";
    else if (curveID == 0x0C) return "secp256r1";
    else if (curveID == 0x0D) return "secp256k1";
    else if (curveID == 0x0E) return "secp384r1";
    else if (curveID == 0x0F) return "secp521r1";
    else if (curveID == 0x80) return "sect113r1"; //End of prime curves, first binary curve
    else if (curveID == 0x81) return "sect113r2";
    else if (curveID == 0x82) return "sect131r1";
    else if (curveID == 0x83) return "sect131r2";
    else if (curveID == 0x84) return "sect163r1";
    else if (curveID == 0x85) return "sect163r2";
    else if (curveID == 0x86) return "sect163k1";
    else if (curveID == 0x87) return "sect193r1";
    else if (curveID == 0x88) return "sect193r2";
    else if (curveID == 0x89) return "sect233r1";
    else if (curveID == 0x8A) return "sect233k1";
    else if (curveID == 0x8B) return "sect239r1";
    else if (curveID == 0x8C) return "sect283r1";
    else if (curveID == 0x8D) return "sect283k1";
    else if (curveID == 0x8E) return "sect409r1";
    else if (curveID == 0x8F) return "sect409k1";
    else if (curveID == 0x90) return "sect571r1";
    else if (curveID == 0x91) return "sect571k1";
    else throw new runtime_error("Unknown curve ID");
}

OID KeyRing::getPCurveFromName(std::string curveName){
    if (curveName == "secp112r1"){
        return CryptoPP::ASN1::secp112r1();
    } else if (curveName == "secp112r2"){
        return CryptoPP::ASN1::secp112r2();
    } else if (curveName == "secp128r1"){
        return CryptoPP::ASN1::secp128r1();
    } else if (curveName == "secp128r2"){
        return CryptoPP::ASN1::secp128r2();
    } else if (curveName == "secp160r1"){
        return CryptoPP::ASN1::secp160r1();
    } else if (curveName == "secp160r2"){
        return CryptoPP::ASN1::secp160r2();
    } else if (curveName == "secp160k1"){
        return CryptoPP::ASN1::secp160k1();
    } else if (curveName == "secp192r1"){
        return CryptoPP::ASN1::secp192r1();
    } else if (curveName == "secp192k1"){
        return CryptoPP::ASN1::secp192k1();
    } else if (curveName == "secp224r1"){
        return CryptoPP::ASN1::secp224r1();
    } else if (curveName == "secp224k1"){
        return CryptoPP::ASN1::secp224k1();
    } else if (curveName == "secp256r1"){
        return CryptoPP::ASN1::secp256r1();
    } else if (curveName == "secp256k1"){
        return CryptoPP::ASN1::secp256k1();
    } else if (curveName == "secp384r1"){
        return CryptoPP::ASN1::secp384r1();
    } else if (curveName == "secp521r1"){
        return CryptoPP::ASN1::secp521r1();
    } else ThrowException(v8::Exception::TypeError(String::New("Invalid prime curve name")));
}

OID KeyRing::getBCurveFromName(std::string curveName){
    if (curveName == "sect113r1"){
        return CryptoPP::ASN1::sect113r1();
    } else if (curveName == "sect113r2"){
        return CryptoPP::ASN1::sect113r2();
    } else if (curveName == "sect131r1"){
        return CryptoPP::ASN1::sect131r1();
    } else if (curveName == "sect131r2"){
        return CryptoPP::ASN1::sect131r2();
    } else if (curveName == "sect163r1"){
        return CryptoPP::ASN1::sect163r1();
    } else if (curveName == "sect163r2"){
        return CryptoPP::ASN1::sect163r2();
    } else if (curveName == "sect163k1"){
        return CryptoPP::ASN1::sect163k1();
    } else if (curveName == "sect193r1"){
        return CryptoPP::ASN1::sect193r1();
    } else if (curveName == "sect193r2"){
        return CryptoPP::ASN1::sect193r2();
    } else if (curveName == "sect233r1"){
        return CryptoPP::ASN1::sect233r1();
    } else if (curveName == "sect233k1"){
        return CryptoPP::ASN1::sect233k1();
    } else if (curveName == "sect239k1"){
        return CryptoPP::ASN1::sect239k1();
    } else if (curveName == "sect283r1"){
        return CryptoPP::ASN1::sect283r1();
    } else if (curveName == "sect283k1"){
        return CryptoPP::ASN1::sect283k1();
    } else if (curveName == "sect409r1"){
        return CryptoPP::ASN1::sect409r1();
    } else if (curveName == "sect409k1"){
        return CryptoPP::ASN1::sect409k1();
    } else if (curveName == "sect571r1"){
        return CryptoPP::ASN1::sect571r1();
    } else if (curveName == "sect571k1"){
        return CryptoPP::ASN1::sect571k1();
    } else ThrowException(v8::Exception::TypeError(String::New("Invalid binary curve name")));
}

std::string KeyRing::bufferHexEncode(byte buffer[], unsigned int size){
	std::string encoded;
	StringSource(buffer, size, true, new HexEncoder(new StringSink(encoded)));
	return encoded;
}

std::string KeyRing::strHexEncode(std::string const& s){
	std::string encoded;
	StringSource(s, true, new HexEncoder(new StringSink(encoded)));
	return encoded;
}

void KeyRing::bufferHexDecode(std::string const& e, byte buffer[], unsigned int bufferSize){
	StringSource(e, true, new HexDecoder(new ArraySink(buffer, bufferSize)));
}

std::string KeyRing::strHexDecode(std::string const& e){
	std::string decoded;
	StringSource(e, true, new HexDecoder(new StringSink(decoded)));
	return decoded;
}

std::string KeyRing::IntegerToHexStr(CryptoPP::Integer const& i){
	byte bigEndian[i.MinEncodedSize()];
	i.Encode(bigEndian, sizeof(bigEndian));
	return bufferHexEncode(bigEndian, sizeof(bigEndian));
}

CryptoPP::Integer KeyRing::HexStrToInteger(std::string const& hexStr){
	byte buffer[hexStr.size() / 2];
	bufferHexDecode(hexStr, buffer, sizeof(buffer));
	CryptoPP::Integer i;
	i.Decode(buffer, sizeof(buffer));
	return i;
}

std::string KeyRing::SecByteBlockToHexStr(SecByteBlock const& array){
    CryptoPP::Integer val;
    val.Decode(array.BytePtr(), array.SizeInBytes());
    return IntegerToHexStr(val);
}

SecByteBlock KeyRing::HexStrToSecByteBlock(std::string const& hexStr){
    CryptoPP::Integer val = HexStrToInteger(hexStr);
    SecByteBlock block(val.MinEncodedSize());
    val.Encode(block.BytePtr(), block.SizeInBytes());
    return block;
}

string KeyRing::strBase64Encode(string const& s){
	string encoded;
	StringSource(s, true, new Base64Encoder(new StringSink(encoded)));
	return encoded;
}

string KeyRing::strBase64Decode(string const& e){
	string decoded;
	StringSource(e, true, new Base64Decoder(new StringSink(decoded)));
	return decoded;
}

void KeyRing::encryptFile(std::string const& filename, std::string content, std::string const& passphrase, unsigned int pbkdfIterations, int aesKeySize){
	if (!(aesKeySize == 256 || aesKeySize == 192 || aesKeySize == 128)) throw new runtime_error("AES key size must be either 128, 192 or 256");
	aesKeySize /= 8;
	AutoSeededRandomPool prng;
	//Generating pbkdf salt
	//cout << "Generating salt" << endl;
	byte salt[16];
	prng.GenerateBlock(salt, sizeof(salt));
	//Copying passphrase to byte array
	//cout << "Copying passphrase to array" << endl;
	byte passphraseArray[passphrase.size()];
	for (int i = 0; i < sizeof(passphraseArray); i++){
		passphraseArray[i] = passphrase[i];
	}
	//Calculating key
	//cout << "Calculating key" << endl;
	byte key[aesKeySize];
	PKCS5_PBKDF2_HMAC<SHA1> derivation;
	derivation.DeriveKey(key, sizeof(key), 0, passphraseArray, sizeof(passphraseArray), salt, sizeof(salt), pbkdfIterations);
	//Generating an IV
	byte iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));
	//Encrypt content
	//cout << "Initializing encryptor" << endl;
	CFB_Mode<AES>::Encryption e;
	e.SetKeyWithIV(key, sizeof(key), iv);
	string encrypted;
	//cout << "Encrypting the buffer" << endl;
	StringSource(content, true, new StreamTransformationFilter(e, new StringSink(encrypted)));
	//Opening file and writing content
	//cout << "Writing file" << endl;
	fstream file(filename.c_str(), ios::out | ios::trunc);
	file << bufferHexEncode(salt, sizeof(salt));
	file << std::endl;
	file << bufferHexEncode(iv, sizeof(iv));
	file << std::endl;
	file << strHexEncode(encrypted);
	file.close();
}

std::string KeyRing::decryptFile(std::string const& filename, std::string const& passphrase, unsigned int pbkdfIterations, int aesKeySize){
	//Checking whether aes key size is valid or not
	if (!(aesKeySize == 256 || aesKeySize == 192 || aesKeySize == 128)) throw new runtime_error("Invalid key size. Must be either 128, 192 or 256 bits");
	aesKeySize /= 8;
	//Copying passphrase to an array
	byte passphraseArray[passphrase.size()];
	for (int i = 0; i < sizeof(passphraseArray); i++){
		passphraseArray[i] = passphrase[i];
	}
	//Opening file, reading pbkdf and AES iv
	fstream file(filename.c_str(), ios::in);
	string saltStr, ivStr, encryptedStr;
	getline(file, saltStr);
	getline(file, ivStr);
	getline(file, encryptedStr);
	file.close();
	//Decodign hex of salt, iv and encrypted content
	byte iv[ivStr.size() / 2], salt[saltStr.size() / 2];
	bufferHexDecode(saltStr, salt, sizeof(salt));
	bufferHexDecode(ivStr, iv, sizeof(iv));
	encryptedStr = strHexDecode(encryptedStr);
	//Calculating key
	byte key[aesKeySize];
	PKCS5_PBKDF2_HMAC<SHA1> derivation;
	derivation.DeriveKey(key, sizeof(key), 0, passphraseArray, sizeof(passphraseArray), salt, sizeof(salt), pbkdfIterations);
	//Decrypting content
	CFB_Mode<AES>::Decryption d;
	d.SetKeyWithIV(key, sizeof(key), iv);
	string decrypted;
	StringSource(encryptedStr, true, new StreamTransformationFilter(d, new StringSink(decrypted)));
	return decrypted;
}
