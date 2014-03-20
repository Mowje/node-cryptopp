/*
Node.js static bindings to the Crypto++ library.
Written by the Syrian watermelon
*/

#define BUILDING_NODE_EXTENSION

#include <cstdlib>
#include <cmath>
#include <string>
#include <iostream>
#include <exception>

#include <v8.h>
#include <node.h>

//Loading the KeyRing class
#include "keyring.h"

//Importing AES
#include <cryptopp/aes.h>
using CryptoPP::AES;

//Importing ECC objects
#include <cryptopp/eccrypto.h>
using CryptoPP::ECP;
using CryptoPP::EC2N;
using CryptoPP::ECIES;
using CryptoPP::ECDSA;
using CryptoPP::ECDH;
using CryptoPP::ECPPoint;
using CryptoPP::EC2NPoint;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::DL_GroupPrecomputation;
using CryptoPP::DL_FixedBasePrecomputation;

//Importing RSA stuff
#include <cryptopp/rsa.h>
using CryptoPP::RSA;
using CryptoPP::RSAFunction;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSASS;

//Importing DSA stuff
#include <cryptopp/dsa.h>
using CryptoPP::DSA;

//Importing DH stuff
#include <cryptopp/dh.h>
using CryptoPP::DH;

//Importing PSS
#include <cryptopp/pssr.h>
using CryptoPP::PSS;

//Importing some tools (filters, block cipher modes, byte structs, exception obj, RNGs)
#include <cryptopp/filters.h>
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;

#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;
using CryptoPP::PK_Encryptor;
using CryptoPP::PK_Decryptor;
using CryptoPP::g_nullNameValuePairs;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::AutoSeededX917RNG;

#include <cryptopp/integer.h>
using CryptoPP::Integer;

#include <cryptopp/sha.h>
using CryptoPP::SHA1;
using CryptoPP::SHA256;

#include <cryptopp/gf2n.h>
using CryptoPP::PolynomialMod2;

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

#include <cryptopp/modes.h>
using CryptoPP::CFB_Mode;

#include <cryptopp/asn.h>
using CryptoPP::OID;
#include <cryptopp/oids.h>

// Importing encodings
#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <cryptopp/base64.h>
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

using namespace v8;

/*
*  Local data transformation methods
*/
// --- HEX ENCODING ---
std::string bufferHexEncode(byte buffer[], unsigned int size){
    std::string encoded;
    StringSource(buffer, size, true, new HexEncoder(new StringSink(encoded)));
    return encoded;
}

std::string strHexEncode(std::string const& s){
    std::string encoded;
    StringSource(s, true, new HexEncoder(new StringSink(encoded)));
    return encoded;
}

void bufferHexDecode(std::string const& encoded, byte receiver[], unsigned int receiverSize){
    StringSource(encoded, true, new HexDecoder(new ArraySink(receiver, receiverSize)));
}

std::string strHexDecode(std::string const& e){
    std::string decoded;
    StringSource(e, true, new HexDecoder(new StringSink(decoded)));
    return decoded;
}

std::string IntegerToHexStr(CryptoPP::Integer const& i){
    byte bigEndian[i.MinEncodedSize()];
    i.Encode(bigEndian, sizeof(bigEndian));
    return bufferHexEncode(bigEndian, sizeof(bigEndian));
}

CryptoPP::Integer HexStrToInteger(std::string const& hexStr){
    byte buffer[hexStr.size() / 2];
    bufferHexDecode(hexStr, buffer, sizeof(buffer));
    CryptoPP::Integer i;
    i.Decode(buffer, sizeof(buffer));
    return i;
}

std::string PolynomialMod2ToHexStr(CryptoPP::PolynomialMod2 const& i){
    byte bigEndian[i.MinEncodedSize()];
    i.Encode(bigEndian, sizeof(bigEndian));
    return bufferHexEncode(bigEndian, sizeof(bigEndian));
}

CryptoPP::PolynomialMod2 HexStrToPolynomialMod2(std::string const& hexStr){
    byte buffer[hexStr.size() / 2];
    bufferHexDecode(hexStr, buffer, sizeof(buffer));
    CryptoPP::PolynomialMod2 i;
    i.Decode(buffer, sizeof(buffer));
    return i;
}

std::string SecByteBlockToHexStr(SecByteBlock const& array){
    CryptoPP::Integer val;
    val.Decode(array.BytePtr(), array.SizeInBytes());
    return IntegerToHexStr(val);
}

SecByteBlock HexStrToSecByteBlock(std::string const& hexStr){
    CryptoPP::Integer val = HexStrToInteger(hexStr);
    SecByteBlock block(val.MinEncodedSize());
    val.Encode(block.BytePtr(), block.SizeInBytes());
    return block;
}
// -- END OF HEX ENCODING

// -- Base64 ENCODING
std::string bufferBase64Encode(byte buffer[], unsigned int size){
    std::string encoded;
    StringSource(buffer, size, true, new Base64Encoder(new StringSink(encoded), false)); // "False" parameter prevents inserting line breaks
    return encoded;
}

std::string strBase64Encode(std::string const& s){
    std::string encoded;
    StringSource(s, true, new HexEncoder(new StringSink(encoded)));
    return encoded;
}

void bufferBase64Decode(std::string const& encoded, byte receiver[], unsigned int receiverSize){
    StringSource(encoded, true, new Base64Decoder(new ArraySink(receiver, receiverSize)));
}

std::string strBase64Decode(std::string const& e){
    std::string decoded;
    StringSource(e, true, new Base64Decoder(new StringSink(decoded)));
    return decoded;
}

std::string IntegerToBase64Str(CryptoPP::Integer const& i){
    byte bigEndian[i.MinEncodedSize()];
    std::cout << "Buffer size on encoding : " << sizeof(bigEndian) << std::endl;
    i.Encode(bigEndian, sizeof(bigEndian));
    return bufferBase64Encode(bigEndian, sizeof(bigEndian));
}

// Finally functional
CryptoPP::Integer Base64StrToInteger(std::string const& base64Str){
    int base64Padding = 0, lastCharIndex = base64Str.length() - 2;
    char lastChar = base64Str[lastCharIndex];
    while (lastChar == '='){
        base64Padding++;
        lastCharIndex--;
        lastChar = base64Str[lastCharIndex];
    }
    //std::cout << "Padding length : " << base64Padding << std::endl;
    int bufferSize = (int)((3.0/4) * base64Str.length() - base64Padding);
    //std::cout << "Buffer size : " << bufferSize << std::endl;
    byte buffer[bufferSize];
    //std::cout << "Buffer size on decoding : " << sizeof(buffer) << std::endl;
    bufferBase64Decode(base64Str, buffer, sizeof(buffer));
    CryptoPP::Integer i;
    i.Decode(buffer, sizeof(buffer));
    return i;
}

/*
*  Hexadecimal encoding/decoding
*/
Handle<Value> hexEncode(const Arguments& args){
    HandleScope scope;
    String::Utf8Value strVal(args[0]->ToString());
    std::string encoded = strHexEncode(std::string(*strVal));
    return scope.Close(String::New(encoded.c_str()));
}

Handle<Value> hexDecode(const Arguments& args){
    HandleScope scope;
    String::Utf8Value strVal(args[0]->ToString());
    std::string decoded = strHexDecode(std::string(*strVal));
    return scope.Close(String::New(decoded.c_str()));
}

/*
*  Base64 encoding/decoding
*/
Handle<Value> base64Encode(const Arguments& args){
    HandleScope scope;
    String::Utf8Value strVal(args[0]->ToString());
    std::string content(*strVal);
    std::string encodedContent;
    StringSource(content, true, new Base64Encoder(new StringSink(encodedContent), false)); // "False" parameter prevents inserting line breaks
    return scope.Close(String::New(encodedContent.c_str()));
}

Handle<Value> base64Decode(const Arguments& args){
    HandleScope scope;
    String::Utf8Value strVal(args[0]->ToString());
    std::string encodedContent(*strVal);
    std::string content;
    StringSource(encodedContent, true, new Base64Decoder(new StringSink(content)));
    return scope.Close(String::New(content.c_str()));
}

/*
* Generation of batikh
*/

Handle<Value> randomBytes(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 1 || args.Length() == 2){
        std::string encoding = "hex";
        if (args.Length() == 2){
            String::AsciiValue encodingVal(args[1]->ToString());
            std::string encodingInput(*encodingVal);
            if (encodingInput == "hex" || encodingInput == "base64"){
                encoding = encodingInput;
            } else {
                ThrowException(v8::Exception::TypeError(String::New("When used, the \"encoding\" parameters must either be \"hex\" for hexadecimal or \"base64\" for Base64 encoding")));
            }
        }
        Local<v8::Integer> numBytesVal = Local<v8::Integer>::Cast(args[0]);
        unsigned int numBytes = numBytesVal->Value();
        byte randomBytes[numBytes];
        AutoSeededRandomPool prng;
        prng.GenerateBlock(randomBytes, sizeof(randomBytes));
        std::string randomString = "";
        if (encoding == "hex"){
            randomString = bufferHexEncode(randomBytes, sizeof(randomBytes));
        } else {
            randomString = bufferBase64Encode(randomBytes, sizeof(randomBytes));
        }
        return scope.Close(String::New(randomString.c_str()));
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters. generateBytes methods takes only the number of bytes to be generated.")));
        return scope.Close(Undefined());
    }
}

/*
*  ECIES key generation, encryption, decryption
*/

OID getPCurveFromName(std::string curveName){
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

OID getBCurveFromName(std::string curveName){
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

// Method signature : ecies.prime.generateKeyPair(curveName, [callback(keyPair)]); returns keyPair object if callback == undefined
Handle<Value> eciesGenerateKeyPairP(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 1 || args.Length() == 2){
        String::Utf8Value curveVal(args[0]->ToString());
        std::string curveName(*curveVal);
        Local<Value> result = Local<Value>::New(Undefined());
        OID curve = getPCurveFromName(curveName);
        //Initializing decryptor
        AutoSeededRandomPool prng;
        ECIES<ECP>::Decryptor d(prng, curve);
        CryptoPP::Integer privateKey = d.GetKey().GetPrivateExponent();
        const DL_GroupParameters_EC<ECP>& params = d.GetKey().GetGroupParameters();
        const DL_FixedBasePrecomputation<ECPPoint>& bpc = params.GetBasePrecomputation();
        const ECPPoint publicKey = bpc.Exponentiate(params.GetGroupPrecomputation(), d.GetKey().GetPrivateExponent());
        Local<Object> keyPair = Object::New();
        keyPair->Set(String::NewSymbol("curveName"), String::New(curveName.c_str()));
        keyPair->Set(String::NewSymbol("privateKey"), String::New(IntegerToHexStr(privateKey).c_str()));
        Local<Object> publicKeyObj = Object::New();
        publicKeyObj->Set(String::NewSymbol("x"), String::New(IntegerToHexStr(publicKey.x).c_str()));
        publicKeyObj->Set(String::NewSymbol("y"), String::New(IntegerToHexStr(publicKey.y).c_str()));
        keyPair->Set(String::NewSymbol("publicKey"), publicKeyObj);
        result = keyPair;
        //Returning the result
        if (args.Length() == 1){
            return scope.Close(result);
        } else {
            Local<Function> callback = Local<Function>::Cast(args[1]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }
}

/*map<string, string>* LLEciesGenerateKeyPairP(string curveName){
        OID curve = getPCurveFromName(curveName);
        //Initializing decryptor
        AutoSeededRandomPool prng;
        ECIES<ECP>::Decryptor d(prng, curve);
        CryptoPP::Integer privateKey = d.GetKey().GetPrivateExponent();
        const DL_GroupParameters_EC<ECP>& params = d.GetKey().GetGroupParameters();
        const DL_FixedBasePrecomputation<ECPPoint>& bpc = params.GetBasePrecomputation();
        const ECPPoint publicKey = bpc.Exponentiate(params.GetGroupPrecomputation(), d.GetKey().GetPrivateExponent());
}*/

//Method signature : ecies.binary.generateKeyPair(curveName, [callback(keyPair)]); returns keyPair objec if callback == undefined
Handle<Value> eciesGenerateKeyPairB(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 1 || args.Length() == 2){
        String::Utf8Value curveVal(args[0]->ToString());
        std::string curveName(*curveVal);
        Local<Value> result = Local<Value>::New(Undefined());
        OID curve = getBCurveFromName(curveName);
        //Initializing decryptor
        AutoSeededRandomPool prng;
        ECIES<EC2N>::Decryptor d(prng, curve);
        CryptoPP::Integer privateKey = d.GetKey().GetPrivateExponent();
        const DL_GroupParameters_EC<EC2N>& params = d.GetKey().GetGroupParameters();
        const DL_FixedBasePrecomputation<EC2NPoint>& bpc = params.GetBasePrecomputation();
        const EC2NPoint publicKey = bpc.Exponentiate(params.GetGroupPrecomputation(), d.GetKey().GetPrivateExponent());
        Local<Object> keyPair = Object::New();
        keyPair->Set(String::NewSymbol("curveName"), String::New(curveName.c_str()));
        keyPair->Set(String::NewSymbol("privateKey"), String::New(IntegerToHexStr(privateKey).c_str()));
        Local<Object> publicKeyObj = Object::New();
        publicKeyObj->Set(String::NewSymbol("x"), String::New(PolynomialMod2ToHexStr(publicKey.x).c_str()));
        publicKeyObj->Set(String::NewSymbol("y"), String::New(PolynomialMod2ToHexStr(publicKey.y).c_str()));
        keyPair->Set(String::NewSymbol("publicKey"), publicKeyObj);
        result = keyPair;
        //Returning the result
        if (args.Length() == 1){
            return scope.Close(result);
        } else {
            Local<Function> callback = Local<Function>::Cast(args[1]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }
}

//Method signature : ecies.prime.encrypt(plainText, publicKey, curveName, [callback(cipherText)]); returns cipherText if callback == undefined
Handle<Value> eciesEncryptP(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 3 || args.Length() == 4){
        //Casting arguments
        String::Utf8Value plainTextVal(args[0]->ToString());
        String::AsciiValue curveNameVal(args[2]->ToString());
        std::string plainText(*plainTextVal), curveName(*curveNameVal), cipherText;
        Local<Object> publicKeyObj = Local<Object>::Cast(args[1]);
        Local<Value> result = Local<Value>::New(Undefined());
        OID curve = getPCurveFromName(curveName);
        //Casting the public key and encrypting the plaintext
        if (!(publicKeyObj->Has(String::New("x")) && publicKeyObj->Has(String::New("y")))) {
            ThrowException(v8::Exception::TypeError(String::New("Invalid public key object")));
            return scope.Close(Local<Value>::New(Undefined()));
        }
        AutoSeededRandomPool prng;
        ECIES<ECP>::Encryptor e;
        Local<String> xVal, yVal;
        xVal = Local<String>::Cast(publicKeyObj->Get(String::New("x")));
        yVal = Local<String>::Cast(publicKeyObj->Get(String::New("y")));
        const ECPPoint publicKey(HexStrToInteger(*(String::AsciiValue(xVal))), HexStrToInteger(*(String::AsciiValue(yVal))));
        e.AccessKey().AccessGroupParameters().Initialize(curve);
        e.AccessKey().SetPublicElement(publicKey);
        StringSource(plainText, true, new PK_EncryptorFilter(prng, e, new StringSink(cipherText)));
        cipherText = strHexEncode(cipherText);
        result = String::New(cipherText.c_str());
        //Returning the result
        if (args.Length() == 3){
            return scope.Close(result);
        } else {
            Local<Function> callback = Local<Function>::Cast(args[3]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    } // Invalid number of parameters
}

//Method signature : ecies.prime.decrypt(cipherText, privateKey, curveName, [callback(plainText)]); return plainText if callback == undefined
Handle<Value> eciesDecryptP(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 3 || args.Length() == 4){
        //Casting the arguments
        String::AsciiValue cipherTextVal(args[0]->ToString()), privateKeyVal(args[1]->ToString()), curveNameVal(args[2]->ToString()); 
        std::string cipherText(*cipherTextVal), curveName(*curveNameVal), plainText;
        const CryptoPP::Integer privateKey = HexStrToInteger(*privateKeyVal);
        cipherText = strHexDecode(cipherText);
        Local<Value> result = Local<Value>::New(Undefined());
        OID curve = getPCurveFromName(curveName);
        //Decrypting
        AutoSeededRandomPool prng;
        ECIES<ECP>::Decryptor d;
        d.AccessKey().AccessGroupParameters().Initialize(curve);
        d.AccessKey().SetPrivateExponent(privateKey);
        try {
            StringSource(cipherText, true, new PK_DecryptorFilter(prng, d, new StringSink(plainText)));
        } catch (CryptoPP::Exception const& ex){
            std::cerr << "Exception : " << std::endl << ex.what() << std::endl;
            std::cerr << "Error type : " << ex.GetErrorType() << std::endl;
            std::cerr << "What : " << ex.GetWhat() << std::endl;
        }
        result = String::New(plainText.c_str());
        //Returning the result
        if (args.Length() == 3){
            return scope.Close(result);
        } else {
            Local<Function> callback = Local<Function>::Cast(args[3]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }
}

//Method signature ecies.binary.encrypt(plainText, publicKey, curveName, [callback(cipherText)]); returns cipherText if no callback is given
Handle<Value> eciesEncryptB(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 3 || args.Length() == 4){
        //Casting the arguments
        String::Utf8Value plainTextVal(args[0]->ToString());
        String::AsciiValue curveNameVal(args[2]->ToString());
        std::string plainText(*plainTextVal), curveName(*curveNameVal), cipherText;
        Local<Object> publicKeyObj = Local<Object>::Cast(args[1]);
        Local<Value> result = Local<Value>::New(Undefined());
        OID curve = getBCurveFromName(curveName);
        //Casting the public key and encrypting the plaintext
        if (!(publicKeyObj->Has(String::New("x")) && publicKeyObj->Has(String::New("y")))) {
            ThrowException(v8::Exception::TypeError(String::New("Invalid public key object")));
            return scope.Close(Local<Value>::New(Undefined()));
        }
        AutoSeededRandomPool prng;
        ECIES<EC2N>::Encryptor e;
        Local<String> xVal, yVal;
        xVal = Local<String>::Cast(publicKeyObj->Get(String::New("x")));
        yVal = Local<String>::Cast(publicKeyObj->Get(String::New("y")));
        const EC2NPoint publicKey(HexStrToPolynomialMod2(*(String::AsciiValue(xVal))), HexStrToPolynomialMod2(*(String::AsciiValue(yVal))));
        e.AccessKey().AccessGroupParameters().Initialize(curve);
        e.AccessKey().SetPublicElement(publicKey);
        StringSource(plainText, true, new PK_EncryptorFilter(prng, e, new StringSink(cipherText)));
        cipherText = strHexEncode(cipherText);
        result = String::New(cipherText.c_str());
        //Returning the result
        if (args.Length() == 3){
            return scope.Close(result);
        } else {
            Local<Function> callback = Local<Function>::Cast(args[3]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }
}

//Method signature : ecies.binary.decrypt(cipherText, privateKey, curveName, [callback(plainText)]); return plainText if no callback is given
Handle<Value> eciesDecryptB(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 3 || args.Length() == 4){
        //Casting the arguments
        String::AsciiValue cipherTextVal(args[0]->ToString()), privateKeyVal(args[1]->ToString()), curveNameVal(args[2]->ToString());
        std::string cipherText(*cipherTextVal), curveName(*curveNameVal), plainText;
        const CryptoPP::Integer privateKey(HexStrToInteger(*privateKeyVal));
        cipherText = strHexDecode(cipherText);
        Local<Value> result = Local<Value>::New(Undefined());
        OID curve = getBCurveFromName(curveName);
        //Decrypting the ciphertext
        AutoSeededRandomPool prng;
        ECIES<EC2N>::Decryptor d;
        d.AccessKey().AccessGroupParameters().Initialize(curve);
        d.AccessKey().SetPrivateExponent(privateKey);
        StringSource(cipherText, true, new PK_DecryptorFilter(prng, d, new StringSink(plainText)));
        result = String::New(plainText.c_str());
        //Returning the result
        if (args.Length() == 3){
            return scope.Close(result);
        } else {
            Local<Function> callback = Local<Function>::Cast(args[3]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }
}

/*
* ECDSA key generation, signature and verification -- Uses SHA256
*/

//Method signature : ecdsa.prime.generateKeyPair(curveName, [callback(keyPair)])
Handle<Value> ecdsaGenerateKeyPairP(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 1 || args.Length() == 2){
        String::AsciiValue curveNameVal(args[0]->ToString());
        std::string curveName(*curveNameVal);
        Local<Value> result = Local<Value>::New(Undefined());
        //Checking the existence of the curve
        OID curve = getPCurveFromName(curveName);
        //Generating the private key, then the public key.
        AutoSeededRandomPool prng;
        ECDSA<ECP, SHA256>::PrivateKey privateKey;
        ECDSA<ECP, SHA256>::PublicKey publicKey;
        privateKey.Initialize(prng, curve);
        privateKey.MakePublicKey(publicKey);
        // Extracting the values of each key
        const CryptoPP::Integer privateExponent = privateKey.GetPrivateExponent();
        const ECPPoint publicPoint = publicKey.GetPublicElement();
        Local<Object> keyPair = Object::New();
        keyPair->Set(String::NewSymbol("curveName"), String::New(curveName.c_str()));
        keyPair->Set(String::NewSymbol("privateKey"), String::New(IntegerToHexStr(privateExponent).c_str()));
        Local<Object> publicKeyObj = Object::New();
        publicKeyObj->Set(String::NewSymbol("x"), String::New(IntegerToHexStr(publicPoint.x).c_str()));
        publicKeyObj->Set(String::NewSymbol("y"), String::New(IntegerToHexStr(publicPoint.y).c_str()));
        keyPair->Set(String::NewSymbol("publicKey"), publicKeyObj);
        result = keyPair;
       //Returning the result
        if (args.Length() == 1){
            return scope.Close(result);
        } else {
            Local<Function> callback = Local<Function>::Cast(args[1]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }
}

//Method signature : ecdsa.prime.sign(message, privateKey, curveName, [hashName], [callback(signature)]); if no callback is given then the signature is returned
Handle<Value> ecdsaSignMessageP(const Arguments& args){
    HandleScope scope;
    if (args.Length() >= 3 && args.Length() <= 5){
        String::Utf8Value messageVal(args[0]->ToString());
        String::AsciiValue privateKeyVal(args[1]->ToString()), curveNameVal(args[2]->ToString());
        std::string curveName(*curveNameVal), message(*messageVal), privateKeyStr(*privateKeyVal), signature, hashName = "";
        if (args.Length() >= 4){
            if (!args[3]->IsUndefined()){
                String::Utf8Value hashNameVal(args[3]->ToString());
                hashName = std::string(*hashNameVal);
                if (!(hashName == "sha1" || hashName == "sha256")){
                    ThrowException(v8::Exception::TypeError(String::New("Invalid hash function name")));
                    return scope.Close(Undefined());
                }
            }
        }
        Local<Value> result = Local<Value>::New(Undefined());
        //Checking the existence of the curve
        OID curve = getPCurveFromName(curveName);
        //Method body
        AutoSeededRandomPool prng;
        if (hashName == "" || hashName == "sha1"){
            ECDSA<ECP, SHA1>::PrivateKey privateKey;
            privateKey.Initialize(prng, curve);
            privateKey.SetPrivateExponent(HexStrToInteger(privateKeyStr));
            StringSource(message, true, new SignerFilter(prng, ECDSA<ECP, SHA1>::Signer(privateKey), new StringSink(signature)));
        } else {
            ECDSA<ECP, SHA256>::PrivateKey privateKey;
            privateKey.Initialize(prng, curve);
            privateKey.SetPrivateExponent(HexStrToInteger(privateKeyStr));
            StringSource(message, true, new SignerFilter(prng, ECDSA<ECP, SHA256>::Signer(privateKey), new StringSink(signature)));
        }
        signature = strHexEncode(signature);
        result = String::New(signature.c_str());
        // Returning the result
        if (args.Length() < 5){
            return scope.Close(result);
        } else {
            if (args[4]->IsUndefined()) return scope.Close(result);
            Local<Function> callback = Local<Function>::Cast(args[4]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }
}

//Method signature : ecdsa.prime.verify(message, signature, publicKey, curveName, [hashName], [callback(authentic)]); if no callback is given then the methods returns a boolean, whether the message is authentic or not
Handle<Value> ecdsaVerifyMessageP(const Arguments& args){
    HandleScope scope;
    if (args.Length() >= 4 && args.Length() <= 6){
        String::Utf8Value messageVal(args[0]->ToString());
        String::AsciiValue signatureVal(args[1]->ToString()), curveNameVal(args[3]->ToString());
        Local<Object> publicKeyObj = Local<Object>::Cast(args[2]);
        std::string message(*messageVal), signature(*signatureVal), curveName(*curveNameVal), hashName = "";
        if (args.Length() >= 5){
            if (!args[4]->IsUndefined()){
                String::Utf8Value hashNameVal(args[4]->ToString());
                hashName = std::string(*hashNameVal);
                if (!(hashName == "sha1" || hashName == "sha256")){
                    ThrowException(v8::Exception::TypeError(String::New("Invalid hash function name")));
                    return scope.Close(Undefined());
                }
            }
        }
        Local<Value> result = Local<Value>::New(Undefined());
        //Checking the existence of the curve
        if (!(publicKeyObj->Has(String::New("x")) && publicKeyObj->Has(String::New("y")))){
            ThrowException(v8::Exception::TypeError(String::New("Invalid public key object")));
            return scope.Close(Local<Value>::New(Undefined()));
        }
        OID curve = getPCurveFromName(curveName);
        //Method body
        bool valid = false;
        AutoSeededRandomPool prng;
        if (hashName == "" || hashName == "sha1"){
            ECDSA<ECP, SHA1>::PublicKey publicKey;
            Local<String> xVal, yVal;
            xVal = Local<String>::Cast(publicKeyObj->Get(String::NewSymbol("x")));
            yVal = Local<String>::Cast(publicKeyObj->Get(String::NewSymbol("y")));
            const ECPPoint publicElement(HexStrToInteger(*(String::AsciiValue(xVal))), HexStrToInteger(*(String::AsciiValue(yVal))));
            publicKey.Initialize(curve, publicElement);
            signature = strHexDecode(signature);
            StringSource(signature+message, true, new SignatureVerificationFilter(ECDSA<ECP, SHA1>::Verifier(publicKey), new ArraySink( (byte*)&valid, sizeof(valid) )));
        } else {
            ECDSA<ECP, SHA256>::PublicKey publicKey;
            Local<String> xVal, yVal;
            xVal = Local<String>::Cast(publicKeyObj->Get(String::NewSymbol("x")));
            yVal = Local<String>::Cast(publicKeyObj->Get(String::NewSymbol("y")));
            const ECPPoint publicElement(HexStrToInteger(*(String::AsciiValue(xVal))), HexStrToInteger(*(String::AsciiValue(yVal))));
            publicKey.Initialize(curve, publicElement);
            signature = strHexDecode(signature);
            StringSource(signature+message, true, new SignatureVerificationFilter(ECDSA<ECP, SHA256>::Verifier(publicKey), new ArraySink( (byte*)&valid, sizeof(valid) )));
        }
        result = BooleanObject::New(valid);
        //Returning the result
        if (args.Length() < 6){
            return scope.Close(result);
        } else {
            if (args[5]->IsUndefined()) return scope.Close(result);
            Local<Function> callback = Local<Function>::Cast(args[5]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }

}

//Method signature : cryptopp.ecdsa.binary.generateKeyPair(curveName, [callback(keyPair)])
Handle<Value> ecdsaGenerateKeyPairB(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 1 || args.Length() == 2){
        //Casting the curveName parameter
        String::AsciiValue curveNameVal(args[0]->ToString());
        std::string curveName(*curveNameVal);
        Local<Value> result = Local<Value>::New(Undefined());
        OID curve = getBCurveFromName(curveName);
        //Generating the keypair
        AutoSeededRandomPool prng;
        ECDSA<EC2N, SHA256>::PrivateKey privateKey;
        ECDSA<EC2N, SHA256>::PublicKey publicKey;
        privateKey.Initialize(prng, curve);
        privateKey.MakePublicKey(publicKey);
        //Building the result object
        const CryptoPP::Integer privateExponent = privateKey.GetPrivateExponent();
        const CryptoPP::EC2NPoint publicPoint = publicKey.GetPublicElement();
        Local<Object> keyPair = Object::New();
        keyPair->Set(String::NewSymbol("curveName"), String::New(curveName.c_str()));
        keyPair->Set(String::NewSymbol("privateKey"), String::New(IntegerToHexStr(privateExponent).c_str()));
        Local<Object> pubKeyObj = Object::New();
        pubKeyObj->Set(String::NewSymbol("x"), String::New(PolynomialMod2ToHexStr(publicPoint.x).c_str()));
        pubKeyObj->Set(String::NewSymbol("y"), String::New(PolynomialMod2ToHexStr(publicPoint.y).c_str()));
        keyPair->Set(String::NewSymbol("publicKey"), pubKeyObj);
        result = keyPair;
        //Return the resulting object
        if (args.Length() == 1){
            return scope.Close(result);
        } else {
            Local<Function> callback = Local<Function>::Cast(args[1]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }
}

//Method signature : cryptopp.ecdsa.binary.sign(message, privateKey, curveName, [callback(signature)])
Handle<Value> ecdsaSignMessageB(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 3 || args.Length() == 4){
        //Casting parameters
        String::Utf8Value messageVal(args[0]->ToString());
        String::AsciiValue curveNameVal(args[1]->ToString()), privateKeyVal(args[2]->ToString());
        std::string message(*messageVal), curveName(*curveNameVal), privateKeyStr(*privateKeyVal), signature;
        Local<Value> result = Local<Value>::New(Undefined());
        //Checking curve existence and loading it.
        try {
            OID curve = getBCurveFromName(curveName);
            std::cout << "Curve OID loaded" << std::endl;
            //Generating the signature
            AutoSeededRandomPool prng;
            std::cout << "Generator initialized" << std::endl;
            ECDSA<EC2N, SHA256>::PrivateKey privateKey;
            privateKey.Initialize(prng, curve);
            std::cout << "Curve initialized" << std::endl;
            privateKey.SetPrivateExponent(HexStrToInteger(privateKeyStr));
            std::cout << "Key initialized" << std::endl;
            StringSource(message, true, new SignerFilter(prng, ECDSA<EC2N, SHA256>::Signer(privateKey), new StringSink(signature)));
            signature = strHexEncode(signature);
            result = String::New(signature.c_str());
        } catch (CryptoPP::Exception& e){
            std::cout << "An exception occured :" << std::endl << e.what() << std::endl;
            ThrowException(v8::Exception::TypeError(String::New(e.what())));
            return scope.Close(Undefined());
        }
        if (args.Length() == 3){
            return scope.Close(result);
        } else {
            Local<Function> callback = Local<Function>::Cast(args[3]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined()); 
    }
}

//Method signature : cryptopp.ecdsa.verify(message, signature, publicKey, curveName, [callback(isValid)])
Handle<Value> ecdsaVerifyMessageB(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 4 || args.Length() == 5){
        //Casting parameters
        String::Utf8Value messageVal(args[0]->ToString());
        String::AsciiValue signatureVal(args[1]->ToString()), curveNameVal(args[3]->ToString());
        std::string message(*messageVal), signature(*signatureVal), curveName(*curveNameVal);
        bool isValid = false;
        Local<Value> result = Local<Value>::New(Undefined());
        Local<Object> publicKeyObj = Local<Object>::Cast(args[2]);
        //Checking curve existence and loading it. Checking attributes of public key object
        if (!(publicKeyObj->Has(String::New("x")) && publicKeyObj->Has(String::New("y")))){
            ThrowException(v8::Exception::TypeError(String::New("Invalid public key object")));
            return scope.Close(Local<Value>::New(Undefined()));
        }
        OID curve = getBCurveFromName(curveName);
        //Verifying signature
        AutoSeededRandomPool prng;
        ECDSA<EC2N, SHA256>::PublicKey publicKey;
        Local<String> xVal, yVal;
        xVal = Local<String>::Cast(publicKeyObj->Get(String::NewSymbol("x")));
        yVal = Local<String>::Cast(publicKeyObj->Get(String::NewSymbol("y")));
        const EC2NPoint publicElement(HexStrToPolynomialMod2(*(String::AsciiValue(xVal))), HexStrToPolynomialMod2(*(String::AsciiValue(yVal))));
        publicKey.Initialize(curve, publicElement);
        signature = strHexDecode(signature);
        StringSource(signature+message, true, new SignatureVerificationFilter(ECDSA<EC2N, SHA256>::Verifier(publicKey), new ArraySink( (byte*) &isValid, sizeof(isValid) )));
        result = BooleanObject::New(isValid);
        //Return the result
        if (args.Length() == 4){
            return scope.Close(result);
        } else {
            Local<Function> callback = Local<Function>::Cast(args[4]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined()); 
    }
}

// ECDH key agreement algorithm : key generation and secret agreement

// Method signature : cryptopp.ecdh.prime.generateKeyPair(curveName, [callback(keyPair)])
Handle<Value> ecdhGenerateKeyPairP(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 1 || args.Length() == 2){
        String::AsciiValue curveNameVal(args[0]->ToString());
        std::string curveName(*curveNameVal);
        Local<Value> result = Local<Value>::New(Undefined());
        //Checking the existence of the curve
        OID curve = getPCurveFromName(curveName);
        //Method body
        AutoSeededX917RNG<AES> prng;
        ECDH<ECP>::Domain dhDomain(curve);
        SecByteBlock privKey(dhDomain.PrivateKeyLength()), publicKey(dhDomain.PublicKeyLength());
        dhDomain.GenerateKeyPair(prng, privKey, publicKey);
        Local<Object> keyPair = Object::New();
        keyPair->Set(String::NewSymbol("curveName"), String::New(curveName.c_str()));
        keyPair->Set(String::NewSymbol("privateKey"), String::New(SecByteBlockToHexStr(privKey).c_str()));
        keyPair->Set(String::NewSymbol("publicKey"), String::New(SecByteBlockToHexStr(publicKey).c_str()));
        result = keyPair;
        //Returning the result
        if (args.Length() == 1){
            return scope.Close(result);
        } else {
            Local<Function> callback = Local<Function>::Cast(args[1]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }

}

//Method signature : cryptopp.ecdh.prime.agree(yourPrivateKey, counterpartsPublicKey, curveName, [callback(secret)]) : returns the secret if no callback is given
Handle<Value> ecdhAgreeP(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 3 || args.Length() == 4){
        String::AsciiValue privateKeyVal(args[0]->ToString()), publicKeyVal(args[1]->ToString()), curveNameVal(args[2]->ToString());
        std::string curveName(*curveNameVal), privateKeyStr(*privateKeyVal), publicKeyStr(*publicKeyVal);
        Local<Value> result = Local<Value>::New(Undefined());
        //Checking the existence of the curve
        OID curve = getPCurveFromName(curveName);
        //Method body
        ECDH<ECP>::Domain dhDomain(curve);
        SecByteBlock privateKey = HexStrToSecByteBlock(privateKeyStr);
        SecByteBlock publicKey = HexStrToSecByteBlock(publicKeyStr);
        SecByteBlock secret(dhDomain.AgreedValueLength());
        dhDomain.Agree(secret, privateKey, publicKey);
        result = String::New(SecByteBlockToHexStr(secret).c_str());
        //Returning the result
        if (args.Length() == 3){
            return scope.Close(result);
        } else {
            Local<Function> callback = Local<Function>::Cast(args[3]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }
}

//Method signature : cryptopp.ecdh.binary.generateKeyPair(curveName, [callback(keyPair)])
Handle<Value> ecdhGenerateKeyPairB(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 1 || args.Length() == 2){
        String::AsciiValue curveNameVal(args[0]->ToString());
        std::string curveName(*curveNameVal);
        Local<Value> result = Local<Value>::New(Undefined());
        //Checking curve existence and loading it.
        OID curve = getBCurveFromName(curveName);
        //Method body
        AutoSeededX917RNG<AES> prng;
        ECDH<EC2N>::Domain dhDomain(curve);
        SecByteBlock privKey(dhDomain.PrivateKeyLength()), pubKey(dhDomain.PublicKeyLength());
        dhDomain.GenerateKeyPair(prng, privKey, pubKey);
        Local<Object> keyPair = Object::New();
        keyPair->Set(String::NewSymbol("curveName"), String::New(curveName.c_str()));
        keyPair->Set(String::NewSymbol("privateKey"), String::New(SecByteBlockToHexStr(privKey).c_str()));
        keyPair->Set(String::NewSymbol("publicKey"), String::New(SecByteBlockToHexStr(pubKey).c_str()));
        result = keyPair;
        if (args.Length() == 1){
            return scope.Close(result);
        } else {
            Local<Function> callback = Local<Function>::Cast(args[1]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }
}

//Method signature : cryptopp.ecdh.binary.agree(yourPrivateKey, counterpartsPublicKey, curveName, [callback(secret)])
Handle<Value> ecdhAgreeB(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 3 || args.Length() == 4){
        String::AsciiValue privateKeyVal(args[0]->ToString()), publicKeyVal(args[1]->ToString()), curveNameVal(args[2]->ToString());
        std::string curveName(*curveNameVal), privateKeyStr(*privateKeyVal), publicKeyStr(*publicKeyVal);
        Local<Value> result = Local<Value>::New(Undefined());
        //Checking curve existence and loading it
        OID curve = getBCurveFromName(curveName);
        //Method body
        ECDH<EC2N>::Domain dhDomain(curve);
        SecByteBlock privateKey = HexStrToSecByteBlock(privateKeyStr);
        SecByteBlock publicKey = HexStrToSecByteBlock(publicKeyStr);
        SecByteBlock secret(dhDomain.AgreedValueLength());
        dhDomain.Agree(secret, privateKey, publicKey);
        result = String::New(SecByteBlockToHexStr(secret).c_str());
        //Returning the result
        if (args.Length() == 3){
            return scope.Close(result);
        } else {
            Local<Function> callback = Local<Function>::Cast(args[3]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }
}

/*
* RSA encryption algorithm; key generation, encryption and decryption, signature and verification
*/

// Method signature : cryptopp.rsa.generateKeyPair(sizeInBits, [callback(keyPair)])
Handle<Value> rsaGenerateKeyPair(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 1 || args.Length() == 2){
        Local<Value> result;
        //Casting the keySize parameters
        Local<v8::Integer> keySizeVal = Local<v8::Integer>::Cast(args[0]);
        int keySize = keySizeVal->Value();
        //Checking the user provided key size
        if (!(keySize >= 1024 && keySize <= 16384)) {
            ThrowException(v8::Exception::RangeError(String::New("Invalid key size. Allowed key sizes : between 1024 and 16384 bits")));
            return scope.Close(Undefined());
        }
        /*bool validKeySize = false;
        int testedKeySize = 1024;
        while (testedKeySize <= 16384){
            if (testedKeySize == keySize) {
                validKeySize = true;
                break;
            } else testedKeySize *= 2;
        }
        if (!validKeySize) {
            ThrowException(v8::Exception::RangeError(String::New("Invalid key size. Allowed key sizes : 1024, 2048, 4096, 8192, 16384 bits")));
            return scope.Close(Undefined());
        }*/
        //Generating the key pair
        AutoSeededRandomPool prng;
        InvertibleRSAFunction keyPairParams;
        keyPairParams.GenerateRandomWithKeySize(prng, keySize);
        //Building the result object
        Local<Object> keyPair = Object::New();
        keyPair->Set(String::NewSymbol("modulus"), String::New(IntegerToHexStr(keyPairParams.GetModulus()).c_str()));
        keyPair->Set(String::NewSymbol("publicExponent"), String::New(IntegerToHexStr(keyPairParams.GetPublicExponent()).c_str()));
        keyPair->Set(String::NewSymbol("privateExponent"), String::New(IntegerToHexStr(keyPairParams.GetPrivateExponent()).c_str()));
        result = keyPair;
        if (args.Length() == 1){
            return scope.Close(result);
        } else {
            Local<Function> callback = Local<Function>::Cast(args[1]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }
}

// Method signature : cryptopp.rsa.encrypt(plainText, modulus, publicExponent, [callback(cipherText)])
Handle<Value> rsaEncrypt(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 3 || args.Length() == 4){
        //Casting arguments
        String::Utf8Value plainTextVal(args[0]->ToString());
        String::AsciiValue modulusVal(args[1]->ToString()), publicExpVal(args[2]->ToString());
        std::string plainText(*plainTextVal), modulusStr(*modulusVal), publicExpStr(*publicExpVal), cipherText;
        Local<Value> result;
        //Encrypting the plainText
        AutoSeededRandomPool prng;
        RSAFunction publicParams;
        publicParams.Initialize(HexStrToInteger(modulusStr), HexStrToInteger(publicExpStr));
        RSA::PublicKey publicKey(publicParams);
        RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
        StringSource(plainText, true, new PK_EncryptorFilter(prng, encryptor, new StringSink(cipherText)));
        result = String::New(strHexEncode(cipherText).c_str());
        //Returning the result
        if (args.Length() == 3){
            return scope.Close(result);
        } else {
            Local<Function> callback = Local<Function>::Cast(args[3]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }
}

// Method signature : cryptopp.rsa.decrypt(cipherText, modulus, privateExponent, publicExponent, [callback(plainText)])
Handle<Value> rsaDecrypt(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 4 || args.Length() == 5){
        //Casting arguments
        String::AsciiValue cipherTextVal(args[0]->ToString()), modulusVal(args[1]->ToString()), privateExpVal(args[2]->ToString()), publicExpVal(args[3]->ToString());
        std::string cipherText(*cipherTextVal), modulusStr(*modulusVal), privateExpStr(*privateExpVal), publicExpStr(*publicExpVal), plainText;
        Local<Value> result = Local<Value>::New(Undefined());
        //Decrypting cipherText
        AutoSeededRandomPool prng;
        InvertibleRSAFunction privateParams;
        privateParams.Initialize(HexStrToInteger(modulusStr), HexStrToInteger(publicExpStr), HexStrToInteger(privateExpStr));
        RSA::PrivateKey privateKey(privateParams);
        RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
        cipherText = strHexDecode(cipherText);
        StringSource(cipherText, true, new PK_DecryptorFilter(prng, decryptor, new StringSink(plainText)));
        result = String::New(plainText.c_str());
        //Returning the result
        if (args.Length() == 4){
            return scope.Close(result);
        } else {
            Local<Function> callback = Local<Function>::Cast(args[4]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }
}

// Method signature : cryptopp.rsa.sign(message, modulus, privateExponent, publicExponent, [hashName], [callback(signature)])
Handle<Value> rsaSign(const Arguments& args){
    HandleScope scope;
    if (args.Length() >= 4 && args.Length() <= 6){
        //Casting arguments
        String::Utf8Value messageVal(args[0]->ToString());
        String::AsciiValue modulusVal(args[1]->ToString()), privateExpVal(args[2]->ToString()), publicExpVal(args[3]->ToString());
        std::string message(*messageVal), modulusStr(*modulusVal), privateExpStr(*privateExpVal), publicExpStr(*publicExpVal), signature, hashName = "";
        //Casting the hashName argument
        if (args.Length() >= 5){
            if (!args[4]->IsUndefined()){
                String::Utf8Value hashNameVal(args[4]->ToString());
                hashName = std::string(*hashNameVal);
                if (!(hashName == "sha1" || hashName == "sha256")){
                    ThrowException(v8::Exception::TypeError(String::New("Invalid hash function name")));
                    return scope.Close(Undefined());
                }
            }
        }
        Local<Value> result = Local<Value>::New(Undefined());
        //Signing the message
        AutoSeededRandomPool prng;
        InvertibleRSAFunction privateParams;
        privateParams.Initialize(HexStrToInteger(modulusStr), HexStrToInteger(publicExpStr), HexStrToInteger(privateExpStr));
        RSA::PrivateKey privateKey(privateParams);
        if (hashName == "" || hashName == "sha1"){
            RSASS<PSS, SHA1>::Signer signer(privateKey);
            StringSource(message, true, new SignerFilter(prng, signer, new StringSink(signature)));
        } else {
            RSASS<PSS, SHA256>::Signer signer(privateKey);
            StringSource(message, true, new SignerFilter(prng, signer, new StringSink(signature)));
        }
        signature = strHexEncode(signature);
        result = String::New(signature.c_str());
        if (args.Length() < 6){
            return scope.Close(result);
        } else {
            if (args[5]->IsUndefined()) return scope.Close(result);
            Local<Function> callback = Local<Function>::Cast(args[5]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }
}

// Method signature : cryptopp.rsa.verify(message, signature, modulus, publicExponent, [hashName], [callback(isValid)])
Handle<Value> rsaVerify(const Arguments& args){
    HandleScope scope;
    if (args.Length() >= 4 || args.Length() <= 6){
        //Casting parameters
        String::Utf8Value messageVal(args[0]->ToString());
        String::AsciiValue signatureVal(args[1]->ToString()), modulusVal(args[2]->ToString()), publicExpVal(args[3]->ToString());
        std::string message(*messageVal), signature(*signatureVal), modulusStr(*modulusVal), publicExpStr(*publicExpVal), hashName = "";
        signature = strHexDecode(signature);
        if (args.Length() >= 5){
            if (!args[4]->IsUndefined()){
                String::Utf8Value hashNameVal(args[4]->ToString());
                hashName = std::string(*hashNameVal);
                if (!(hashName == "sha1" || hashName == "sha256")){
                    ThrowException(v8::Exception::TypeError(String::New("Invalid hash function name")));
                    return scope.Close(Undefined());
                }
            }
        }
        Local<Value> result = Local<Value>::New(Undefined());
        //Verifying the signature
        RSAFunction publicParams;
        bool isValid = false;
        publicParams.Initialize(HexStrToInteger(modulusStr), HexStrToInteger(publicExpStr));
        RSA::PublicKey publicKey(publicParams);
        if (hashName == "" || hashName == "sha1"){
            RSASS<PSS, SHA1>::Verifier verifier(publicKey);
            StringSource(signature+message, true, new SignatureVerificationFilter(verifier, new ArraySink( (byte*)&isValid, sizeof(isValid) )));
        } else {
            RSASS<PSS, SHA256>::Verifier verifier(publicKey);
            StringSource(signature+message, true, new SignatureVerificationFilter(verifier, new ArraySink( (byte*)&isValid, sizeof(isValid) )));
        }
        result = BooleanObject::New(isValid);
        //Returning the result
        if (args.Length() < 6){
            return scope.Close(result);
        } else {
            if (args[5]->IsUndefined()) return scope.Close(Undefined());
            Local<Function> callback = Local<Function>::Cast(args[5]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }
}

/*
* DSA signature and verification
*/

//Method signature : cryptopp.dsa.generateKeyPair(keySize, [callback(keyPair)])
Handle<Value> dsaGenerateKeyPair(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 1 || args.Length() == 2){
        Local<Value> result;

        Local<v8::Integer> keySizeVal = Local<v8::Integer>::Cast(args[0]);
        int keySize = keySizeVal->Value();

        AutoSeededRandomPool prng;
        DSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(prng, keySize);
        DSA::PublicKey publicKey;
        publicKey.AssignFrom(privateKey);

        Local<Object> keyPair = Object::New();
        keyPair->Set(String::NewSymbol("primeField"), String::New(IntegerToHexStr(privateKey.GetGroupParameters().GetModulus()).c_str()));
        keyPair->Set(String::NewSymbol("divider"), String::New(IntegerToHexStr(privateKey.GetGroupParameters().GetSubgroupOrder()).c_str()));
        keyPair->Set(String::NewSymbol("base"), String::New(IntegerToHexStr(privateKey.GetGroupParameters().GetSubgroupGenerator()).c_str()));
        keyPair->Set(String::NewSymbol("privateExponent"), String::New(IntegerToHexStr(privateKey.GetPrivateExponent()).c_str()));
        keyPair->Set(String::NewSymbol("publicElement"), String::New(IntegerToHexStr(publicKey.GetPublicElement()).c_str()));
        result = keyPair;
        if (args.Length() == 1){
            return scope.Close(result);
        } else {
            Local<Function> callback = Local<Function>::Cast(args[1]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }
}

//Method signature : cryptopp.dsa.sign(message, primeField, divider, base, privateExponent, [callback(signature)])
Handle<Value> dsaSign(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 5 || args.Length() == 6){
        Local<Value> result;

        String::Utf8Value messageVal(args[0]->ToString());
        String::AsciiValue fieldPrimeVal(args[1]->ToString()), dividerVal(args[2]->ToString()), baseVal(args[3]->ToString()), privateExponentVal(args[4]);
        std::string message(*messageVal), signature;
        CryptoPP::Integer fieldPrime(HexStrToInteger(*fieldPrimeVal)), divider(HexStrToInteger(*dividerVal)), base(HexStrToInteger(*baseVal)), privateExponent(HexStrToInteger(*privateExponentVal));

        DSA::PrivateKey privateKey;
        privateKey.Initialize(fieldPrime, divider, base, privateExponent);

        AutoSeededRandomPool prng;
        //DSA::Signer signer(privateKey);
        StringSource(message, true, new SignerFilter(prng, DSA::Signer(privateKey), new StringSink(signature)));
        signature = strHexEncode(signature);
        result = String::New(signature.c_str());

        if (args.Length() == 5){
            return scope.Close(result);
        } else {
            Local<Function> callback = Local<Function>::Cast(args[5]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }
}

//Method signature : cryptopp.dsa.verify(message, signature, primeField, divider, base, publicElement, [callback(isValid)])
Handle<Value> dsaVerify(const Arguments& args){
    HandleScope scope;
    if (args.Length() == 6 || args.Length() == 7){
        String::Utf8Value messageVal(args[0]->ToString());
        String::AsciiValue signatureVal(args[1]->ToString()), fieldPrimeVal(args[2]->ToString()), dividerVal(args[3]->ToString()), baseVal(args[4]->ToString()), publicElementVal(args[5]->ToString());
        std::string message(*messageVal), signature(*signatureVal);
        bool isValid = false;
        Local<Value> result;

        CryptoPP::Integer fieldPrime(HexStrToInteger(*fieldPrimeVal)), divider(HexStrToInteger(*dividerVal)), base(HexStrToInteger(*baseVal)), publicElement(HexStrToInteger(*publicElementVal));

        DSA::PublicKey publicKey;
        publicKey.Initialize(fieldPrime, divider, base, publicElement);

        signature = strHexDecode(signature);
        StringSource(signature+message, true, new SignatureVerificationFilter(DSA::Verifier(publicKey), new ArraySink( (byte*)&isValid, sizeof(isValid) )));
        result = BooleanObject::New(isValid);
        if (args.Length() == 6){
            return scope.Close(result);
        } else {
            Local<Function> callback = Local<Function>::Cast(args[6]);
            const unsigned argc = 1;
            Local<Value> argv[argc] = { Local<Value>::New(result) };
            callback->Call(Context::GetCurrent()->Global(), argc, argv);
            return scope.Close(Undefined());
        }
    } else {
        ThrowException(v8::Exception::TypeError(String::New("Invalid number of parameters")));
        return scope.Close(Undefined());
    }
}

// Lib initialization method
void init(Handle<Object> exports){
    // Binding the keyManager class
    KeyRing::Init(exports);
    // Setting the cryptopp.hex object
	Local<Object> hexObj = Object::New();
	hexObj->Set(String::NewSymbol("encode"), FunctionTemplate::New(hexEncode)->GetFunction());
	hexObj->Set(String::NewSymbol("decode"), FunctionTemplate::New(hexDecode)->GetFunction());
    exports->Set(String::NewSymbol("hex"), hexObj);
    // Setting the cryptopp.base64 object
    Local<Object> base64Obj = Object::New();
    base64Obj->Set(String::NewSymbol("encode"), FunctionTemplate::New(base64Encode)->GetFunction());
    base64Obj->Set(String::NewSymbol("decode"), FunctionTemplate::New(base64Decode)->GetFunction());
    exports->Set(String::NewSymbol("base64"), base64Obj);
    // Setting the generateBytes method
    exports->Set(String::NewSymbol("randomBytes"), FunctionTemplate::New(randomBytes)->GetFunction());
    //Setting the cryptopp.ecies object
    Local<Object> eciesObj = Object::New();
    Local<Object> eciesPrimeObj = Object::New();
    Local<Object> eciesBinaryObj = Object::New();
    eciesPrimeObj->Set(String::NewSymbol("generateKeyPair"), FunctionTemplate::New(eciesGenerateKeyPairP)->GetFunction());
    eciesPrimeObj->Set(String::NewSymbol("encrypt"), FunctionTemplate::New(eciesEncryptP)->GetFunction());
    eciesPrimeObj->Set(String::NewSymbol("decrypt"), FunctionTemplate::New(eciesDecryptP)->GetFunction());
    eciesBinaryObj->Set(String::NewSymbol("generateKeyPair"), FunctionTemplate::New(eciesGenerateKeyPairB)->GetFunction());
    eciesBinaryObj->Set(String::NewSymbol("encrypt"), FunctionTemplate::New(eciesEncryptB)->GetFunction());
    eciesBinaryObj->Set(String::NewSymbol("decrypt"), FunctionTemplate::New(eciesDecryptB)->GetFunction());
    eciesObj->Set(String::NewSymbol("prime"), eciesPrimeObj);
    eciesObj->Set(String::NewSymbol("binary"), eciesBinaryObj);
    exports->Set(String::NewSymbol("ecies"), eciesObj);
    //Setting the cryptopp.ecdsa object
    Local<Object> ecdsaObj = Object::New();
    Local<Object> ecdsaPrimeObj = Object::New();
    Local<Object> ecdsaBinaryObj = Object::New();
    ecdsaPrimeObj->Set(String::NewSymbol("generateKeyPair"), FunctionTemplate::New(ecdsaGenerateKeyPairP)->GetFunction());
    ecdsaPrimeObj->Set(String::NewSymbol("sign"), FunctionTemplate::New(ecdsaSignMessageP)->GetFunction());
    ecdsaPrimeObj->Set(String::NewSymbol("verify"), FunctionTemplate::New(ecdsaVerifyMessageP)->GetFunction());
    ecdsaBinaryObj->Set(String::NewSymbol("generateKeyPair"), FunctionTemplate::New(ecdsaGenerateKeyPairB)->GetFunction());
    ecdsaBinaryObj->Set(String::NewSymbol("sign"), FunctionTemplate::New(ecdsaSignMessageB)->GetFunction());
    ecdsaBinaryObj->Set(String::NewSymbol("verify"), FunctionTemplate::New(ecdsaVerifyMessageB)->GetFunction());
    ecdsaObj->Set(String::NewSymbol("prime"), ecdsaPrimeObj);
    ecdsaObj->Set(String::NewSymbol("binary"), ecdsaBinaryObj);
    exports->Set(String::NewSymbol("ecdsa"), ecdsaObj);
    //Setting the cryptopp.ecdh object
    Local<Object> ecdhObj = Object::New();
    Local<Object> ecdhPrimeObj = Object::New();
    Local<Object> ecdhBinaryObj = Object::New();
    ecdhPrimeObj->Set(String::NewSymbol("generateKeyPair"), FunctionTemplate::New(ecdhGenerateKeyPairP)->GetFunction());
    ecdhPrimeObj->Set(String::NewSymbol("agree"), FunctionTemplate::New(ecdhAgreeP)->GetFunction());
    ecdhBinaryObj->Set(String::NewSymbol("generateKeyPair"), FunctionTemplate::New(ecdhGenerateKeyPairB)->GetFunction());
    ecdhBinaryObj->Set(String::NewSymbol("agree"), FunctionTemplate::New(ecdhAgreeB)->GetFunction());
    ecdhObj->Set(String::NewSymbol("prime"), ecdhPrimeObj);
    ecdhObj->Set(String::NewSymbol("binary"), ecdhBinaryObj);
    exports->Set(String::NewSymbol("ecdh"), ecdhObj);
    //Setting the cryptopp.rsa object
    Local<Object> rsaObj = Object::New();
    rsaObj->Set(String::NewSymbol("generateKeyPair"), FunctionTemplate::New(rsaGenerateKeyPair)->GetFunction());
    rsaObj->Set(String::NewSymbol("encrypt"), FunctionTemplate::New(rsaEncrypt)->GetFunction());
    rsaObj->Set(String::NewSymbol("decrypt"), FunctionTemplate::New(rsaDecrypt)->GetFunction());
    rsaObj->Set(String::NewSymbol("sign"), FunctionTemplate::New(rsaSign)->GetFunction());
    rsaObj->Set(String::NewSymbol("verify"), FunctionTemplate::New(rsaVerify)->GetFunction());
    exports->Set(String::NewSymbol("rsa"), rsaObj);
    //Setting the cryptopp.dsa object
    Local<Object> dsaObj = Object::New();
    dsaObj->Set(String::NewSymbol("generateKeyPair"), FunctionTemplate::New(dsaGenerateKeyPair)->GetFunction());
    dsaObj->Set(String::NewSymbol("sign"), FunctionTemplate::New(dsaSign)->GetFunction());
    dsaObj->Set(String::NewSymbol("verify"), FunctionTemplate::New(dsaVerify)->GetFunction());
    exports->Set(String::NewSymbol("dsa"), dsaObj);
}

NODE_MODULE(cryptopp, init)