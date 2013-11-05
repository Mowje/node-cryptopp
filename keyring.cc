#define BUILDING_NODE_EXTENSION

#include <string>
#include <iostream>
#include <exception>
#include <stdexcept>
#include <fstream>
#include <sstream>

#include <node.h>
#include "keyring.h"

using namespace v8;

Persistent<Function> KeyRing::constructor;

KeyRing::KeyRing(string filename) : filename_(filename), keyPair(0){
	//If filename is not null, try to load the key at the given filename
	if (filename != ""){

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
		string filename = args[0]->IsUndefined() ? "" : args[0]->ToString();
		KeyRing* newInstance = new KeyRing(filename);
		newInstance->Wrap(args.This());
		return args.This();
	} else {
		//Invoked as a plain function, turn into construct call
		const int argc = 1;
		Local<Value> argv[argc] = { args[0] };
		return scope.Close(constructor->NewInstance(argc, argv));
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
* String message
*/
Handle<Value> KeyRing::Decrypt(const Arguments& args){
	HandleScope scope;
	KeyRing* instance = ObjectWrap::Unwrap<KeyRing>(args.This());
	if (instance->keyPair == 0){
		ThrowException(Exception::TypeError(String::New("No key has been loaded in the keyring. Either load a key on instanciation or by calling the Load() method")));
	}
	//Checking the key type
}

/*
* Signature :
* String message
*/
Handle<Value> KeyRing::Sign(const Arguments& args){

}

/*
* Signature
* Object pubKeyInfo
*/
Handle<Value> KeyRing::Agree(const Arguments& args){

}

// No params
Handle<Value> KeyRing::PublicKeyInfo(const Arguments& args){

}

/*
* Signature
* String keyType, Number/String keyOptions, String filename [optional], String passphrase [optional]
*/
Handle<Value> KeyRing::CreateKeyPair(const Arguments& args){

}

/*
* Signature
* String filename, String passphrase [optional]
*/
Handle<Value> KeyRing::Load(const Arguments& args){

}

/*
* Signature
* String filename, String passphrase [optional]
*/
Handle<Value> KeyRing::Save(const Arguments& args){

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

map<string, string>* KeyRing::loadKeyPair(string const& filename, string passphrase){
	fstream file(filename.c_str(), std::ios::in);
	if (passphrase != ""){ //If passphrase is defined, then decrypt file

	}
}

bool KeyRing::saveKeyPair(string const& filename, map<string, string>* keyPair, string passphrase){

}

map<string, string>* KeyRing::decodeBuffer(string const& fileBuffer){
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
		else (keyType == 0x04) keyPair->insert(make_pair("keyType", "ecies"));
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
		unsigned short publicKeyLength, privateKey;
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
	buffer << "key";
	string keyType = keyPair->at("keyType");
	if (keyType == "ecdsa" || keyType == "ecies"){
		//Checking key pair integrality
		string params[] = {"curveName", "publicKeyX", "publicKeyY", "privateKey"};
		for (int i = 0; i < 4; i++){
			if (!keyPair->count(params[i])) throw new runtime_error("Missing " + params[i] + " parameter");
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
		//Writing publicKey.x
		buffer << (char) (publicX.length() >> 8);
		buffer << (char) publicX.length();
		buffer << publicX;
		//Writing publicKey.y
		buffer << (char) (publicY.length() >> 8);
		buffer << (char) publicY.length();
		buffer << publicY;
		//Writing privateKey
		buffer << (char) (privateKey.length() >> 8);
		buffer << (char) privateKey.length();
		buffer << privateKey;
	} else if (keyType == "rsa"){
		
	} else if (keyType == "dsa"){

	} else if (keyType == "ecdh"){

	} else throw new runtime_error("Unknown key type");
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