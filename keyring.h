#ifndef KEYRING_H
#define KEYRING_H

#include <string>
#include <map>

#include <cryptopp/secblock.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/integer.h>
using CryptoPP::Integer;

#include <node.h>

class KeyRing : public node::ObjectWrap{

public:
	static void Init(v8::Handle<v8::Object> exports);

private:
	explicit KeyRing(std::string filename = "", std::string passphrase = "");
	~KeyRing();
	//Internal attributes
	map<std::string, std::string>* keyPair;
	std::string filename_;
	/*
	* Internal methods
	*/
	map<std::string, std::string>* loadKeyPair(std::string const& filename, std::string passphrase = "");
	bool saveKeyPair(std::string const& filename, map<std::string, std::string>* keyPair, std::string passphrase = "");
	//Encode/Decoding the file buffer
	map<std::string, std::string>* decodeBuffer(std::string const& fileBuffer);
	std::string encodeBuffer(map<std::string, std::string>* keyPair);
	//char / curveName conversions
	char getCurveID(std::string curveName);
	std::string getCurveName(char curveID);
	//String / Integer <-> hex conversions
	std::string bufferHexEncode(byte buffer[], unsigned int size);
	std::string strHexEncode(std::string const& s);
	void bufferHexDecode(std::string const& e, byte buffer[], unsigned int bufferSize);
	std::string strHexDecode(std::string const& e);
	std::string IntegerToHexStr(CryptoPP::Integer const& i);
	CryptoPP::Integer HexStrToInteger(std::string const& hexStr);
	//PBKDF2 / AES file encryption / decryption
	void encryptFile(std::string const& filename, std::string const& content, std::string const& passphrase, unsigned int pbkdfIterations = 8192, int aesKeySize = 256);
	std::string decryptFile(std::string const& filename, std::string const& passphrase, unsigned int pbkdfIterations = 8192, int aesKeySize = 256);
	bool doesFileExist(std::string const& filename);

	//JS Methods
	static v8::Handle<v8::Value> New(const v8::Arguments& args);
	static v8::Handle<v8::Value> Decrypt(const v8::Arguments& args);
	static v8::Handle<v8::Value> Sign(const Arguments& args);
	static v8::Handle<v8::Value> Agree(const Arguments& args);
	static v8::Handle<v8::Value> PublicKeyInfo(const Arguments& args);
	static v8::Handle<v8::Value> CreateKeyPair(const Arguments& args);
	static v8::Handle<v8::Value> Load(const Arguments& args);
	static v8::Handle<v8::Value> Save(const Arguments& args);
	static v8::Handle<v8::Value> Clear(const Arguments& args);
	static v8::Persistent<v8::Function> constructor;
};

#endif