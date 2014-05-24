#ifndef KEYRING_H
#define KEYRING_H

#include <string>
#include <map>

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;
#include <cryptopp/cryptlib.h>
#include <cryptopp/integer.h>
using CryptoPP::Integer;
#include <cryptopp/asn.h>
using CryptoPP::OID;

#include <node.h>

class KeyRing : public node::ObjectWrap{

public:
	static void Init(v8::Handle<v8::Object> exports);

private:
	explicit KeyRing(std::string filename = "", std::string passphrase = "");
	~KeyRing();
	//Internal attributes
	std::map<std::string, std::string>* keyPair;
	std::string filename_;
	/*
	* Internal methods
	*/
	static std::map<std::string, std::string>* loadKeyPair(std::string const& filename, bool legacy = false, std::string passphrase = "");
	static bool saveKeyPair(std::string const& filename, std::map<std::string, std::string>* keyPair, std::string passphrase = "");
	//Encode/Decoding the file buffer
	static std::map<std::string, std::string>* decodeBuffer(std::string const& fileBuffer);
	static std::map<std::string, std::string>* decodeBufferLegacy(std::string const& fileBuffer);
	static std::string encodeBuffer(std::map<std::string, std::string>* keyPair);
	//char / curveName conversions
	static char getCurveID(std::string curveName);
	static std::string getCurveName(char curveID);
	//String / Integer / SecByteBlock <-> hex conversions
	static std::string bufferHexEncode(byte buffer[], unsigned int size);
	static std::string strHexEncode(std::string const& s);
	static void bufferHexDecode(std::string const& e, byte buffer[], unsigned int bufferSize);
	static std::string strHexDecode(std::string const& e);
	static std::string IntegerToHexStr(CryptoPP::Integer const& i);
	static CryptoPP::Integer HexStrToInteger(std::string const& hexStr);
	static std::string SecByteBlockToHexStr(SecByteBlock const& array);
	static SecByteBlock HexStrToSecByteBlock(std::string const& hexStr);
	//String <-> Base64 conversions
	static std::string strBase64Encode(std::string const& s);
	static std::string strBase64Decode(std::string const& e);
	//PBKDF2 / AES file encryption / decryption
	static void encryptFile(std::string const& filename, std::string content, std::string const& passphrase, unsigned int pbkdfIterations = 8192, int aesKeySize = 256);
	static std::string decryptFile(std::string const& filename, std::string const& passphrase, unsigned int pbkdfIterations = 8192, int aesKeySize = 256);
	static bool doesFileExist(std::string const& filename);
	//curveName -> curveOID conversion
	static OID getPCurveFromName(std::string curveName);
	static OID getBCurveFromName(std::string curveName);

	//private PubKeyInfo object constructor
	v8::Local<v8::Object> PPublicKeyInfo();

	//JS Methods
	static v8::Handle<v8::Value> New(const v8::Arguments& args);
	static v8::Handle<v8::Value> Decrypt(const v8::Arguments& args);
	static v8::Handle<v8::Value> Sign(const v8::Arguments& args);
	static v8::Handle<v8::Value> Agree(const v8::Arguments& args);
	static v8::Handle<v8::Value> PublicKeyInfo(const v8::Arguments& args);
	static v8::Handle<v8::Value> CreateKeyPair(const v8::Arguments& args);
	static v8::Handle<v8::Value> Load(const v8::Arguments& args);
	static v8::Handle<v8::Value> Save(const v8::Arguments& args);
	static v8::Handle<v8::Value> Clear(const v8::Arguments& args);
	static v8::Persistent<v8::Function> constructor;
};

#endif
