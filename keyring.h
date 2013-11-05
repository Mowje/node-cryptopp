#ifndef KEYRING_H
#define KEYRING_H

#include <string>
#include <map>

#include <node.h>

class KeyRing : public node::ObjectWrap{

public:
	static void Init(v8::Handle<v8::Object> exports);

private:
	explicit KeyRing(string filename = "");
	~KeyRing();
	//Internal attributes
	map<string, string>* keyPair;
	string filename_;
	//Internal methods
	map<string, string>* loadKeyPair(string const& filename, string passphrase = "");
	bool saveKeyPair(string const& filename, map<string, string>* keyPair, string passphrase = "");
	//Encode/Decoding the file buffer
	map<string, string>* decodeBuffer(string const& fileBuffer);
	string encodeBuffer(map<string, string>* keyPair);
	//char / curveName conversions
	char getCurveID(string curveName);
	string getCurveName(char curveID);

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