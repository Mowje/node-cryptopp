# node-cryptopp
================

Node.js module that statically binds and simplifies the usage of the [Crypto++](http://cryptopp.com) comprehensive cryptography library.

Bindings for:
* [RSA](https://en.wikipedia.org/wiki/RSA_%28algorithm%29)
* [DSA](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm) 
* [ECIES](https://en.wikipedia.org/wiki/ECIES) 
* [ECDH](https://en.wikipedia.org/wiki/ECDH)
* [ECDSA](https://en.wikipedia.org/wiki/ECDSA)
* Base64 and hexadecimal encoding

All the crypto methods could be used in sync/async mode

## Requirements
* [node.js](http://nodejs.org), obviously..
* [node-gyp](https://github.com/TooTallNate/node-gyp)
* ~~[Crypto++](http://cryptopp.com), that could be installed on Linux [rather easily](http://cryptopp.com/wiki/Linux#Distribution_Package)~~ (Not a requirement anymore. v0.2.1 is all about having Crypto++ as a submodule)

## Installation

On installation, the node-cryptopp module compiles on your computer. Hence Crypto++ needs to be installed.

To install this module, run :

```shell
npm install git+https://github.com/Tashweesh/node-cryptopp.git
```

Or, alternatively :

```shell
npm install git+ssh://git@github.com:Tashweesh/node-cryptopp.git
```

*NOTE*: This module used to be installable from npm. I struggled to make it work with 0.2.1. So I'm giving up on npm for now and gave you this alternate way to install cryptopp.

## CAUTION : minor API changes starting from v.0.2.0

## Use the `KeyRing` !

This feature was introduced in version 0.2.0. A friend of mine told me that "key management" in 0.1.x versions of node-cryptopp was totally unsafe because of javascript's memory management : you have cannot control when a keypair is ereased from memory, even though you removed all references to it. Because Node.js is a relatively new technology and it is highly probable that there are unknown exploits in it (like in any piece of software), it would be then unsafe to have private keys loaded in js code.

Hence, I created the `KeyRing` class, that manages keypair generation, saving, loading and clearing in addition to the cryptographic operations where the private key is needed. Also, there is no method in this class that will allow you to extract the private key.

As of now, I kept the unsafe methods from the previous versions of the module, but I **highly** recommend using the key ring.

Note that I wanted to allow key encryption (ie, when saving then on disk). But it doesn't work as of now. Hence, don't use the `passphrase` parameter (or skip it with `undefined` like you'd skip any other parameter in cryptopp, as explained below).

## General notes

* By default, each method described could be given a callback. If no callback is given, the method's result is returned.
* If you want to skip an optional parameter but want to define the parameter that follows it, then the skipped parameter **MUST** be set to `undefined`. Sorry if this seems to totally inconvenient
* This library isn't well written in terms of error management (except the KeyRing class). If the app crashes or throws some strange exception, it is probably because you did something wrong (Thanks Captain Obvious) but in general it won't tell you what it is. Note that if you use a method with a callback, the errors will be thrown exactly like when you use the method without a callback
* The different ECC algorithms for which are (or will be) implemented here use standard elliptic curves, defined [here](http://www.secg.org/collateral/sec2_final.pdf). The related methods will have a "curveName" parameter, taken from the previously linked document, like "secp256r1" or "sect233k1". Beware, it is case-sensible. Each communicating side must use the same curve.
* ECIES keypairs can be used in ECDSA and vice-versa! (as long as you use the same curve in both algorithms) [paper that proves it; look for section 4](http://eprint.iacr.org/2011/615)
* You can choose what hash function want to use in ECDSA and RSA signatures. You can choose either SHA1 (default) or SHA256. Just set the `hashName` parameter to 'sha1' or 'sha256' in the corresponding methods. Note that the default hash function for these algorthims in version prior to v0.2.0 was SHA256.
* Keys, ciphertexts and signatures are all hex encoded. These data types should be kept "as-is" when passed to other methods.

## Usage

The test.js script gives example usages for most implemented algorithms. So you can learn from there, in addition to learning from this page.

### KeyRing

Before using the `KeyRing`, you must construct it. This is how it's done : 

```js
var cryptopp = require('cryptopp');
var keyRing = new cryptopp.KeyRing();
```

Here are the list of methods exposed by the `KeyRing`:

* `createKeyPair(algoType, algoOptions, [filename], [passphrase], [callback])`:  
Generates a keypair the given algorithm. Returns the public key information object (as in the `publicKeyInfo()` method)
	* algoType : the name of the algorithm for which you want to create a keyPair. Possible values are "rsa", "dsa", "ecies", "ecdsa", "ecdh"
	* algoOptions : the keysize when algoType is "rsa" or "dsa", the curve name otherwise
	* filename : the path to the file where you want the keypair to saved. Optional parameter
	* passphrase : a passphrase used to encrypt the keypair (when you choose to save it). Optional parameter
	* callback : a callback function, that will recieve the public key information object as argument. Optional parameter
* `decrypt(cipherText, [encoding], [callback])`  
Decrypts the cipherText (optionally encoded)
	* cipherText : the ciphertext to decrypt
	* encoding : optional, the encoding of the ciphertext. Possible values are : 'hex', 'base64'. Defaults to 'hex'
	* callback : optional, receives the plaintext as a parameter
* `sign(message, [signatureEncoding], [hashName], [callback])`  
Signs the message with the loaded key ring.
	* message : the message to be signed
	* signatureEncoding : optional, determines the encoding that should be used for the signature. Possible values : 'hex', 'base64'. Defaults to 'hex'.
	* hashName : optional, name of the hash function to be used in the signing process. Possible values are 'sha1', 'sha256'. Defaults to 'sha1'.
	* callback : optional. Recieves the signature as a parameter if used
* `agree(pubKey, [callback])`  
Agrees on a shared secret and returns it (hex encoded)
	* pubKey : object containing the keyType, curveName and publicKey attributes for an ECDH key agreement
	* callback : receives the shared secret
* `publicKeyInfo([callback])`
Returns an object containing public key information from the currently loaded key pair. You can give a callback. The returned object has the following attributes :
	* keyType : a string that contains the algo type. Possible values : "rsa", "dsa", "ecdsa", "ecies", "ecdh"
	* if (keyType == "rsa") :
		* modulus : the RSA modulus
		* publicExponent : the RSA public exponent
	* if (keyType == "dsa") :
		* primeField : the DSA prime field
		* divider : the DSA divider
		* base : the DSA base
		* publicElement : the DSA public key
	* if (keyType == "ecdsa" || keyType == "ecies")
		* curveName : the standard name of the cruve used
		* publicKey.x : x coordinate of the public point
		* publicKey.y : y coordinate of the public point
	* if (keyType == "ecdh")
		* curveName : the standard name of the curve used
		* publicKey : the ECDH public key
* `save(filename, [passphrase], [callback])`  
Save the keypair to the given filename. DON'T USE THE PASSPHRASE! No paramter passed to the callback
* `load(filename, [legacy], [passphrase], [callback])`  
Load the keypair from the given path. Legacy is a boolean, determining whether the file is in the old key file format (prior to v0.2.2) DON'T USE THE PASSPHRASE! The callback receives the public key information object
* `clear()`  
Deletes the keypair from memory. You **MUST** call this method once you're done working the keyring.

### RSA

RSA encryption and signature schemes are supported by this module. For signatures : the default hashing function used here is SHA1, but you can specify the `hashName` parameter either to "sha1" or "sha256" (other values will throw an exception)

There are 5 methods for RSA :

* __rsa.generateKeyPair(keySize, [callback(keyPair)])__ : Generates a RSA keypair with the given key size (in bits). The keysize must be 1024 <= Math.power(2, k) <= 16384 (where k is an integer). The result of the method is an object with 3 attributes : modulus, publicExponent and privateExponent
* __rsa.encrypt(plainText, modulus, publicExponent, [callback(cipherText)])__ : Returns the ciphertext
* __rsa.decrypt(cipherText, modulus, privateExponent, publicExponent, [callback(plainText)])__ : Returns the plain text message
* __rsa.sign(message, modulus, privateExponent, publicExponent, [hashName], [callback(signature)])__ : Signs the message with the given private key
* __rsa.verify(message, signature, modulus, publicExponent, [hashName], [callback(isValid)])__ : Tells whether the signature for the given message and public key is valid or not

#### Example usage
```javascript
var cryptopp = require('cryptopp');
var rsaKeyPair = cryptopp.rsa.generateKeyPair(2048);
var cipher = cryptopp.rsa.encrypt('Testing RSA', rsaKeyPair.modulus, rsaKeyPair.publicExponent);
var plaintext = cryptopp.rsa.decrypt(cipher, rsaKeyPair.modulus, rsaKeyPair.privateExponent);
```

### DSA

There are 3 methods for DSA. Note that the hashing function used here is SHA1.

* __dsa.generateKeyPair(keySize, [callback(keyPair)])__ : Generates a DSA keypair with the given key size (in bits). The result is an object with 5 attributes : primeField, divider, base, privateExponent, publicElement
* __dsa.sign(message, primeField, divider, base, privateExponent, [callback(signature)])__ : Signs the given message using DSA with SHA1
* __dsa.verify(message, signature, primeField, divider, base, publicElement, [callback(isValid)])__ : Verifies the signature

#### Example usage
```javascript
var cryptopp = require('cryptopp');
var dsaKeyPair = cryptopp.dsa.generateKeyPair(2048);
var message = 'Testing DSA';
var signature = cryptopp.dsa.sign(message, dsaKeyPair.primeField, dsaKeyPair.divider, dsaKeyPair.base, dsaKeyPair.privateExponent);
var isValid = cryptopp.dsa.verify(message, signature, dsaKeyPair.primeField, dsaKeyPair.divider, dsaKeyPair.base, dsaKeyPair.publicElement);
```

### ECIES

Bindings have been written for ECIES on prime and binary fields.

The methods are reachable as following cryptopp.ecies.[fieldType].[methodname]

For each of these fields, there are 3 methods available :

* __ecies.[fieldType].generateKeyPair(curveName, [callback(keyPair)])__ : Returns an object containing the private key, the public key, and curve name. The private and public keys are hex encoded and should be passed in that format to other methods.
* __ecies.[fieldType].encrypt(plainText, publicKey, curveName, [callback(cipherText)])__ : encrypts the plainText with the given publicKey on the given curve.
* __ecies.[fieldType].decrypt(cipherText, privateKey, curveName, [callback(plainText)])__ : decrypts the cipherText with the given privateKey on the given curve.

#### Example usage
```javascript
var cryptopp = require('cryptopp');
var keyPair = cryptopp.ecies.prime.generateKeyPair("secp256r1");
var cipher = cryptopp.ecies.prime.encrypt("Testing ECIES", keyPair.publicKey, keyPair.curveName);
var plainText = cryptopp.ecies.prime.decrypt(cipher, keyPair.privateKey, keyPair.curveName);
```

To use ECIES on binary fields, just replace in the code above "prime" by "binary" and the curve name by a "binary curve" one.

### ECDSA

Bindings have been written for ECDSA for prime and prime fields. However, there is a bug somewhere in the binary field version in the signing method (probably in hexStr<->PolynomialMod2 conversions, a bug I don't want to fix for now...). You can choose which hashing function you want to use by setting the `hashName` parameter either to "sha1" or "sha256" (other values will throw an exception). The ECDSA methods are reachable in a manner similar to ECIES. Here are ECDSA's methods :

* __ecdsa.[fieldType].generateKeyPair(curveName, [callback(keyPair)])__ : Returns an object containing the private key, the public key and the curve name.
* __ecdsa.[fieldType].sign(message, privateKey, curveName, [hashName], [callback(signature)])__ : Returns the signature for the given message
* __ecdsa.[fieldType].verify(message, signature, publicKey, curveName, [hashName], [callback(isValid)])__ : A boolean is returned by this method; true when the signature is valid, false when it isn't.

#### Example usage
```javascript
var cryptopp = require('cryptopp');
var keyPair = cryptopp.ecdsa.prime.generateKeyPair("secp256r1");
var message = "Testing ECDSA";
var signature = cryptopp.ecdsa.prime.sign(message, keyPair.privateKey, keyPair.curveName);
var isValid = cryptopp.ecdsa.prime.verify(message, signature, keyPair.publicKey, keyPair.curveName);
```

### ECDH

Binding have been written for ECDH for both type of fields. However, the ECDH version don't always give the same secret in the "agree" method. So don't use it... There is probably a bug somewhere in hexStr<->PolynomialMod2 conversion methods, but I don't want to fix it for now.

There are only 2 methods per field :

* __ecdh.[fieldType].generateKeyPair(curveName, [callback(keyPair)])__ : The result is an object with 3 attributes : curveName, privateKey, publicKey
* __ecdh.[fieldType].agree(yourPrivateKey, yourCounterpartsPublicKey, curveName, [callback(secret)])__ : Returns the common secret.

#### Example usage
```javascript
var cryptopp = require('cryptopp');
var ecdhKeyPair1 = cryptopp.ecdh.prime.generateKeyPair('secp256r1');
var ecdhKeyPair2 = cryptopp.ecdh.prime.generateKeyPair('secp256r1');
var secret1 = cryptopp.ecdh.prime.agree(ecdhKeyPair1.privateKey, ecdhKeyPair2.publicKey, ecdhKeyPair1.curveName);
var secret2 = cryptopp.ecdh.prime.agree(ecdhKeyPair2.privateKey, ecdhKeyPair1.publicKey, ecdhKeyPair2.curveName);
```

### Random bytes generation

I found it useful to have a method that gives you random bytes, using the a generator from Crypto++ rather than ```Math.random()``` or whatever

__cryptopp.randomBytes(length, [encoding])__ :  
* length : number of bytes to be generated
* encoding : optional, possible values are 'hex' for hexadecimal and 'base64' for Base64 encoding. Defaults to 'hex'.

### Hex and Base64 encodings

Although there are already ways to encode/decode to hex/base64 in Node.js, I wrote bindings to the implementations in Crypto++

* __hex.encode(text)__ : Encode the text to hexadecimal
* __hex.decode(encoded)__ : Decode the hex encoded text

* __base64.encode(text)__ : Encode the text to Base64
* __base64.decode(encoded)__ : Decode the Base64 encoded text

## Keypair file format

Here is how a keypair file is built. Note that every number is in written in big endian. Note that the format has changed slightly as of v0.2.2 to homogenize it [node-sodium](https://github.com/Tashweesh/node-sodium.git)'s format and to ease the integration of both modules into [node-hpka](https://github.com/Tashweesh/node-hpka.git). For reference, here is the [old key file format](https://github.com/Tashweesh/node-cryptopp/tree/master/OldKeyFileFormat.md).

* algoType : a byte; 0x00 for ECDSA, 0x01 for RSA, 0x02 for DSA, 0x03 for ECDH, 0x04 for ECIES
* if keyType is ECDSA or ECIES
	* curveID : a byte, corresponding to the curve used
	* publicKeyX.length : length of the x coordinate of the public point (2 bytes, unsigned integer)
	* publicKeyX : x coordinate of the public point
	* publicKeyY.length : length of the y coordinate of the public point (2 bytes, unsigned integer)
	* publicKeyY : y coordinate of the public point
	* privateKey.length : length of the private key (2 bytes, unsigned integer)
	* privateKey
* if keyType is RSA
	* modulus.length : length of the RSA modulus (2 bytes, unsigned integer)
	* modulus : RSA modulus
	* publicExponent.length : length of the public exponent (2 bytes, unsigned integer)
	* publicExponent : RSA public exponent (or public key)
	* privateExponent.length : length of the private exponent (2 bytes, unsigned integer)
	* privateExponent : RSA private exponent (or private key)
* if keyType is DSA
	* primeField.length : length of the prime field used by the DSA key pair (2 bytes, unsigned integer)
	* primeField
	* divider.length : length of the divider (2 bytes, unsigned integer)
	* divider
	* base.length : length of the base (2 bytes, unsigned integer)
	* base : DSA base
	* publicElement.length : length of the DSA public key (2 bytes, unsigned integer)
	* publicElement : DSA public key
	* privateExponent.length : length of the DSA private exponent (2 bytes, unsigned integer)
	* privateExponent : DSA private exponent (ie, the private key)
* if keyType is ECDH
	* curveID : a byte, corresponding to the curve used
	* publicKey.length : length of the ECDH public key (2 bytes, unsigned integer)
	* publicKey : ECDH public key
	* privateKey.length : length of the ECDH private key (2 bytes, unsigned integer)
	* privateKey : ECDH private key

#### CruveName <-> CurveID

 CurveID | Curve name
-------- | -----------
 0x01    | secp112r1
 0x02    | secp112r2
 0x03    | secp128r1
 0x04    | secp128r2
 0x05    | secp160r1
 0x06    | secp160r2
 0x07    | secp160k1
 0x08    | secp192r1
 0x09    | secp192k1
 0x0A    | secp224r1
 0x0B    | secp224k1
 0x0C    | secp256r1
 0x0D    | secp256k1
 0x0E    | secp384r1
 0x0F    | secp521r1
 0x80    | sect113r1
 0x81    | sect113r2
 0x82    | sect131r1
 0x83    | sect131r2
 0x84    | sect163r1
 0x85    | sect163r2
 0x86    | sect163k1
 0x87    | sect193r1
 0x88    | sect193r2
 0x89    | sect233r1
 0x8A    | sect233k1
 0x8B    | sect239r1
 0x8C    | sect283r1
 0x8D    | sect283k1
 0x8E    | sect409r1
 0x8F    | sect409k1
 0x90    | sect571r1
 0x91    | sect571k1

## License

This module is licensed under MIT license.
