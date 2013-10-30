node-cryptopp
================

Node.js module that statically binds and simplifies the usage of the [Crypto++](http://cryptopp.com) comprehensive cryptography library.

Bindings for:
* [RSA](https://en.wikipedia.org/wiki/RSA_(algorithm\))
* [DSA](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm) 
* [ECIES](https://en.wikipedia.org/wiki/ECIES) 
* [ECDH](https://en.wikipedia.org/wiki/ECDH)
* [ECDSA](https://en.wikipedia.org/wiki/ECDSA)
* Base64 and hexadecimal encoding

All the crypto methods could de used in sync/async mode

### General note

This library isn't well written in terms of error management. If the app crashes or throws some strange exception, it is probably because you did something wrong but in general it won't tell you what it is. (As of 18th september 2013)

The different ECC algorithms for which are (or will be) implemented here use standard elliptic curves, defined [here](http://www.secg.org/collateral/sec2_final.pdf). The related methods will have a "curveName" parameter, taken from the previously linked document, like "secp256r1" or "sect233k1". Beware, it is case-sensible. Each communicating side must use the same curve.

Normally, each method described could be given a callback. If no callback is given, the method's result is returned.

Also, keys, ciphertexts and signatures are all hex encoded. These data types should be kept "as-is" when passed to other methods.

### Requirements
* [node.js](http://nodejs.org), obviously..
* [Crypto++](http://cryptopp.com), that could be installed on Linux [rather easily](http://cryptopp.com/wiki/Linux#Distribution_Package)

### Installation

On installation, the node-cryptopp module compiles on your computer. Hence Crypto++ needs to be installed.

To install this module, simply

```shell
npm install cryptopp
```

### Usage

The test.js script gives example usages for most implemented algorithms. So you can learn from there, in addition to learning from this page.

#### RSA

RSA encryption and signature schemes are supported by this module. The hash algorithm used in signatures is SHA256.

There are 5 methods for RSA :

* __rsa.generateKeyPair(keySize, [callback(keyPair)])__ : Generates a RSA keypair with the given key size (in bits). The keysize must be 1024 <= Math.power(2, k) <= 16384 (where k is an integer). The result of the method is an object with 3 attributes : modulus, publicExponent and privateExponent
* __rsa.encrypt(plainText, modulus, publicExponent, [callback(cipherText)])__ : Returns the ciphertext
* __rsa.decrypt(cipherText, modulus, privateExponent, publicExponent, [callback(plainText)])__ : Returns the plain text message
* __rsa.sign(message, modulus, privateExponent, publicExponent, [callback(signature)])__ : Signs the message with the given private key
* __rsa.verify(message, signature, modulus, publicExponent, [callback(isValid)])__ : Tells whether the signature for the given message and public key is valid or not

##### Example usage
```javascript
var cryptopp = require('cryptopp');
var rsaKeyPair = cryptopp.rsa.generateKeyPair(2048);
var cipher = cryptopp.rsa.encrypt('Testing RSA', rsaKeyPair.modulus, rsaKeyPair.publicExponent);
var plaintext = cryptopp.rsa.decrypt(cipher, rsaKeyPair.modulus, rsaKeyPair.privateExponent);
```

#### DSA

There are 3 methods for DSA :

* __dsa.generateKeyPair(keySize, [callback(keyPair)])__ : Generates a DSA keypair with the given key size (in bits). The result is an object with 5 attributes : primeField, divider, base, privateExponent, publicElement
* __dsa.sign(message, primeField, divider, base, privateExponent, [callback(signature)])__ : Signs the given message using DSA with SHA1
* __dsa.verify(message, signature, primeField, divider, base, publicElement, [callback(isValid)])__ : Verifies the signature

##### Example usage
```javascript
var cryptopp = require('cryptopp');
var dsaKeyPair = cryptopp.dsa.generateKeyPair(2048);
var message = 'Testing DSA';
var signature = cryptopp.dsa.sign(message, dsaKeyPair.primeField, dsaKeyPair.divider, dsaKeyPair.base, dsaKeyPair.privateExponent);
var isValid = cryptopp.dsa.verify(message, signature, dsaKeyPair.primeField, dsaKeyPair.divider, dsaKeyPair.base, dsaKeyPair.publicElement);
```

#### ECIES

Bindings have been written for ECIES on prime and binary fields.

The methods are reachable as following cryptopp.ecies.[fieldType].[methodname]

For each of these fields, there are 3 methods available :

* __ecies.[fieldType].generateKeyPair(curveName, [callback(keyPair)])__ : Returns an object containing the private key, the public key, and curve name. The private and public keys are hex encoded and should be passed in that format to other methods.
* __ecies.[fieldType].encrypt(plainText, publicKey, curveName, [callback(cipherText)])__ : encrypts the plainText with the given publicKey on the given curve.
* __ecies.[fieldType].decrypt(cipherText, privateKey, curveName, [callback(plainText)])__ : decrypts the cipherText with the given privateKey on the given curve.

##### Example usage
```javascript
var cryptopp = require('cryptopp');
var keyPair = cryptopp.ecies.prime.generateKeyPair("secp256r1");
var cipher = cryptopp.ecies.prime.encrypt("Testing ECIES", keyPair.publicKey, keyPair.curveName);
var plainText = cryptopp.ecies.prime.decrypt(cipher, keyPair.privateKey, keyPair.curveName);
```

To use ECIES on binary fields, just replace in the code above "prime" by "binary" and the curve name by a "binary curve" one.

#### ECDSA

Bindings have been written for ECDSA for prime and prime fields. However, there is a bug somewhere in the binary field version in the signing method (probably in hexStr<->PolynomialMod2 conversions, a bug I don't want to fix for now...). And as of now, the only hashing algorithm that can be used is SHA256. The ECDSA methods are reachable in a manner similar to ECIES. Here are ECDSA's methods :

* __ecdsa.[fieldType].generateKeyPair(curveName, [callback(keyPair)])__ : Returns an object containing the private key, the public key and the curve name.
* __ecdsa.[fieldType].sign(message, privateKey, curveName, [callback(signature)])__ : Returns the signature for the given message
* __ecdsa.[fieldType].verify(message, signature, publicKey, curveName, [callback(isValid)])__ : A boolean is returned by this method; true when the signature is valid, false when it isn't.

##### Example usage
```javascript
var cryptopp = require('cryptopp');
var keyPair = cryptopp.ecdsa.prime.generateKeyPair("secp256r1");
var message = "Testing ECDSA";
var signature = cryptopp.ecdsa.prime.sign(message, keyPair.privateKey, keyPair.curveName);
var isValid = cryptopp.ecdsa.prime.verify(message, signature, keyPair.publicKey, keyPair.curveName);
```

#### ECDH

Binding have been written for ECDH for both type of fields. However, the ECDH version don't always give the same secret in the "agree" method. So don't use it... There is probably a bug somewhere in hexStr<->PolynomialMod2 conversion methods, but I don't want to fix it for now.

There are only 2 methods per field :

* __ecdh.[fieldType].generateKeyPair(curveName, [callback(keyPair)])__ : The result is an object with 3 attributes : curveName, privateKey, publicKey
* __ecdh.[fieldType].agree(yourPrivateKey, yourCounterpartsPublicKey, curveName, [callback(secret)])__ : Returns the common secret.

##### Example usage
```javascript
var cryptopp = require('cryptopp');
var ecdhKeyPair1 = cryptopp.ecdh.prime.generateKeyPair('secp256r1');
var ecdhKeyPair2 = cryptopp.ecdh.prime.generateKeyPair('secp256r1');
var secret1 = cryptopp.ecdh.prime.agree(ecdhKeyPair1.privateKey, ecdhKeyPair2.publicKey, ecdhKeyPair1.curveName);
var secret2 = cryptopp.ecdh.prime.agree(ecdhKeyPair2.privateKey, ecdhKeyPair1.publicKey, ecdhKeyPair2.curveName);
```

#### Random bytes generation

I found it useful to have a method that gives you random bytes, using the a generator from Crypto++ rather than ```Math.random()``` or whatever

__cryptopp.randomBytes(length, [encoding])__ :  
* length : number of bytes to be generated
* encoding : optional, possible values are 'hex' for hexadecimal and 'base64' for Base64 encoding. Defaults to 'hex'.

#### Hex and Base64 encodings

Although there are already ways to encode/decode to hex/base64 in Node.js, I wrote bindings to the implementations in Crypto++

* __hex.encode(text)__ : Encode the text to hexadecimal
* __hex.decode(encoded)__ : Decode the hex encoded text

* __base64.encode(text)__ : Encode the text to Base64
* __base64.decode(encoded)__ : Decode the Base64 encoded text