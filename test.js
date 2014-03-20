//console.log('CRYPTOPP TEST AND EXAMPLE SCRIPT');
var cryptopp = require('./node-cryptopp.js');
var assert = require('assert');
// NOTE : when you have installed node-cryptopp, use require('cryptopp') instead

// Testing hexadecimal encoding/decoding
var hexTest = "testing hex encoding";
var hexEncoded = cryptopp.hex.encode(hexTest);
var hexDecoded = cryptopp.hex.decode(hexEncoded);
//console.log('\n### Testing hexadecimal encoding/decoding ###\nTest message : ' + hexTest + "\nEncoded : " + hexEncoded + "\nDecoded : " + hexDecoded);
assert.equal(hexTest, hexDecoded, 'Problem with hex encoding');

// Testing Base64 encoding/decoding
var base64Test = "testing Base64 encoding";
var base64Encoded = cryptopp.base64.encode(base64Test);
var base64Decoded = cryptopp.base64.decode(base64Encoded);
//console.log('\n### Testing base64 encoding/decoding ###\nTest message : ' + base64Test + "\nEncoded : " + base64Encoded + "\nDecoded : " + base64Decoded);
assert.equal(base64Test, base64Decoded, 'Problem with base64 encoding');

// Testing random byte generation
var randomBytes1 = cryptopp.randomBytes(5, 'base64');
var randomBytes2 = cryptopp.randomBytes(10);
//console.log('\n### Testing random bytes generation ###\nRandom bytes : ' + randomBytes1 + '\nOther random bytes : ' + randomBytes2);

// Testing RSA encryption/decryption
var rsaTest = "testing RSA encryption/decryption";
var rsaKeyPair = cryptopp.rsa.generateKeyPair(2048);
//console.log("\n### Testing RSA encryption/decryption ###\nTest message : " + rsaTest + "\nModulus : " + rsaKeyPair.modulus + "\nPublic exponent : " + rsaKeyPair.publicExponent + "\nPrivate exponent : " + rsaKeyPair.privateExponent);
var rsaCipher = cryptopp.rsa.encrypt(rsaTest, rsaKeyPair.modulus, rsaKeyPair.publicExponent);
//console.log("Cipher :\n" + rsaCipher);
var rsaDecrypted = cryptopp.rsa.decrypt(rsaCipher, rsaKeyPair.modulus, rsaKeyPair.privateExponent, rsaKeyPair.publicExponent);
//console.log("Plain text (decrypted) : " + rsaDecrypted);
assert.equal(rsaTest, rsaDecrypted, 'The RSA decrypted message is invalid');

//Testing RSA signature and verification
var rsaSignTest = "testing RSA signature and verification";
var rsaSignKeyPair = cryptopp.rsa.generateKeyPair(2048);
//console.log('\n### Testing RSA signature and verification ###\nTest message : ' + rsaSignTest + '\nModulus : ' + rsaSignKeyPair.modulus + '\nPublic exponent : ' + rsaSignKeyPair.publicExponent + '\nPrivate exponent : ' + rsaSignKeyPair.privateExponent);
var rsaSignature = cryptopp.rsa.sign(rsaSignTest, rsaKeyPair.modulus, rsaKeyPair.privateExponent, rsaKeyPair.publicExponent);
//console.log('Signature : ' + rsaSignature)
var isRsaSignValid = cryptopp.rsa.verify(rsaSignTest, rsaSignature, rsaKeyPair.modulus, rsaKeyPair.publicExponent);
//console.log('Is signature valid : ' + isRsaSignValid);
assert.equal(isRsaSignValid, true, 'The RSA signature is invalid');

// Testing DSA signature and verification
var dsaTest = "testing DSA signature scheme";
var dsaKeyPair = cryptopp.dsa.generateKeyPair(2048);
//console.log("\n### Testing DSA signature/verification ###\nTest message : " + dsaTest + "\nPrime Field : " + dsaKeyPair.primeField + "\nDivider : " + dsaKeyPair.divider + "\nBase : " + dsaKeyPair.base + "\nPrivate exponent : " + dsaKeyPair.privateExponent + "\nPublic element : " + dsaKeyPair.publicElement);
var dsaSignature = cryptopp.dsa.sign(dsaTest, dsaKeyPair.primeField, dsaKeyPair.divider, dsaKeyPair.base, dsaKeyPair.privateExponent);
//console.log("Signature : " + dsaSignature);
var dsaIsValid = cryptopp.dsa.verify(dsaTest, dsaSignature, dsaKeyPair.primeField, dsaKeyPair.divider, dsaKeyPair.base, dsaKeyPair.publicElement);
//console.log("Is signature valid : " + dsaIsValid);
assert.equal(dsaIsValid, true, 'The DSA signature is invalid');

// Testing ECIES encryption/decryption
var eciesTest = "Testing ECIES encryption/decryption";
var eciesKeyPair = cryptopp.ecies.prime.generateKeyPair("secp256r1");
//console.log("\n### Testing ECIES encryption/decryption on prime fields###\nTest message : " + eciesTest + "\nCurve name : " + eciesKeyPair.curveName + "\nPrivate key : " + eciesKeyPair.privateKey + "\nPublic key :\n\tx : " + eciesKeyPair.publicKey.x + "\n\ty : " + eciesKeyPair.publicKey.y);
var eciesCipher = cryptopp.ecies.prime.encrypt(eciesTest, eciesKeyPair.publicKey, "secp256r1");
//console.log("Cipher :\n" + eciesCipher);
var eciesDecrypted = cryptopp.ecies.prime.decrypt(eciesCipher, eciesKeyPair.privateKey, "secp256r1");
//console.log("Plain text (decrypted) : " + eciesDecrypted);
assert.equal(eciesTest, eciesDecrypted, 'The decrypted ECIES message is invalid (prime fields)');

//Testing ECIES on binary fields
eciesKeyPair = cryptopp.ecies.binary.generateKeyPair('sect283r1');
//console.log('\n### Testing ECIES encryption/decryption on binary fields###\nCurve name : ' + eciesKeyPair.curveName + '\nPrivate key : ' + eciesKeyPair.privateKey + '\nPublic key\n\tx : ' + eciesKeyPair.publicKey.x + '\n\ty : ' + eciesKeyPair.publicKey.y);
eciesCipher = cryptopp.ecies.binary.encrypt(eciesTest, eciesKeyPair.publicKey, 'sect283r1');
//console.log('Cipher :\n' + eciesCipher);
eciesDecrypted = cryptopp.ecies.binary.decrypt(eciesCipher, eciesKeyPair.privateKey, 'sect283r1');
//console.log('Plain text (decrypted) : ' + eciesDecrypted);
assert.equal(eciesTest, eciesDecrypted, 'The decrypted ECIES message is invalid (binary fields)');

//Testing ECDSA signing and verification on prime fields
var ecdsaTest = "testing ECDSA signing and verification";
var ecdsaKeyPair = cryptopp.ecdsa.prime.generateKeyPair("secp256r1");
//console.log("\n### Testing ECDSA signing and verification on prime fields ###\nTest message : " + ecdsaTest + "\nCurve name : " + ecdsaKeyPair.curveName + "\nPrivate key : " + ecdsaKeyPair.privateKey + "\nPublic key :\n\tx : " + ecdsaKeyPair.publicKey.x + "\n\ty : " + ecdsaKeyPair.publicKey.y);
var ecdsaSignature = cryptopp.ecdsa.prime.sign(ecdsaTest, ecdsaKeyPair.privateKey, "secp256r1");
//console.log("Signature : " + ecdsaSignature);
var ecdsaIsValid = cryptopp.ecdsa.prime.verify(ecdsaTest, ecdsaSignature, ecdsaKeyPair.publicKey, "secp256r1");
//console.log("Is valid : " + ecdsaIsValid);
assert.equal(ecdsaIsValid, true, 'The ECDSA signature is invalid (prime fields)');

//Testing ECDSA signing and verification on binary fields
/*ecdsaKeyPair = cryptopp.ecdsa.binary.generateKeyPair('sect283r1');
console.log('\n### Testing ECDSA signing and verification on binary fields ###\nCurve name : ' + ecdsaKeyPair.curveName + '\nPrivate key : ' + ecdsaKeyPair.privateKey + '\nPublic key :\n\tx : ' + ecdsaKeyPair.publicKey.x + '\n\ty : ' + ecdsaKeyPair.publicKey.y);
ecdsaSignature = cryptopp.ecdsa.binary.sign(ecdsaTest, ecdsaKeyPair.privateKey, 'sect283r1');
console.log('Signature : ' + ecdsaSignature);
ecdsaIsValid = cryptopp.ecdsa.binary.verify(ecdsaTest, ecdsaSignature, ecdsaKeyPair.publicKey, 'sect283r1');
console.log('Is valid : ' + ecdsaIsValid);*/

//Testing ECDH key agreement protocol on prime fields
//console.log("\n### Testing ECDH key agreement on prime fields ###");
var keyPair1 = cryptopp.ecdh.prime.generateKeyPair("secp256r1");
var keyPair2 = cryptopp.ecdh.prime.generateKeyPair("secp256r1");
//console.log("Key pair 1 :\nPrivate key : " + keyPair1.privateKey + "\nPublic key : " + keyPair1.publicKey + "\nCurve name : " + keyPair1.curveName + "\n");
//console.log("Key pair 2 :\nPrivate key : " + keyPair2.privateKey + "\nPublic key : " + keyPair2.publicKey + "\nCurve name : " + keyPair2.curveName + "\n");
//console.log("Calculating first secret");
var secret1 = cryptopp.ecdh.prime.agree(keyPair1.privateKey, keyPair2.publicKey, keyPair1.curveName);
//console.log("Calculating second secret");
var secret2 = cryptopp.ecdh.prime.agree(keyPair2.privateKey, keyPair1.publicKey, keyPair2.curveName);
assert.equal(secret1, secret2, 'The shared secret isn\'t the same (prime fields)');
//console.log("Secret 1 :\n" + secret1);
//console.log("Secret 2 :\n" + secret2);

//Testing ECDH on binary fields
//console.log('\n### Testing ECDH key agreement on binary fields ###');
keyPair1 = cryptopp.ecdh.binary.generateKeyPair('sect283r1');
keyPair2 = cryptopp.ecdh.binary.generateKeyPair('sect283r1');
//console.log('Key pair 1 :\nPrivate key : ' + keyPair1.privateKey + '\nPublic key : ' + keyPair1.publicKey + '\nCurve name : ' + keyPair1.curveName + '\n');
//console.log('Key pair 2 :\nPrivate key : ' + keyPair2.privateKey + '\nPublic key : ' + keyPair2.publicKey + '\nCurve name : ' + keyPair2.curveName + '\n');
//console.log('Calculating first secret');
secret1 = cryptopp.ecdh.binary.agree(keyPair1.privateKey, keyPair2.publicKey, keyPair1.curveName);
//console.log('Calculating second secret');
secret2 = cryptopp.ecdh.binary.agree(keyPair2.privateKey, keyPair1.publicKey, keyPair2.curveName);
//console.log('Secret 1 :\n' + secret1 + '\nSecret 2 :\n' + secret2);
assert.equal(secret1, secret2, 'The shared secret isn\'t the same (binary fields)');

//console.log('\nCRYPTOPP TEST SCRIPT ENDED SUCCESSFULLY');