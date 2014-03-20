var cryptopp = require('./node-cryptopp.js');
var assert = require('assert');
var fs = require('fs');
var Buffer = require('buffer').Buffer;

/*console.log('--------------------------');
console.log('   KeyRing test script    ');
console.log('--------------------------');*/

//console.log('\n### ECDSA ###');
var ecdsaMessage = 'Message to be signed by ECDSA'
var ecdsaKeyRing = new cryptopp.KeyRing();
var ecdsaPubKey = ecdsaKeyRing.createKeyPair("ecdsa", "secp256r1", './ecdsaKeyRing.key');
//console.log("ECDSA public key : " + JSON.stringify(ecdsaPubKey));
//ecdsaKeyRing.save('./ecdsaKeyRing.key');
var ecdsaKeyRing2 = new cryptopp.KeyRing();
ecdsaKeyRing2.load('./ecdsaKeyRing.key');
var ecdsaPubKey2 = ecdsaKeyRing2.publicKeyInfo();
//console.log('ECDSA public key (after loading the key file in an other ring): ' + JSON.stringify(ecdsaPubKey2));
//Unit test, checking that the key has been loaded correctly
assert.equal(ecdsaPubKey2.publicKey.x == ecdsaPubKey.publicKey.x && ecdsaPubKey2.publicKey.y == ecdsaPubKey.publicKey.y && ecdsaPubKey2.curveName == ecdsaPubKey.curveName, true, 'ERROR : generated key and loaded key are not the same');
//Signing the message
var ecdsaSignature = ecdsaKeyRing.sign(ecdsaMessage, undefined, 'sha256');
var isEcdsaValid = cryptopp.ecdsa.prime.verify(ecdsaMessage, ecdsaSignature, ecdsaPubKey.publicKey, ecdsaPubKey.curveName, 'sha256');
//console.log('Is ECDSA signature valid : ' + isEcdsaValid);
//Unit test : invalid signature
assert.equal(isEcdsaValid, true, 'ERROR : the ECDSA signature seems invalid');
//Method clear to be called when you're done with the key ring, the keypair is flushed from memory
ecdsaKeyRing.clear();
ecdsaKeyRing2.clear();
//Unit test : asking for public key details when no key is loaded
assert.throws(function(){
	ecdsaKeyRing.publicKeyInfo();
}, TypeError, 'ECDSA key ring has not been cleared');

//console.log('\n### ECIES ###');
var eciesMessage = "Message to be encrypted by ECIES";
var eciesKeyRing = new cryptopp.KeyRing();
var eciesPubKey = eciesKeyRing.createKeyPair("ecies", "secp256r1", './eciesKeyRing.key');
//console.log('ECIES public key : ' + JSON.stringify(eciesPubKey));
//eciesKeyRing.save('./eciesKeyRing.key');
var eciesKeyRing2 = new cryptopp.KeyRing();
//Unit testing : the file doesn't exist
assert.throws(function(){
	eciesKeyRing2.load('./eciesKeyRing2.key');
}, TypeError, 'ERROR : the keypair file has been loaded even though it should not exist');
eciesKeyRing2.load('./eciesKeyRing.key');
//Encrypting message then decrypting it
var eciesCipher = cryptopp.ecies.prime.encrypt(eciesMessage, eciesPubKey.publicKey, eciesPubKey.curveName);
var eciesDecrypted = eciesKeyRing.decrypt(eciesCipher);
//Unit test : checking that the plaintexts are the same
//console.log('eciesMessage : ' + eciesMessage + '\neciesDecrypted : ' + eciesDecrypted);
assert.equal(eciesDecrypted == eciesMessage, true, 'ERROR : ECIES plaintexts are not the same');
eciesKeyRing.clear();
eciesKeyRing2.clear();

//console.log('\n### ECDH ###');
var ecdhKeyRing = new cryptopp.KeyRing();
var ecdhPubKey = ecdhKeyRing.createKeyPair("ecdh", "secp256r1");
//console.log('ECDH public key : ' + JSON.stringify(ecdhPubKey));
ecdhKeyRing.save('./ecdhKeyRing.key');
var ecdhKeyRing2 = new cryptopp.KeyRing();
ecdhKeyRing2.load('./ecdhKeyRing.key');
var ecdhKeyRing3 = new cryptopp.KeyRing();
var ecdhPubKey3 = ecdhKeyRing3.createKeyPair('ecdh', 'secp256r1');
//console.log('ECDH public key 2 : ' + JSON.stringify(ecdhPubKey3));
var secret1 = ecdhKeyRing.agree(ecdhPubKey3);
var secret2 = ecdhKeyRing3.agree(ecdhPubKey);
//console.log('ECDH secret 1 : ' + secret1 + '\nECDH secret 2 : ' + secret2);
assert.equal(secret1, secret2, 'ERROR : ECDH shared secrets are different!');
ecdhKeyRing.clear();
ecdhKeyRing2.clear();
ecdhKeyRing3.clear();

//console.log('\n### RSA ###');
var rsaKeyRing = new cryptopp.KeyRing();
var rsaPubKey = rsaKeyRing.createKeyPair("rsa", 2048);
var rsaPubKey2 = rsaKeyRing.publicKeyInfo();
//console.log('RSA public key : ' + JSON.stringify(rsaPubKey));
assert.equal(rsaPubKey.modulus == rsaPubKey2.modulus && rsaPubKey.publicExponent == rsaPubKey2.publicExponent, true, 'ERROR : .createKeyPair() & .publicKeyInfo() don\'t return the public key info object');
var rsaMessage = 'message to be encrypted and signed with RSA';
var rsaCipher = cryptopp.rsa.encrypt(rsaMessage, rsaPubKey.modulus, rsaPubKey.publicExponent);
var rsaSignature = rsaKeyRing.sign(rsaCipher, undefined, 'sha256');
var isSignatureValid = cryptopp.rsa.verify(rsaCipher, rsaSignature, rsaPubKey.modulus, rsaPubKey.publicExponent, 'sha256');
var rsaDecrypted = rsaKeyRing.decrypt(rsaCipher);
assert.equal(rsaMessage, rsaDecrypted, 'ERROR : RSA plaintexts are not the same');
assert.equal(isSignatureValid, true, 'ERROR : Invalid RSA signature');
rsaKeyRing.save('./rsaKeyRing.key');
var rsaKeyRing2 = new cryptopp.KeyRing();
rsaKeyRing2.load('./rsaKeyRing.key');
var rsaPubKey3 = rsaKeyRing2.publicKeyInfo();
assert.equal(rsaPubKey3.modulus == rsaPubKey.modulus && rsaPubKey3.publicExponent == rsaPubKey.publicExponent, true, 'ERROR : generated key and loaded key are not the same');
rsaKeyRing.clear();
rsaKeyRing2.clear();

//console.log('\n### DSA ###');
var dsaMessage = 'message to be signed by DSA';
var dsaKeyRing = new cryptopp.KeyRing();
var dsaPubKey = dsaKeyRing.createKeyPair('dsa', 2048, './dsaKeyRing.key');
//console.log('DSA key pair : ' + JSON.stringify(dsaPubKey));
var dsaKeyRing2 = new cryptopp.KeyRing();
dsaKeyRing2.load('./dsaKeyRing.key');
var dsaSignature = dsaKeyRing.sign(dsaMessage);
var isDsaValid = cryptopp.dsa.verify(dsaMessage, dsaSignature, dsaPubKey.primeField, dsaPubKey.divider, dsaPubKey.base, dsaPubKey.publicElement);
assert.equal(isDsaValid, true, 'ERROR : DSA signature seems invalid');
dsaKeyRing.clear();
dsaKeyRing2.clear();

//console.log('--------------------------');
//console.log('End of KeyRing test script');
//console.log('--------------------------');