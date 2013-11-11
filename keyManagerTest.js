var cryptopp = require('./node-cryptopp.js');
var assert = require('assert');
var fs = require('fs');
var Buffer = require('buffer').Buffer;

console.log('--------------------------');
console.log('   KeyRing test script    ');
console.log('--------------------------');

var ecdsaMessage = 'Message to be signed by ECDSA'
var ecdsaKeyRing = new cryptopp.KeyRing();
var ecdsaPubKey = ecdsaKeyRing.createKeyPair("ecdsa", "secp256r1");
console.log("ECDSA public key : " + JSON.stringify(ecdsaPubKey));
ecdsaKeyRing.save('./ecdsaKeyRing.key');
var ecdsaKeyRing2 = new cryptopp.KeyRing();
ecdsaKeyRing2.load('./ecdsaKeyRing.key');
//Unit test, checking that the key has been loaded correctly
assert.notEqual(ecdsaKeyRing2.publicKeyInfo(), ecdsaPubKey, 'ERROR : generated key and loaded key are not the same');
//Signing the message
var ecdsaSignature = ecdsaKeyRing.sign(ecdsaMessage);
var isEcdsaValid = cryptopp.ecdsa.prime.verify(ecdsaMessage, ecdsaSignature, ecdsaPubKey.publicKey, ecdsaPubKey.curveName);
console.log('Is ECDSA signature valid : ' + isEcdsaValid);
//Unit test : invalid signature
assert.notEqual(isEcdsaValid, true, 'ERROR : the ECDSA signature seems invalid');
//Method clear to be called when you're done with the key ring, the keypair is flushed from memory
ecdsaKeyRing.clear();
ecdsaKeyRing2.clear();
//Unit test : asking for public key details when no key is loaded
assert.throws(function(){
	ecdsaKeyRing.publicKeyInfo();
}, TypeError, 'ECDSA key ring has not been cleared');

var eciesMessage = "Message to be encrypted by ECIES";
var eciesKeyRing = new cryptopp.KeyRing();
var eciesPubKey = eciesKeyRing.createKeyPair("ecies", "secp256r1");
console.log('ECIES public key : ' + JSON.stringify(eciesPubKey));
eciesKeyRing.save('./eciesKeyRing.key');
var eciesKeyRing2 = new cryptopp.KeyRing();
//Unit testing : the file doesn't exist
assert.throws(function(){
	eciesKeyRing2.load('./eciesKeyRing2.key');
}, TypeError, 'ERROR : the keypair file has been loaded even though it should not exist');
eciesKeyRing2.load('./eciesKeyRing.key');
//Encrypting message then decrypting it
var eciesCipher = cryptopp.ecies.prime.encrypt(eciesMessage, eciesPubKey.publicKey, eciesPubKey.curveName);
var eciesDecrypted = eciesKeyRing.decrypt(eciesCipher);
if (eciesMessage !== eciesDecrypted){
	throw new TypeError('ERROR : ECIES plaintexts are not the same');
}
//Unit test : checking that the plaintexts are the same
console.log('eciesMessage : ' + eciesMessage + '\neciesDecrypted : ' + eciesDecrypted);
//assert.notEqual(eciesDecrypted == eciesMessage, true, 'ERROR : ECIES plaintexts are not the same');

var ecdhKeyRing = new cryptopp.KeyRing();
var ecdhPubKey = ecdhKeyRing.createKeyPair("ecdh", "secp256r1");
console.log('ECDH public key : ' + JSON.stringify(ecdhPubKey));
ecdhKeyRing.save('./ecdhKeyring.key');
var ecdhKeyRing2 = new cryptopp.KeyRing();
ecdhKeyRing2.load('./ecdhKeyring.key');
var ecdhKeyRing3 = new cryptopp.KeyRing();
var ecdhPubKey3 = ecdhKeyRing3.createKeyPair('ecdh', 'secp256r1');
var secret1 = ecdhKeyRing.agree(ecdhPubKey3);
var secret2 = ecdhKeyRing3.agree(ecdhPubKey);
console.log('ECDH secret 1 : ' + secret1 + '\nECDH secret 2 : ' + secret2);
if (secret1 !== secret2){
	throw new TypeError('ERROR : ECDH shared secrets are different!');
}

var rsaKeyRing = new cryptopp.KeyRing();
var rsaPubKey = rsaKeyRing.createKeyPair("rsa", 2048);
var rsaPubKey2 = rsaKeyRing.publicKeyInfo();
console.log('RSA public key : ' + JSON.stringify(rsaPubKey));
assert.notEqual(rsaPubKey == rsaPubKey2, true, 'ERROR : .createKeyPair() & .publicKeyInfo() don\'t return the public key info object');
var rsaMessage = 'message to be encrypted and signed  with RSA';
var rsaCipher = cryptopp.rsa.encrypt(rsaMessage, rsaPubKey.modulus, rsaPubKey.publicExponent);
var rsaSignature = rsaKeyRing.sign(rsaCipher);
var isSignatureValid = cryptopp.rsa.verify(rsaCipher, rsaSignature, rsaPubKey.modulus, rsaPubKey.publicExponent);


var dsaKeyRing = new cryptopp.KeyRing();
var dsaPubKey = dsaKeyRing.createKeyPair('dsa', 2048);
console.log('DSA key pair : ' + JSON.stringify(dsaPubKey));

console.log('--------------------------');
console.log('End of KeyRing test script');
console.log('--------------------------');