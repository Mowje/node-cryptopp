var cryptopp = require('./node-cryptopp.js');
var assert = require('assert');
var fs = require('fs');


var ecdsaKeyRing = new cryptopp.KeyRing();
var ecdsaPubKey = ecdsaKeyRing.createKeyPair("ecdsa", "secp256r1");
console.log("ECDSA public key : " + JSON.stringify(ecdsaPubKey));
ecdsaPubKey.save('./ecdsaKeyring.key');


var eciesKeyRing = new cryptopp.KeyRing();
var eciesPubKey = eciesKeyRing.createKeyPair("ecies", "secp256r1");
console.log('ECIES public key : ' + JSON.stringify(eciesPubKey));

var ecdhKeyRing = new cryptopp.KeyRing();
var ecdhPubKey = ecdhKeyRing.createKeyPair("ecdh", "secp256r1");
console.log('ECDH public key : ' + JSON.stringify(ecdhPubKey));

var rsaKeyRing = new cryptopp.KeyRing();
var rsaPubKey = rsaKeyRing.createKeyPair("rsa", 2048);
var rsaPubKey2 = rsaKeyRing.publicKeyInfo();
console.log('RSA public key : ' + JSON.stringify(rsaPubKey));
assert.notEqual(rsaPubKey == rsaPubKey2, true, 'ERROR : .createKeyPair() & .publicKeyInfo() don\'t return the public key info object');

var dsaKeyRing = new cryptopp.KeyRing();
var dsaPubKey = dsaKeyRing.createKeyPair('dsa', 2048);
console.log('DSA key pair : ' + JSON.stringify(dsaPubKey));

console.log('--------------------------');
console.log('End of KeyRing test script');
console.log('--------------------------');