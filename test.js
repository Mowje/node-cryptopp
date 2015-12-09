var cryptopp = require('./node-cryptopp.js');
var crypto = require('crypto');
var assert = require('assert');
// NOTE : when you have installed node-cryptopp, use require('cryptopp') instead

var useFuzzing = false;
var yell = false;

if (process.argv.length > 2){
	for (var i = 2; i < process.argv.length; i++){
		if (process.argv[i] == 'verbose') yell = true;
		else if (process.argv[i] == 'fuzzing') useFuzzing = true;
	}
}

log('CRYPTOPP TEST AND EXAMPLE SCRIPT');

function log(m){
	if (yell) console.log(m);
}

function rand(){
	return crypto.randomBytes(crypto.randomBytes(1)[0] + 1).toString('hex');
}

// Testing hexadecimal encoding/decoding
var hexTest = "testing hex encoding";
var hexEncoded = cryptopp.hex.encode(hexTest);
var hexDecoded = cryptopp.hex.decode(hexEncoded);
log('\n### Testing hexadecimal encoding/decoding ###\nTest message : ' + hexTest + "\nEncoded : " + hexEncoded + "\nDecoded : " + hexDecoded);
assert.equal(hexTest, hexDecoded, 'Problem with hex encoding');

// Testing Base64 encoding/decoding
var base64Test = "testing Base64 encoding";
var base64Encoded = cryptopp.base64.encode(base64Test);
var base64Decoded = cryptopp.base64.decode(base64Encoded);
log('\n### Testing base64 encoding/decoding ###\nTest message : ' + base64Test + "\nEncoded : " + base64Encoded + "\nDecoded : " + base64Decoded);
assert.equal(base64Test, base64Decoded, 'Problem with base64 encoding');

// Testing random byte generation
var randomBytes1 = cryptopp.randomBytes(5, 'base64');
var randomBytes2 = cryptopp.randomBytes(10);
log('\n### Testing random bytes generation ###\nRandom bytes : ' + randomBytes1 + '\nOther random bytes : ' + randomBytes2);

// Testing RSA encryption/decryption
var rsaTest = "testing RSA encryption/decryption";
var rsaKeyPair = cryptopp.rsa.generateKeyPair(2048);
log("\n### Testing RSA encryption/decryption ###\nTest message : " + rsaTest + "\nModulus : " + rsaKeyPair.modulus + "\nPublic exponent : " + rsaKeyPair.publicExponent + "\nPrivate exponent : " + rsaKeyPair.privateExponent);
var rsaCipher = cryptopp.rsa.encrypt(rsaTest, rsaKeyPair.modulus, rsaKeyPair.publicExponent);
log("Cipher :\n" + rsaCipher);
var rsaDecrypted = cryptopp.rsa.decrypt(rsaCipher, rsaKeyPair.modulus, rsaKeyPair.privateExponent, rsaKeyPair.publicExponent);
log("Plain text (decrypted) : " + rsaDecrypted);
assert.equal(rsaTest, rsaDecrypted, 'The RSA decrypted message is invalid');

//Testing RSA signature and verification
var rsaSignTest = "testing RSA signature and verification";
var rsaSignKeyPair = cryptopp.rsa.generateKeyPair(2048);
var otherRsaSignKeyPair = cryptopp.rsa.generateKeyPair(2048);
log('\n### Testing RSA signature and verification ###\nTest message : ' + rsaSignTest + '\nModulus : ' + rsaSignKeyPair.modulus + '\nPublic exponent : ' + rsaSignKeyPair.publicExponent + '\nPrivate exponent : ' + rsaSignKeyPair.privateExponent);
var rsaSignature = cryptopp.rsa.sign(rsaSignTest, rsaKeyPair.modulus, rsaKeyPair.privateExponent, rsaKeyPair.publicExponent);
log('Signature : ' + rsaSignature)
var isRsaSignValid = cryptopp.rsa.verify(rsaSignTest, rsaSignature, rsaKeyPair.modulus, rsaKeyPair.publicExponent);
var otherIsRsaSignValid = cryptopp.rsa.verify(rsaSignTest, rsaSignature, otherRsaSignKeyPair.modulus, otherRsaSignKeyPair.publicExponent);
//var fuzzingRsaValid = cryptopp.rsa.verify(rsaSignTest, rand(), rsaKeyPair.modulus, otherRsaSignKeyPair.publicExponent);
log('Is signature valid : ' + isRsaSignValid);
assert.deepEqual(isRsaSignValid, true, 'The RSA signature is invalid');
assert.deepEqual(otherIsRsaSignValid, false, 'RSA signatures do not work!');
//assert.deepEqual(fuzzingRsaValid, false, 'RSA signatures can spoofed with fuzzing!');

if (useFuzzing){
	log('RSA fuzzing test : generating random data and passing it through RSA methods to check that exceptions are raised');
	function RsaEncFuzzing(){
		cryptopp.rsa.encrypt(rsaTest, rand(), rand());
	}
	function RsaDecFuzzing(){
		cryptopp.rsa.decrypt(rand(), rand(), rand(), rand());
	}
	function RsaSigFuzzing(){
		cryptopp.rsa.sign(rsaSignTest, rand(), rand(), rand());
	}
	function RsaVerFuzzing(){
		var isValid = cryptopp.rsa.verify(rsaSignTest, rand(), rand(), rand());
		assert.deepEqual(isValid, false, 'Random data was accepted as valid RSA signature!!!');
	}
	log('Fuzzing RSA encryption');
	try {
		RsaEncFuzzing();
		console.log('RSA encryption fuzzing didn\'t raise an exception')
	} catch (e){}
	log('Fuzzing RSA decryption');
	assert.throws(RsaDecFuzzing, Error, 'RSA decryption fuzzing didn\'t raise an exception');
	log('Fuzzing RSA signature');
	assert.throws(RsaSigFuzzing, Error, 'RSA signature fuzzing didn\'t raise an exception');
	log('Fuzzing RSA signature verification');
	try { //RSA signature verification doesn't always throw an exception when random data is thrown at it
		RsaVerFuzzing();
		console.log('RSA signature verification fuzzing didn\'t raise an exception');
	} catch (e){}
}

// Testing DSA signature and verification
var dsaTest = "testing DSA signature scheme";
var dsaKeyPair = cryptopp.dsa.generateKeyPair(2048);
var otherDsaKeyPair = cryptopp.dsa.generateKeyPair(2048);
log("\n### Testing DSA signature/verification ###\nTest message : " + dsaTest + "\nPrime Field : " + dsaKeyPair.primeField + "\nDivider : " + dsaKeyPair.divider + "\nBase : " + dsaKeyPair.base + "\nPrivate exponent : " + dsaKeyPair.privateExponent + "\nPublic element : " + dsaKeyPair.publicElement);
var dsaSignature = cryptopp.dsa.sign(dsaTest, dsaKeyPair.primeField, dsaKeyPair.divider, dsaKeyPair.base, dsaKeyPair.privateExponent);
log("Signature : " + dsaSignature);
var dsaIsValid = cryptopp.dsa.verify(dsaTest, dsaSignature, dsaKeyPair.primeField, dsaKeyPair.divider, dsaKeyPair.base, dsaKeyPair.publicElement);
var otherDsaIsValid = cryptopp.dsa.verify(dsaTest, dsaSignature, otherDsaKeyPair.primeField, otherDsaKeyPair.divider, otherDsaKeyPair.base, otherDsaKeyPair.publicElement);
//var fuzzingDsaValid = cryptopp.dsa.verify(dsaTest, crypto.randomBytes(crypto.randomBytes(1)[0] + 1).toString('hex'), dsaKeyPair.primeField, dsaKeyPair.divider, dsaKeyPair.base, dsaKeyPair.publicElement);
log("Is signature valid : " + dsaIsValid);
assert.deepEqual(dsaIsValid, true, 'The DSA signature is invalid');
assert.deepEqual(otherDsaIsValid, false, 'DSA signatures do not work!');
//assert.deepEqual(fuzzingDsaValid, false, 'DSA signatures can be spoofed with fuzzing!');

if (useFuzzing){
	log('DSA fuzzing test : generating random data and passing it through DSA methods to check that exceptions are raised');
	function dsaSigFuzzing(){
		cryptopp.dsa.sign(dsaTest, rand(), rand(), rand(), rand());
	}
	function dsaVerFuzzing(){
		var isValid = cryptopp.dsa.verify(dsaTest, rand(), rand(), rand(), rand(), rand());
		assert.deepEqual(isValid, false, 'Random data was accepted as valid DSA signature!!!');
	}
	log('Fuzzing signature');
	try {
		dsaSigFuzzing();
		log('DSA signature fuzzing didn\'t raise an exception');
	} catch (e){}
	log('Fuzzing siganture verification');
	try {
		dsaVerFuzzing();
		log('DSA verification fuzzing didn\'t raise an exception');
	} catch (e){}
}

// Testing ECIES encryption/decryption
var eciesTest = "Testing ECIES encryption/decryption";
var eciesKeyPair = cryptopp.ecies.prime.generateKeyPair("secp256r1");
log("\n### Testing ECIES encryption/decryption on prime fields###\nTest message : " + eciesTest + "\nCurve name : " + eciesKeyPair.curveName + "\nPrivate key : " + eciesKeyPair.privateKey + "\nPublic key :\n\tx : " + eciesKeyPair.publicKey.x + "\n\ty : " + eciesKeyPair.publicKey.y);
var eciesCipher = cryptopp.ecies.prime.encrypt(eciesTest, eciesKeyPair.publicKey, "secp256r1");
log("Cipher :\n" + eciesCipher);
var eciesDecrypted = cryptopp.ecies.prime.decrypt(eciesCipher, eciesKeyPair.privateKey, "secp256r1");
log("Plain text (decrypted) : " + eciesDecrypted);
assert.equal(eciesTest, eciesDecrypted, 'The decrypted ECIES message is invalid (prime fields)');

if (useFuzzing){
	/*
	function eciesPrimeKeyPairFuzzing(){
		cryptopp.ecies.prime.generateKeyPair(rand());
	}*/
	function eciesPrimeEncFuzzing(){
		cryptopp.ecies.prime.encrypt(eciesTest, {x: rand(), y: rand()}, 'secp256r1');
	}
	function eciesPrimeDecFuzzing(){
		cryptopp.ecies.prime.decrypt(eciesCipher, rand(), 'secp256r1');
	}

	//eciesPrimeKeyPairFuzzing();
	try {
		eciesPrimeEncFuzzing();
		console.log('ECIES encryption (with fuzzing) on prime curve didn\'t raise an exception');
	} catch (e){}
	try {
		eciesPrimeDecFuzzing();
		console.log('ECIES decryption (with fuzzing) on prime curve didn\'t raise an exception');
	} catch (e){}
}

//Testing ECIES on binary fields
eciesKeyPair = cryptopp.ecies.binary.generateKeyPair('sect283r1');
log('\n### Testing ECIES encryption/decryption on binary fields###\nCurve name : ' + eciesKeyPair.curveName + '\nPrivate key : ' + eciesKeyPair.privateKey + '\nPublic key\n\tx : ' + eciesKeyPair.publicKey.x + '\n\ty : ' + eciesKeyPair.publicKey.y);
eciesCipher = cryptopp.ecies.binary.encrypt(eciesTest, eciesKeyPair.publicKey, 'sect283r1');
log('Cipher :\n' + eciesCipher);
eciesDecrypted = cryptopp.ecies.binary.decrypt(eciesCipher, eciesKeyPair.privateKey, 'sect283r1');
log('Plain text (decrypted) : ' + eciesDecrypted);
assert.equal(eciesTest, eciesDecrypted, 'The decrypted ECIES message is invalid (binary fields)');

if (useFuzzing){
	/*function eciesBinaryKeyPairFuzzing(){
		cryptopp.ecies.binary.generateKeyPair(rand());
	}*/
	function eciesBinaryEncFuzzing(){
		cryptopp.ecies.binary.encrypt(eciesTest, {x: rand(), y: rand()}, 'sect283r1');
	}
	function eciesBinaryDecFuzzing(){
		cryptopp.ecies.binary.decrypt(eciesCipher, rand(), 'sect283r1');
	}

	//eciesBinaryKeyPairFuzzing();
	try {
		eciesBinaryEncFuzzing();
		console.log('ECIES encryption (with fuzzing) on binary curve didn\'t raise an exception');
	} catch (e){}
	try {
		eciesBinaryDecFuzzing();
		console.log('ECIES decryption (with fuzzing) on binary curve didn\'t raise an exception');
	} catch (e){}
}

//Testing ECDSA signing and verification on prime fields
var ecdsaTest = "testing ECDSA signing and verification";
var ecdsaKeyPair = cryptopp.ecdsa.prime.generateKeyPair("secp256r1");
var otherEcdsaKeyPair = cryptopp.ecdsa.prime.generateKeyPair('secp256r1');
log("\n### Testing ECDSA signing and verification on prime fields ###\nTest message : " + ecdsaTest + "\nCurve name : " + ecdsaKeyPair.curveName + "\nPrivate key : " + ecdsaKeyPair.privateKey + "\nPublic key :\n\tx : " + ecdsaKeyPair.publicKey.x + "\n\ty : " + ecdsaKeyPair.publicKey.y);
var ecdsaSignature = cryptopp.ecdsa.prime.sign(ecdsaTest, ecdsaKeyPair.privateKey, "secp256r1");
log("Signature : " + ecdsaSignature);
var ecdsaIsValid = cryptopp.ecdsa.prime.verify(ecdsaTest, ecdsaSignature, ecdsaKeyPair.publicKey, "secp256r1");
var ecdsaIsNotValid = cryptopp.ecdsa.prime.verify(ecdsaTest, ecdsaSignature, otherEcdsaKeyPair.publicKey, 'secp256r1');
//var fuzzingEcdsaValid = cryptopp.ecdsa.prime.verify(ecdsaTest, crypto.randomBytes(crypto.randomBytes(1)[0] + 1).toString('hex'), ecdsaKeyPair.publicKey, "secp256r1");
log("Is valid : " + ecdsaIsValid);
assert.deepEqual(ecdsaIsValid, true, 'The ECDSA signature is invalid (prime fields)');
assert.deepEqual(ecdsaIsNotValid, false, 'ECDSA signatures verification does not work!!!');
//assert.deepEqual(fuzzingEcdsaValid, false, 'ECDSA signatures can be spoofed with fuzzing!');

if (useFuzzing){
	/*function ecdsaPrimeKeyPairFuzzing(){
		cryptopp.ecdsa.prime.createKeyPair(rand());
	}*/
	function ecdsaPrimeSigFuzzing(){
		cryptopp.ecdsa.prime.sign(ecdsaTest, rand(), 'secp256r1');
	}
	function ecdsaPrimeVerFuzzing(){
		var isValid = cryptopp.ecdsa.prime.verify(ecdsaTest, rand(), {x: rand(), y: rand()}, 'secp256r1');
		assert.deepEqual(isValid, false, 'Random data was accepted as valid ECDSA siganture!!!');
	}

	try {
		ecdsaPrimeSigFuzzing();
		console.log('ECDSA signature (with fuzzing) on prime curve didn\'t raise an exception');
	} catch (e){}
	try {
		ecdsaPrimeVerFuzzing();
		console.log('ECDSA verification (with fuzzing) on prime curve didn\'t raise on exception');
	} catch(e){}
}

//Testing ECDSA signing and verification on binary fields
/*ecdsaKeyPair = cryptopp.ecdsa.binary.generateKeyPair('sect283r1');
console.log('\n### Testing ECDSA signing and verification on binary fields ###\nCurve name : ' + ecdsaKeyPair.curveName + '\nPrivate key : ' + ecdsaKeyPair.privateKey + '\nPublic key :\n\tx : ' + ecdsaKeyPair.publicKey.x + '\n\ty : ' + ecdsaKeyPair.publicKey.y);
ecdsaSignature = cryptopp.ecdsa.binary.sign(ecdsaTest, ecdsaKeyPair.privateKey, 'sect283r1');
console.log('Signature : ' + ecdsaSignature);
ecdsaIsValid = cryptopp.ecdsa.binary.verify(ecdsaTest, ecdsaSignature, ecdsaKeyPair.publicKey, 'sect283r1');
console.log('Is valid : ' + ecdsaIsValid);*/

//Testing ECDH key agreement protocol on prime fields
log("\n### Testing ECDH key agreement on prime fields ###");
var keyPair1 = cryptopp.ecdh.prime.generateKeyPair("secp256r1");
var keyPair2 = cryptopp.ecdh.prime.generateKeyPair("secp256r1");
log("Key pair 1 :\nPrivate key : " + keyPair1.privateKey + "\nPublic key : " + keyPair1.publicKey + "\nCurve name : " + keyPair1.curveName + "\n");
log("Key pair 2 :\nPrivate key : " + keyPair2.privateKey + "\nPublic key : " + keyPair2.publicKey + "\nCurve name : " + keyPair2.curveName + "\n");
log("Calculating first secret");
var secret1 = cryptopp.ecdh.prime.agree(keyPair1.privateKey, keyPair2.publicKey, keyPair1.curveName);
log("Calculating second secret");
var secret2 = cryptopp.ecdh.prime.agree(keyPair2.privateKey, keyPair1.publicKey, keyPair2.curveName);
assert.equal(secret1, secret2, 'The shared secret isn\'t the same (prime fields)');
log("Secret 1 :\n" + secret1);
log("Secret 2 :\n" + secret2);

if (useFuzzing){
	function ecdhAgreePrimeFuzzing(){
		cryptopp.ecdh.prime.agree(rand(), {x: rand(), y: rand()}, 'secp256r1');
	}
	try {
		ecdhAgreePrimeFuzzing();
		console.log('ECDH agreement method (with fuzzing) on prime curve didn\'t raise an exception');
	} catch (e){}
}

//Testing ECDH on binary fields
/*
log('\n### Testing ECDH key agreement on binary fields ###');
keyPair1 = cryptopp.ecdh.binary.generateKeyPair('sect283r1');
keyPair2 = cryptopp.ecdh.binary.generateKeyPair('sect283r1');
log('Key pair 1 :\nPrivate key : ' + keyPair1.privateKey + '\nPublic key : ' + keyPair1.publicKey + '\nCurve name : ' + keyPair1.curveName + '\n');
log('Key pair 2 :\nPrivate key : ' + keyPair2.privateKey + '\nPublic key : ' + keyPair2.publicKey + '\nCurve name : ' + keyPair2.curveName + '\n');
log('Calculating first secret');
secret1 = cryptopp.ecdh.binary.agree(keyPair1.privateKey, keyPair2.publicKey, keyPair1.curveName);
log('Calculating second secret');
secret2 = cryptopp.ecdh.binary.agree(keyPair2.privateKey, keyPair1.publicKey, keyPair2.curveName);
log('Secret 1 :\n' + secret1 + '\nSecret 2 :\n' + secret2);
assert.equal(secret1, secret2, 'The shared secret isn\'t the same (binary fields)');
*/
log('\nCRYPTOPP TEST SCRIPT ENDED SUCCESSFULLY');
