//An example script where everything is done asynchronously

var cryptopp = require('./node-cryptopp.js');
var readline = require('readline');

var rl = readline.createInterface({
	input: process.stdin,
	output: process.stdout
});

rl.question('What algorithm do want to test in async mode ? ', function(answer){
	answer = answer.toLowerCase();
	if (!(answer == "ecdsa" || answer == "ecies" || answer == "ecdh" || answer == "rsa" || answer == "dsa")){
		console.log('Unknown algorithm ' + answer + '\nExiting');
		process.exit();
	}
	var keyRing = new cryptopp.KeyRing();
	if (answer == "ecdsa"){
		keyRing.createKeyPair('ecdsa', 'secp192r1', undefined, undefined, function(pubKey){
			console.log('ECDSA public key : ' + JSON.stringify(pubKey));
			rl.question('Enter the message you want to sign : ', function(message){
				keyRing.sign(message, undefined, undefined, function(signature){
					console.log('Signature : ' + signature);
					cryptopp.ecdsa.prime.verify(message, signature, pubKey.publicKey, pubKey.curveName, undefined, function(isValid){
						console.log('Is signature valid : ' + isValid);
						rl.close();
					})
				});
			});
		});
	} else if (answer == "ecies"){
		keyRing.createKeyPair('ecies', 'secp192r1', undefined, undefined, function(pubKey){
			console.log('ECIES public key : ' + JSON.stringify(pubKey));
			rl.question('Enter the message you want to encrypt : ', function(message){
				cryptopp.ecies.prime.encrypt(message, pubKey.publicKey, pubKey.curveName, function(cipherText){
					console.log('Ciphertext : ' + cipherText);
					keyRing.decrypt(cipherText, undefined, function(plainText){
						console.log('Decypted text : ' + plainText);
						rl.close();
					});
				});
			});
		});
	} else if (answer == "ecdh"){
		keyRing.createKeyPair('ecdh', 'secp192r1', undefined, undefined, function(pubKey){
			console.log('Public key 1 : ' + JSON.stringify(pubKey));
			var keyRing2 = new cryptopp.KeyRing();
			keyRing2.createKeyPair('ecdh', 'secp192r1', undefined, undefined, function(pubKey2){
				console.log('Public key 2 : ' + JSON.stringify(pubKey2));
				keyRing.agree(pubKey2, function(secret1){
					keyRing2.agree(pubKey, function(secret2){
						console.log('Secret 1 : ' + secret1 + '\nSecret 2 : ' + secret2);
						rl.close();
					});
				});
			});
		});
	} else if (answer == "rsa"){
		keyRing.createKeyPair('rsa', 2048, undefined, undefined, function(pubKey){
			console.log('Public key : ' + JSON.stringify(pubKey));
			rl.question('Enter the message you want to encrypt and sign : ', function(message){
				cryptopp.rsa.encrypt(message, pubKey.modulus, pubKey.publicExponent, function(cipherText){
					console.log('Ciphertext : ' + cipherText);
					keyRing.sign(cipherText, undefined, 'sha256', function(signature){
						console.log('Signature : ' + signature);
						cryptopp.rsa.verify(cipherText, signature, pubKey.modulus, pubKey.publicExponent, 'sha256', function(isValid){
							console.log('Is signature valid : ' + isValid);
							keyRing.decrypt(cipherText, undefined, function(plainText){
								console.log('Decrypted text : ' + plainText);
								rl.close();
							});
						})
					});
				});
			});
		});
	} else if (answer == "dsa"){
		keyRing.createKeyPair('dsa', 2048, undefined, undefined, function(pubKey){
			console.log('Public key : ' + JSON.stringify(pubKey));
			rl.question('Enter the message you want to sign : ', function(message){
				keyRing.sign(message, undefined, undefined, function(signature){
					console.log('Signature : ' + signature);
					cryptopp.dsa.verify(message, signature, pubKey.primeField, pubKey.divider, pubKey.base, pubKey.publicElement, function(isValid){
						console.log('Is signature valid : ' + isValid);
						rl.close();
					});
				});
			});
		});
	}
});