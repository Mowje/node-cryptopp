# Old key file format (prior to node-cryptopp v0.2.2)
---------------------------------------------

Here is how a keypair file was built back then. Note that every number is in written in big endian, that the buffer resulting from the algorithm below was hex-encoded (for some reason I don't remember. But I don't think it was a valid reason. And I forgot to precise it in the README, like a big noob)

* algoType : a byte; 0x00 for ECDSA, 0x01 for RSA, 0x02 for DSA, 0x03 for ECDH, 0x04 for ECIES
* if keyType is ECDSA or ECIES
	* curveID : a byte, corresponding to the curve used
	* publicKeyX.length : length of the x coordinate of the public point (2 bytes, signed integer)
	* publicKeyX : x coordinate of the public point
	* publicKeyY.length : length of the y coordinate of the public point (2 bytes, signed integer)
	* publicKeyY : y coordinate of the public point
	* privateKey.length : length of the private key (2 bytes)
	* privateKey
* if keyType is RSA
	* modulus.length : length of the RSA modulus (2 bytes, signed integer)
	* modulus : RSA modulus
	* publicExponent.length : length of the public exponent (2 bytes, signed integer)
	* publicExponent : RSA public exponent (or public key)
	* privateExponent.length : length of the private exponent (2 bytes, signed integer)
	* privateExponent : RSA private exponent (or private key)
* if keyType is DSA
	* primeField.length : length of the prime field used by the DSA key pair (2 bytes, signed integer)
	* primeField
	* divider.length : length of the divider (2 bytes, signed integer)
	* divider
	* base.length : length of the base (2 bytes, signed integer)
	* base : DSA base
	* publicElement.length : length of the DSA public key (2 bytes, signed integer)
	* publicElement : DSA public key
	* privateExponent.length : length of the DSA private exponent (2 bytes, signed integer)
	* privateExponent : DSA private exponent (or private key)
* if keyType is ECDH
	* curveID : a byte, corresponding to the curve used
	* publicKey.length : length of the ECDH public key (2 bytes, signed integer)
	* publicKey : ECDH public key
	* privateKey.length : length of the ECDH private key (2 bytes, signed integer)
	* privateKey : ECDH private key