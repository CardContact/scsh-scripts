/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2009 CardContact Software & System Consulting
 * |'##> <##'|  Andreas Schwier, 32429 Minden, Germany (www.cardcontact.de)
 *  --------- 
 *
 *  This file is part of OpenSCDP.
 *
 *  OpenSCDP is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  OpenSCDP is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with OpenSCDP; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * @fileoverview Basic helper functions to convert PKCS#8 data to GP keys and vice versa
 */



/**
 * Empty constructor
 */
function PKCS8() {
}



PKCS8.idEcPublicKey = new ByteString("id-ecPublicKey", OID);
PKCS8.rsaEncryption = new ByteString("1.2.840.113549.1.1.1", OID);

/**
 * Convert x/y coordinates to uncompressed format
 *
 * @param {ByteString} x the x coordinate
 * @param {ByteString} y the y coordinate
 * @type ByteString
 * @return ByteString containing compressed format
 *
 */ 
PKCS8.encodeUncompressedECPoint = function(x,y) {

	bb = new ByteBuffer();

	// uncompressed encoding
	bb.append(new ByteString("04", HEX));
	bb.append(x);
	bb.append(y);

	return bb.toByteString();
}



/**
 * Convert uncompressed format to x and y coordinates
 *
 * @param {ByteString} compressed point
 * @type Object
 * @return Object with ByteString properties x and y
 *
 */ 
PKCS8.decodeUncompressedECPoint = function(uncompressedPoint) {

	// Determine the size of the coordinates ignoring the indicator byte '04'
	var length = uncompressedPoint.length - 1;

	var sizeOfCoordinate = length >> 1;

	var xValue = uncompressedPoint.bytes(1, sizeOfCoordinate);
	var yValue = uncompressedPoint.bytes(1 + sizeOfCoordinate, sizeOfCoordinate);

	return { x:xValue, y:yValue };
} 



/**
 * Strips leading zeros of a ByteString
 *
 * @param {ByteString} value the ByteString value
 * @return the stripped ByteString object, may be an empty ByteString
 * @type ByteString
 */
PKCS8.stripLeadingZeros = function(value) {
	var i = 0;
	for (; (i < value.length) && (value.byteAt(i) == 0); i++);
	
	return value.right(value.length - i);
}



/**
 * Removes leading zeros and prepends a single '00' to ByteStrings which have the most significant bit set.
 *
 * This prevent interpretation of the integer representation if converted into
 * a signed ASN1 INTEGER.
 *
 * @param {ByteString} value the value to convert
 * @return the converted value
 * @type ByteString
 */
PKCS8.convertUnsignedInteger = function(value) {
	assert(value.length > 0);
	
	var i = 0;
	for (var i = 0; (i < value.length - 1) && (value.byteAt(i) == 0); i++);
	
	if (value.byteAt(i) >= 0x80) {
		value = (new ByteString("00", HEX)).concat(value.bytes(i));
	} else {
		value = value.bytes(i);
	}
	
	return value;
}



/**
 * Encode a given GP ECC private key as specified by the PKCS#8 format
 *
 * @param {Key} the private key object that should be encoded
 * @return the encoded PKCS#8 private key
 * @type ByteString
 */
PKCS8.encodeECCKeyUsingPKCS8Format = function(privateKey) {
	var privateKeyInfo = new ASN1(ASN1.SEQUENCE);
	
	// Set the version number - must be zero
	privateKeyInfo.add(new ASN1(ASN1.INTEGER, new ByteString("00", HEX)));
	
	var privateKeyAlgorithm = new ASN1(ASN1.SEQUENCE);
	privateKeyAlgorithm.add(new ASN1(ASN1.OBJECT_IDENTIFIER, PKCS8.idEcPublicKey));
	
	var domainInfo = new ASN1(ASN1.SEQUENCE);
	
	// Cofactor - must be 1
	domainInfo.add(new ASN1(ASN1.INTEGER, PKCS8.stripLeadingZeros(privateKey.getComponent(Key.ECC_H))));
	
	var field = new ASN1(ASN1.SEQUENCE);
	
	// we are using a prime field
	field.add(new ASN1(ASN1.OBJECT_IDENTIFIER, new ByteString("prime-field", OID))); // prime field
	
	var primeOrder = privateKey.getComponent(Key.ECC_P);
	if (primeOrder.byteAt(0) >= 0x80) { // signed int? -> add 0x00
		field.add(new ASN1(ASN1.INTEGER, new ByteString("00", HEX).concat(privateKey.getComponent(Key.ECC_P))));
	} else {
		field.add(new ASN1(ASN1.INTEGER, privateKey.getComponent(Key.ECC_P)));
	}
	
	domainInfo.add(field);
	
	// Coefficients a and b
	var coeff = new ASN1(ASN1.SEQUENCE);
	
	// first coefficient
	coeff.add(new ASN1(ASN1.OCTET_STRING, privateKey.getComponent(Key.ECC_A)));
	
	// second coefficient
	coeff.add(new ASN1(ASN1.OCTET_STRING, privateKey.getComponent(Key.ECC_B)));
	
	domainInfo.add(coeff);
	
	// Base point (uncompressed)
	var gx = privateKey.getComponent(Key.ECC_GX);
	var gy = privateKey.getComponent(Key.ECC_GY);
	
	domainInfo.add(new ASN1(ASN1.OCTET_STRING, PKCS8.encodeUncompressedECPoint(gx, gy)));
	
	// group order generated by the base point
	var groupOrder = privateKey.getComponent(Key.ECC_N);
	if (groupOrder.byteAt(0) >= 0x80) { // signed int? -> add 0x00
		domainInfo.add(new ASN1(ASN1.INTEGER, new ByteString("00", HEX).concat(privateKey.getComponent(Key.ECC_N))));
	} else {
		domainInfo.add(new ASN1(ASN1.INTEGER, privateKey.getComponent(Key.ECC_N)));
	}
	
	privateKeyAlgorithm.add(domainInfo);
	
	// encode the key information
	privateKeyInfo.add(privateKeyAlgorithm);
	
	// encode the private key
	var encodedPrivateKey = new ASN1(ASN1.OCTET_STRING);
	
	var pk = privateKey.getComponent(Key.ECC_D);
	var key = new ASN1(ASN1.SEQUENCE);
	key.add(new ASN1(ASN1.INTEGER, new ByteString("01", HEX)));
	key.add(new ASN1(ASN1.OCTET_STRING, pk));
	
	encodedPrivateKey.add(key);
	
	privateKeyInfo.add(encodedPrivateKey);
	
	print(privateKeyInfo);
	return privateKeyInfo.getBytes();	
}



/**
 * Encode RSA private key as defined in PKCS#1
 *
 * RSAPrivateKey ::= SEQUENCE {
 *     version           Version,
 *     modulus           INTEGER,  -- n
 *     publicExponent    INTEGER,  -- e
 *     privateExponent   INTEGER,  -- d
 *     prime1            INTEGER,  -- p
 *     prime2            INTEGER,  -- q
 *     exponent1         INTEGER,  -- d mod (p-1)
 *     exponent2         INTEGER,  -- d mod (q-1)
 *     coefficient       INTEGER,  -- (inverse of q) mod p
 *     otherPrimeInfos   OtherPrimeInfos OPTIONAL
 * }
 * @param {Key} privateKey the private RSA key in CRT format
 * @type ByteString
 * @return the encoded RSA key
 */
PKCS8.encodeRSAKey = function(privateKey, publicKey) {
	var rsaPrivateKey = 
		new ASN1(ASN1.SEQUENCE);
		
	rsaPrivateKey.add(new ASN1(ASN1.INTEGER, ByteString.valueOf(0)));
	if (typeof(publicKey) != "undefined") {
		rsaPrivateKey.add(new ASN1(ASN1.INTEGER, PKCS8.convertUnsignedInteger(publicKey.getComponent(Key.MODULUS))));
		rsaPrivateKey.add(new ASN1(ASN1.INTEGER, PKCS8.convertUnsignedInteger(publicKey.getComponent(Key.EXPONENT))));
	} else {
		rsaPrivateKey.add(new ASN1(ASN1.INTEGER, ByteString.valueOf(0)));
		rsaPrivateKey.add(new ASN1(ASN1.INTEGER, ByteString.valueOf(0)));
	}
	rsaPrivateKey.add(new ASN1(ASN1.INTEGER, ByteString.valueOf(0)));		// Private Exponent not at interface for CRT format
	rsaPrivateKey.add(new ASN1(ASN1.INTEGER, PKCS8.convertUnsignedInteger(privateKey.getComponent(Key.CRT_P))));
	rsaPrivateKey.add(new ASN1(ASN1.INTEGER, PKCS8.convertUnsignedInteger(privateKey.getComponent(Key.CRT_Q))));
	rsaPrivateKey.add(new ASN1(ASN1.INTEGER, PKCS8.convertUnsignedInteger(privateKey.getComponent(Key.CRT_DP1))));
	rsaPrivateKey.add(new ASN1(ASN1.INTEGER, PKCS8.convertUnsignedInteger(privateKey.getComponent(Key.CRT_DQ1))));
	rsaPrivateKey.add(new ASN1(ASN1.INTEGER, PKCS8.convertUnsignedInteger(privateKey.getComponent(Key.CRT_PQ))));

	return rsaPrivateKey.getBytes();
}



/**
 * Encode a given GP RSA private key as specified by the PKCS#8 format
 *
 * @param {Key} the private key object that should be encoded
 * @return the encoded PKCS#8 private key
 * @type ByteString
 */
PKCS8.encodeRSAKeyUsingPKCS8Format = function(privateKey, publicKey) {
	var privateKeyInfo = new ASN1(ASN1.SEQUENCE);
	
	// Set the version number - must be zero
	privateKeyInfo.add(new ASN1(ASN1.INTEGER, new ByteString("00", HEX)));
	
	var privateKeyAlgorithm = new ASN1(ASN1.SEQUENCE);
	privateKeyAlgorithm.add(new ASN1(ASN1.OBJECT_IDENTIFIER, PKCS8.rsaEncryption));
	privateKeyAlgorithm.add(new ASN1(ASN1.NULL));
	
	// encode the key information
	privateKeyInfo.add(privateKeyAlgorithm);
	
	// encode the private key
	var encodedPrivateKey = new ASN1(ASN1.OCTET_STRING, PKCS8.encodeRSAKey(privateKey, publicKey));
	
	privateKeyInfo.add(encodedPrivateKey);
	
	print(privateKeyInfo);
	return privateKeyInfo.getBytes();	
}



/**
 * Encode a given GP private key as specified by the PKCS#8 format
 *
 * For now we only support the encoding of ECC private keys in a prime field
 *
 * @param {Key} the private key object that should be encoded
 * @return the encoded PKCS#8 private key
 * @type ByteString
 */
PKCS8.encodeKeyUsingPKCS8Format = function(privateKey, publicKey) {
	
	assert(privateKey.getType() == Key.PRIVATE);
	if (typeof(privateKey.getComponent(Key.ECC_P)) != "undefined") {
		return PKCS8.encodeECCKeyUsingPKCS8Format(privateKey);
	} else {
		return PKCS8.encodeRSAKeyUsingPKCS8Format(privateKey, publicKey);
	}
}



/**
 * Decode a given PKCS#8 ECC private key from the given ByteString and create a GP key object
 *
 * For now we only support the decoding of ECC private keys in a prime field
 * 
 * @param {ASN1} algparam the algorithm parameter from AlgorithmInfo
 * @param {ASN1} privateKey the privateKey element from the PKCS#8 structure
 * @return the GP key object
 * @type Key
 */
PKCS8.decodeECCKeyFromPKCS8Format = function(domainParameter, encodedKey) {
	
	var key = new Key();
	
	key.setType(Key.PRIVATE);
	
	key.setComponent(Key.ECC_D, encodedKey.get(1).value);
	
	// Decode the domain parameters
	var cofactor = domainParameter.get(0);
	key.setComponent(Key.ECC_H, cofactor.value);
	
	var order = domainParameter.get(1).get(1);
	key.setComponent(Key.ECC_P, PKCS8.stripLeadingZeros(order.value));
	
	var coeff_A = domainParameter.get(2).get(0);
	key.setComponent(Key.ECC_A, coeff_A.value);
	
	var coeff_B = domainParameter.get(2).get(1);
	key.setComponent(Key.ECC_B, coeff_B.value);
	
	var generatorPoint = domainParameter.get(3).value;
	
	var coordinates = PKCS8.decodeUncompressedECPoint(generatorPoint);
	
	key.setComponent(Key.ECC_GX, coordinates.x);
	key.setComponent(Key.ECC_GY, coordinates.y);
	
	var groupOrder = domainParameter.get(4);
	
	key.setComponent(Key.ECC_N, PKCS8.stripLeadingZeros(groupOrder.value));
	
	return key;	
}



/**
 * Decode a given PKCS#8 RSA private key from the given ByteString and create a GP key object
 *
 * @param {ByteString} the private key object in PKCS#8 format
 * @param {ASN1} algparam the algorithm parameter from AlgorithmInfo
 * @param {ASN1} privateKey the privateKey element from the PKCS#8 structure
 * @return the GP key object
 * @type Key
 */
PKCS8.decodeRSAKeyFromPKCS8Format = function(algparam, privateKey) {
	
	var key = new Key();
	
	key.setType(Key.PRIVATE);
	
	assert(algparam.tag == ASN1.NULL);
	assert(!algparam.isconstructed);
	assert(algparam.length == 0);
	
	assert(privateKey.tag == ASN1.SEQUENCE);
	assert(privateKey.isconstructed);
	assert(privateKey.elements >= 9);
	
	for (var i = 0; i < 9; i++) {
		var e = privateKey.get(i);
		assert(e.tag == ASN1.INTEGER);
		assert(!e.isconstructed);
	}
	
	assert(privateKey.get(0).value.toUnsigned() == 0);
	
	key.setComponent(Key.CRT_P,   PKCS8.stripLeadingZeros(privateKey.get(4).value));
	key.setComponent(Key.CRT_Q,   PKCS8.stripLeadingZeros(privateKey.get(5).value));
	key.setComponent(Key.CRT_DP1, PKCS8.stripLeadingZeros(privateKey.get(6).value));
	key.setComponent(Key.CRT_DQ1, PKCS8.stripLeadingZeros(privateKey.get(7).value));
	key.setComponent(Key.CRT_PQ,  PKCS8.stripLeadingZeros(privateKey.get(8).value));

	return key;	
}



/**
 * Decode a given PKCS#8 private key from the given ByteString and create a GP key object
 *
 * For now we only support the decoding of ECC private keys in a prime field
 * 
 * @param {ByteString} the private key object in PKCS#8 format
 * @return the GP key object
 * @type Key
 */
PKCS8.decodeKeyFromPKCS8Format = function(encodedKey) {
	var p8 = new ASN1(encodedKey);
	
	assert(p8.isconstructed);
	assert(p8.elements >= 3);
	
	var version = p8.get(0);
	assert(version.tag == ASN1.INTEGER);
	assert(version.value.toUnsigned() == 0);
	
	var pkai = p8.get(1);
	assert(pkai.tag == ASN1.SEQUENCE);
	assert(pkai.isconstructed);
	assert(pkai.elements == 2);
	var keytype = pkai.get(0);
	
	assert(keytype.tag == ASN1.OBJECT_IDENTIFIER);
	
	var algparam = pkai.get(1);
	
	var privateKey = p8.get(2);
	assert(privateKey.tag == ASN1.OCTET_STRING);
	if (privateKey.isconstructed) {
		privateKey = privateKey.get(0);
	} else {
		privateKey = new ASN1(privateKey.value);
	}
	
	if (keytype.value.equals(PKCS8.rsaEncryption)) {
		return PKCS8.decodeRSAKeyFromPKCS8Format(algparam, privateKey);
	} else if (keytype.value.equals(PKCS8.idEcPublicKey)) {
		return PKCS8.decodeECCKeyFromPKCS8Format(algparam, privateKey);
	} else {
		throw new Error("Unknown key type " + keytype.value.toString(OID));
	}
}



/**
 * Simple self-test
 */
PKCS8.test = function() {

	// Set OID for EC curve
	var ecCurve = "1.3.36.3.3.2.8.1.1.7";
    
    var crypto = new Crypto("BC");
    
    // Create empty public key object
    var pubKey = new Key();
    pubKey.setType(Key.PUBLIC);
    pubKey.setComponent(Key.ECC_CURVE_OID, new ByteString(ecCurve, OID)); 

    // Create empty private key object
    var priKey = new Key();
    priKey.setType(Key.PRIVATE);
    priKey.setComponent(Key.ECC_CURVE_OID, new ByteString(ecCurve, OID)); 
    
    // Generate key pair
    crypto.generateKeyPair(Crypto.EC, pubKey, priKey);
	       
    // Encode
    var p8Key = PKCS8.encodeKeyUsingPKCS8Format(priKey);
    
    // Decode
    var decodedKeyObject = PKCS8.decodeKeyFromPKCS8Format(p8Key);
    
    // Compare
    assert(decodedKeyObject.getComponent(Key.ECC_D).equals(priKey.getComponent(Key.ECC_D)));
    
    assert(decodedKeyObject.getComponent(Key.ECC_GX).equals(priKey.getComponent(Key.ECC_GX)));
    assert(decodedKeyObject.getComponent(Key.ECC_GY).equals(priKey.getComponent(Key.ECC_GY)));
    assert(decodedKeyObject.getComponent(Key.ECC_A).equals(pubKey.getComponent(Key.ECC_A)));
    assert(decodedKeyObject.getComponent(Key.ECC_B).equals(pubKey.getComponent(Key.ECC_B)));
     
    // Encode
    var refp8Key = PKCS8.encodeKeyUsingPKCS8Format(decodedKeyObject);
	
    // Compare
    assert(p8Key.equals(refp8Key));	
	
	
    // Create empty public key object
	var pubKey = new Key();
    pubKey.setType(Key.PUBLIC);
    pubKey.setSize(1024); 

    // Create empty private key object
    var priKey = new Key();
    priKey.setType(Key.PRIVATE);
    
    // Generate key pair
    crypto.generateKeyPair(Crypto.RSA, pubKey, priKey);
	       
    // Encode
    var p8Key = PKCS8.encodeKeyUsingPKCS8Format(priKey);
    
    // Decode
    var decodedKeyObject = PKCS8.decodeKeyFromPKCS8Format(p8Key);
    
    // Compare
    assert(decodedKeyObject.getComponent(Key.CRT_P).equals(priKey.getComponent(Key.CRT_P)));
    assert(decodedKeyObject.getComponent(Key.CRT_Q).equals(priKey.getComponent(Key.CRT_Q)));
    assert(decodedKeyObject.getComponent(Key.CRT_DP1).equals(priKey.getComponent(Key.CRT_DP1)));
    assert(decodedKeyObject.getComponent(Key.CRT_DQ1).equals(priKey.getComponent(Key.CRT_DQ1)));
    assert(decodedKeyObject.getComponent(Key.CRT_PQ).equals(priKey.getComponent(Key.CRT_PQ)));

    // Encode
    var refp8Key = PKCS8.encodeKeyUsingPKCS8Format(decodedKeyObject);
	
    // Compare
    assert(p8Key.equals(refp8Key));	
}
