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
 * @fileoverview Implementation of the chip authentication protocol for both card and terminal
 * as defined for EAC 2.0
 */



/**
 * Create a ChipAuthenticationInfo object
 *
 * @class <p>This class encodes and decodes ChipAuthenticationInfo objects.</p>
 * <p>The class implements the following ASN.1 syntax:</p>
 * <pre>
 *	ChipAuthenticationInfo ::= SEQUENCE {
 *		protocol OBJECT IDENTIFIER(
 *			id-CA-DH-3DES-CBC-CBC |
 *			id-CA-DH-AES-CBC-CMAC-128 |
 *			id-CA-DH-AES-CBC-CMAC-192 |
 *			id-CA-DH-AES-CBC-CMAC-256 |
 *			id-CA-ECDH-3DES-CBC-CBC |
 *			id-CA-ECDH-AES-CBC-CMAC-128 |
 *			id-CA-ECDH-AES-CBC-CMAC-192 |
 *			id-CA-ECDH-AES-CBC-CMAC-256),
 *		version INTEGER, -- MUST be 1 or 2
 *		keyId INTEGER OPTIONAL
 * }
 * </pre>
 * @constructor
 * @param {ASN1} the optional tlv structure to initialize the object
 */
function ChipAuthenticationInfo(tlv) {
	if (tlv && (tlv instanceof ASN1)) {
		assert(tlv.isconstructed);
		assert(tlv.elements >= 2);
		
		var i = 0;
		var t = tlv.get(i++);
		assert(t.tag == ASN1.OBJECT_IDENTIFIER);
		this.protocol = t.value;
		
		var t = tlv.get(i++);
		assert(t.tag == ASN1.INTEGER);
		this.version = t.value.toSigned();
		
		if (i < tlv.elements) {
			var t = tlv.get(i++);
			assert(t.tag == ASN1.INTEGER);
			this.keyId = t.value.toSigned();
		}
		
	}
}



/**
 * Convert object to TLV structure
 *
 * @return the TLV structure
 * @type ASN1
 */
ChipAuthenticationInfo.prototype.toTLV = function() {
	var t = new ASN1(ASN1.SEQUENCE);
	
	t.add(new ASN1(ASN1.OBJECT_IDENTIFIER, this.protocol));
	
	var bb = new ByteBuffer();
	bb.append(this.version);
	t.add(new ASN1(ASN1.INTEGER, bb.toByteString()));
	
	if (typeof(this.keyId) != "undefined") {
		var bb = new ByteBuffer();
		bb.append(this.parameterId);
		t.add(new ASN1(ASN1.INTEGER, bb.toByteString()));
	}
	return t;
}



ChipAuthenticationInfo.prototype.toString = function() {
	return "ChipAuthenticationInfo(protocol=" + this.protocol + ", version=" + this.version + ", keyId=" + this.keyId + ")";
}



/**
 * Create a ChipAuthenticationDomainParameterInfo object
 *
 * @class <p>This class encodes and decodes ChipAuthenticationDomainParameterInfo objects.</p>
 * <p>The class implements the following ASN.1 syntax:</p>
 * <pre>
 *	ChipAuthenticationDomainParameterInfo ::= SEQUENCE {
 *		protocol OBJECT IDENTIFIER(id-CA-DH | id-CA-ECDH),
 *		domainParameter AlgorithmIdentifier,
 *		keyId INTEGER OPTIONAL
 * }
 * </pre>
 * @constructor
 * @param {ASN1} the optional tlv structure to initialize the object
 */
function ChipAuthenticationDomainParameterInfo(tlv) {
	if (tlv && (tlv instanceof ASN1)) {
		assert(tlv.isconstructed);
		assert(tlv.elements >= 2);
		
		var i = 0;
		var t = tlv.get(i++);
		assert(t.tag == ASN1.OBJECT_IDENTIFIER);
		this.protocol = t.value;
		
		var t = tlv.get(i++);
		assert(t.tag == ASN1.SEQUENCE);

		if (t.elements > 0) {
			var oid = t.get(0);
			assert(oid.tag == ASN1.OBJECT_IDENTIFIER);
			if (oid.value.equals(new ByteString("standardizedDomainParameter", OID))) {
				this.standardizedDomainParameter = t.get(1).toUnsigned();
				var curveoid = ChipAuthentication.standardizedDomainParameter[this.standardizedDomainParameter];
				if (!curveoid) {
					throw new GPError("ChipAuthenticationPublicKeyInfo", GPError.INVALID_DATA, 0, "Standardized domain parameter " + this.standardizedDomainParameter + " is unknown");
				}
				this.domainParameter = new Key();
				this.domainParameter.setComponent(Key.ECC_CURVE_OID, new ByteString(curveoid, OID));
			} else {
				this.domainParameter = ECCUtils.decodeECParameters(t.get(1));
			}
		} else {
			this.domainParameter = new Key();
			this.domainParameter.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP256r1", OID));
		}
		
		if (i < tlv.elements) {
			var t = tlv.get(i++);
			assert(t.tag == ASN1.INTEGER);
			this.keyId = t.value.toSigned();
		}
	}
}



/**
 * Convert object to TLV structure
 *
 * @return the TLV structure
 * @type ASN1
 */
ChipAuthenticationDomainParameterInfo.prototype.toTLV = function() {
	var t = new ASN1(ASN1.SEQUENCE);
	
	t.add(new ASN1(ASN1.OBJECT_IDENTIFIER, this.protocol));
	
	t.add(new ASN1(ASN1.SEQUENCE));
	// TODO domainParameter
	
	if (typeof(this.keyId) != "undefined") {
		var bb = new ByteBuffer();
		bb.append(this.keyId);
		t.add(new ASN1(ASN1.INTEGER, bb.toByteString()));
	}
	return t;
}



ChipAuthenticationDomainParameterInfo.prototype.toString = function() {
	return "ChipAuthenticationDomainParameterInfo(protocol=" + this.protocol + ", keyId=" + this.keyId + ")";
}



/**
 * Create a ChipAuthenticationPublicKeyInfo object
 *
 * @class <p>This class encodes and decodes ChipAuthenticationPublicKeyInfo objects.</p>
 * <p>The class implements the following ASN.1 syntax:</p>
 * <pre>
 *	ChipAuthenticationPublicKeyInfo ::= SEQUENCE {
 *		protocol OBJECT IDENTIFIER(id-PK-DH | id-PK-ECDH),
 *		chipAuthenticationPublicKey SubjectPublicKeyInfo,
 *		keyId INTEGER OPTIONAL
 *	}
 *
 *	SubjectPublicKeyInfo ::= SEQUENCE {
 *		algorithm  AlgorithmIdentifier,
 *		subjectPublicKey BIT STRING
 *	}
 *
 *	AlgorithmIdentifier ::= SEQUENCE {
 *		algorithm  OBJECT IDENTIFIER,
 *		parameters ANY DEFINED BY algorithm OPTIONAL
 *	}
 * </pre>
 * @constructor
 * @param {ASN1} the optional tlv structure to initialize the object
 */
function ChipAuthenticationPublicKeyInfo(tlv) {
	if (tlv && (tlv instanceof ASN1)) {
		assert(tlv.isconstructed);
		assert(tlv.elements >= 2);

		var i = 0;
		var t = tlv.get(i++);
		assert(t.tag == ASN1.OBJECT_IDENTIFIER);		// protocol
		this.protocol = t.value;

		var t = tlv.get(i++);
		assert(t.tag == ASN1.SEQUENCE);					// Subject public key info
		assert(t.elements == 2);

		var algo = t.get(0);
		assert(algo.tag == ASN1.SEQUENCE);				// Algorithm Identifier
		assert(algo.elements == 2);

		var oid = algo.get(0);							// algorithm
		assert(oid.tag == ASN1.OBJECT_IDENTIFIER);
		this.algorithm = oid.value;

		if (oid.value.equals(new ByteString("standardizedDomainParameter", OID))) {
			this.standardizedDomainParameter = algo.get(1).toUnsigned();
			var curveoid = ChipAuthentication.standardizedDomainParameter[this.standardizedDomainParameter];
			if (!curveoid) {
				throw new GPError("ChipAuthenticationPublicKeyInfo", GPError.INVALID_DATA, 0, "Standardized domain parameter " + this.standardizedDomainParameter + " is unknown");
			}
			this.domainParameter = new Key();
			this.domainParameter.setComponent(Key.ECC_CURVE_OID, new ByteString(curveoid, OID));
		} else {
			this.domainParameter = ECCUtils.decodeECParameters(algo.get(1));
		}

		var puk = t.get(1);
		assert(puk.tag == ASN1.BIT_STRING);
		this.publicKey = puk.value.bytes(1);

		if (i < tlv.elements) {
			var t = tlv.get(i++);
			assert(t.tag == ASN1.INTEGER);
			this.keyId = t.value.toSigned();
		}
	}
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
ChipAuthenticationPublicKeyInfo.convertUnsignedInteger = function(value) {
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
 * Creates the EC Public Key as subjectPublicKeyInfo TLV structure object.
 *
 * <p>The structure is defined as:</p>
 * <pre>
 *	SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *		algorithm            AlgorithmIdentifier,
 *		subjectPublicKey     BIT STRING  }
 *
 *	AlgorithmIdentifier  ::=  SEQUENCE  {
 *		algorithm               OBJECT IDENTIFIER,
 *		parameters              ANY DEFINED BY algorithm OPTIONAL  }
 * 
 *	id-ecPublicKey OBJECT IDENTIFIER ::= {
 *		iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }
 *
 *	ECParameters ::= CHOICE {
 *		namedCurve         OBJECT IDENTIFIER,
 *		implicitCurve      NULL,
 *		specifiedCurve     SpecifiedECDomain }
 * </pre>
 * @return the subjectPublicKey TLV structure
 * @type ASN1
 */
ChipAuthenticationPublicKeyInfo.createECSubjectPublicKeyInfo = function(publicKey, encodeECDomainParameter) {
	var t = new ASN1("subjectPublicKeyInfo", ASN1.SEQUENCE);

	var algorithm = new ASN1("algorithm", ASN1.SEQUENCE,
			new ASN1("algorithm", ASN1.OBJECT_IDENTIFIER, new ByteString("1.2.840.10045.2.1", OID))
		);

	if (encodeECDomainParameter) {
		if (publicKey.getComponent(Key.ECC_P)) {		// Make sure curve components are available if only curve oid is defined
			publicKey.setComponent(Key.ECC_CURVE_OID, publicKey.getComponent(Key.ECC_CURVE_OID));
		}
		groupCAPuk.setComponent(Key.ECC_CURVE_OID, groupCAPuk.getComponent(Key.ECC_CURVE_OID));
		var ecParameter = 
			new ASN1("ecParameters", ASN1.SEQUENCE,
				new ASN1("version", ASN1.INTEGER, new ByteString("01", HEX)),
				new ASN1("fieldID", ASN1.SEQUENCE,
					new ASN1("fieldType", ASN1.OBJECT_IDENTIFIER, new ByteString("prime-field", OID)),
					new ASN1("prime", ASN1.INTEGER, 
						ChipAuthenticationPublicKeyInfo.convertUnsignedInteger(publicKey.getComponent(Key.ECC_P)))
				),
				new ASN1("curve", ASN1.SEQUENCE,
					new ASN1("a", ASN1.OCTET_STRING, 
						ChipAuthenticationPublicKeyInfo.convertUnsignedInteger(publicKey.getComponent(Key.ECC_A))),
					new ASN1("b", ASN1.OCTET_STRING, 
						ChipAuthenticationPublicKeyInfo.convertUnsignedInteger(publicKey.getComponent(Key.ECC_B)))
				),
				new ASN1("base", ASN1.OCTET_STRING,
						(new ByteString("04", HEX)).concat(publicKey.getComponent(Key.ECC_GX)).concat(publicKey.getComponent(Key.ECC_GY))),
				new ASN1("order", ASN1.INTEGER,
					ChipAuthenticationPublicKeyInfo.convertUnsignedInteger(publicKey.getComponent(Key.ECC_N)))
			);
		
		var cofactor = publicKey.getComponent(Key.ECC_H);
		var i = 0;
		for (; (i < cofactor.length) && (cofactor.byteAt(i) == 0); i++);
		if (i < cofactor.length) {
			ecParameter.add(new ASN1("cofactor", ASN1.INTEGER, cofactor.bytes(i)));
		}
		algorithm.add(ecParameter);	
	} else {
		algorithm.add(new ASN1("parameters", ASN1.OBJECT_IDENTIFIER, publicKey.getComponent(Key.ECC_CURVE_OID)));
	}
	
	t.add(algorithm);
	
	// Prefix a 00 to form correct bitstring
	// Prefix a 04 to indicate uncompressed format
	var keybin = new ByteString("0004", HEX);
	keybin = keybin.concat(publicKey.getComponent(Key.ECC_QX));
	keybin = keybin.concat(publicKey.getComponent(Key.ECC_QY));
	t.add(new ASN1("subjectPublicKey", ASN1.BIT_STRING, keybin));

	return t;
}



/**
 * Convert object to TLV structure
 *
 * @return the TLV structure
 * @type ASN1
 */
ChipAuthenticationPublicKeyInfo.prototype.toTLV = function() {
	var t = new ASN1("chipAuthenticationPublicKeyInfo", ASN1.SEQUENCE);

	t.add(new ASN1("protocol", ASN1.OBJECT_IDENTIFIER, this.protocol));

	if (this.algorithm.equals(new ByteString("id-ecPublicKey", OID))) {
		var spki = ChipAuthenticationPublicKeyInfo.createECSubjectPublicKeyInfo(this.publicKey, true);
	} else {
		var algoid = new ASN1("algorithm", ASN1.SEQUENCE, new ASN1("algorithm", ASN1.OBJECT_IDENTIFIER, this.algorithm));
		if (this.algorithm.equals(new ByteString("standardizedDomainParameter", OID))) {
			algoid.add(new ASN1("standardizedDomainParameter", ASN1.INTEGER, ByteString.valueOf(this.standardizedDomainParameter)));
		}

		var spki = new ASN1("subjectPublicKey", ASN1.SEQUENCE);
		spki.add(algoid);
		var puk = (new ByteString("0004", HEX)).concat(this.publicKey.getComponent(Key.ECC_QX)).concat(this.publicKey.getComponent(Key.ECC_QY));
		spki.add(new ASN1("publicKey", ASN1.BIT_STRING, puk));

	}

	t.add(spki);

	if (typeof(this.keyId) != "undefined") {
		var bb = new ByteBuffer();
		bb.append(this.keyId);
		t.add(new ASN1("keyId", ASN1.INTEGER, bb.toByteString()));
	}
	return t;
}



ChipAuthenticationPublicKeyInfo.prototype.toString = function() {
	return "ChipAuthenticationPublicKeyInfo(protocol=" + this.protocol + ", algorithm=" + this.algorithm + ", publicKey=" + this.publicKey + ", keyId=" + this.keyId + ")";
}



/**
 * Create a ChipAuthentication protocol object
 *
 * @class This class implements the ChipAuthentication protocol
 *
 * @constructor
 *
 * @param {ByteString} algo the algorithm OID
 * @param {Key} domparam the key object holding ECC domain parameter
 */
function ChipAuthentication(crypto, algo, domparam) {
	this.crypto = crypto;
	this.algo = algo;
	this.domparam = domparam;
	this.includeDPinAuthToken = false;
	
//	print(ECCUtils.ECParametersToString(domparam));
}


ChipAuthentication.id_CA_ECDH_3DES_CBC_CBC = (new ByteString("id-CA-ECDH-3DES-CBC-CBC", OID));

ChipAuthentication.standardizedDomainParameter = [];
ChipAuthentication.standardizedDomainParameter[8] = "secp192r1";
ChipAuthentication.standardizedDomainParameter[9] = "brainpoolP192r1";
ChipAuthentication.standardizedDomainParameter[10] = "secp224r1";
ChipAuthentication.standardizedDomainParameter[11] = "brainpoolP224r1";
ChipAuthentication.standardizedDomainParameter[12] = "secp256r1";
ChipAuthentication.standardizedDomainParameter[13] = "brainpoolP256r1";
ChipAuthentication.standardizedDomainParameter[14] = "brainpoolP320r1";
ChipAuthentication.standardizedDomainParameter[15] = "secp384r1";
ChipAuthentication.standardizedDomainParameter[16] = "brainpoolP384r1";
ChipAuthentication.standardizedDomainParameter[17] = "brainpoolP512r1";
ChipAuthentication.standardizedDomainParameter[18] = "secp521r1";


/**
 * Derive key from input parameter, counter and optional nonce
 *
 * @param {ByteString} input the first part of the hash input
 * @param {Number} counter the counter value
 * @param {nonce} the optional nonce inserted between the input and the counter
 * @return the key object
 * @type Key
 */
ChipAuthentication.prototype.deriveKey = function(input, counter, nonce) {
	if (typeof(nonce) != "undefined") {
		input = input.concat(nonce);
	}
	
	var bb = new ByteBuffer("000000", HEX);
	bb.append(counter);
	
	input = input.concat(bb.toByteString());

	var key = new Key();

	if (this.algo.equals(ChipAuthentication.id_CA_ECDH_3DES_CBC_CBC)) {
		var digest = this.crypto.digest(Crypto.SHA_1, input);
		key.setComponent(Key.DES, digest.left(16));
	} else {
		var digest = this.crypto.digest(Crypto.SHA_1, input);
		key.setComponent(Key.AES, digest.left(16));
	}
/*
	} else if (this.algo == PACE.id_PACE_ECDH_GM_AES_CBC_CMAC_128) {
		var digest = this.crypto.digest(Crypto.SHA_1, input);
		key.setComponent(Key.AES, digest.left(16));
	} else if (this.algo == PACE.id_PACE_ECDH_GM_AES_CBC_CMAC_192) {
		var digest = this.crypto.digest(Crypto.SHA_256, input);
		key.setComponent(Key.AES, digest.left(24));
	} else if (this.algo == PACE.id_PACE_ECDH_GM_AES_CBC_CMAC_256) {
		var digest = this.crypto.digest(Crypto.SHA_256, input);
		key.setComponent(Key.AES, digest);
	} else {
		throw new GPError("pace", GPError.INVALID_MECH, 0, "Algorithm not supported");
	}
*/
	return key;
}



/**
 * Generate ephemeral key pair
 */
ChipAuthentication.prototype.generateEphemeralCAKeyPair = function() {
	this.prkCA = new Key(this.domparam);
	this.prkCA.setType(Key.PRIVATE);
	
	this.pukCA = new Key(this.domparam);
	this.pukCA.setType(Key.PUBLIC);
	
	this.crypto.generateKeyPair(Crypto.EC, this.pukCA, this.prkCA);
}



/**
 * Set chip authentication keys
 *
 * @param {Key} prk the private key
 * @param {Key} puk the public key
 */
ChipAuthentication.prototype.setKeyPair = function(prk, puk) {
	this.prkCA = prk;
	this.pukCA = puk;
}



/**
 * Returns the x coordinate of the public key
 *
 * @return the encoded public key
 * @type ByteString
 */
ChipAuthentication.prototype.getCompressedPublicKey = function() {
	return (this.pukCA.getComponent(Key.ECC_QX));
}



/**
 * Returns the ephemeral public key
 *
 * @return the encoded public key
 * @type ByteString
 */
ChipAuthentication.prototype.getEphemeralPublicKey = function() {
	var ecpk = new ByteString("04", HEX);
	ecpk = ecpk.concat(this.pukCA.getComponent(Key.ECC_QX));
	ecpk = ecpk.concat(this.pukCA.getComponent(Key.ECC_QY));
	return ecpk;
}



/**
 * Decodes the ephemeral public key
 *
 * @return the decoded public key
 * @type ByteString
 */
ChipAuthentication.prototype.decodeEphemeralPublicKey = function(encodedKey) {
	if (encodedKey.byteAt(0) != 0x04) {
		throw new GPError("ChipAuthentication", GPError.INVALID_DATA, 0, "Terminal ephemeral public key does not start with '04'");
	}

	var key = new Key(this.domparam);
	var l = key.getSize() >> 3;

	if (encodedKey.length != 1 + (l << 1)) {
		throw new GPError("ChipAuthentication", GPError.INVALID_DATA, 0, "Length of terminal ephemeral public key does not match curve");
	}

	key.setType(Key.PUBLIC);
	key.setComponent(Key.ECC_QX, encodedKey.bytes(1, l));
	key.setComponent(Key.ECC_QY, encodedKey.bytes(1 + l, l));
	return key;
}



/**
 * Performs the mapping operation with mapping data from the other side
 *
 * @param {ByteString} publicKey the public key in encoded format
 */
ChipAuthentication.prototype.performKeyAgreement = function(publicKey, nonce) {
	if (publicKey.byteAt(0) != 0x04) 
		throw new GPError("ChipAuthentication", GPError.INVALID_DATA, 0, "Public key must start with '04'");

	if ((nonce != undefined) && !(nonce instanceof ByteString))
		throw new GPError("ChipAuthentication", GPError.INVALID_TYPE, 0, "nonce must be of type ByteString");

	var l = (publicKey.length - 1) >> 1;
	this.otherPuK = new Key(this.domparam);
	this.otherPuK.setComponent(Key.ECC_QX, publicKey.bytes(    1, l));
	this.otherPuK.setComponent(Key.ECC_QY, publicKey.bytes(l + 1, l));

	var k = this.crypto.decrypt(this.prkCA, Crypto.ECDH, publicKey.bytes(1));
	GPSystem.trace("Shared Secret K:");
	GPSystem.trace(k);
	this.kenc = this.deriveKey(k, 1, nonce);
	this.kmac = this.deriveKey(k, 2, nonce);
}



/**
 * Calculate and verify the authentication token over the public key received from
 * the other side
 *
 * @param {ByteString} the MAC over the authentication data
 * @return true if the MAC is valid
 * @type Boolean
 */
ChipAuthentication.prototype.verifyAuthenticationToken = function(authToken) {
	var t = ChipAuthentication.encodePublicKey(this.algo.toString(OID), this.pukCA, this.includeDPinAuthToken);
	GPSystem.trace("Authentication Token:");
	GPSystem.trace(t);

	if (this.algo.equals(ChipAuthentication.id_CA_ECDH_3DES_CBC_CBC)) {
		var at = this.crypto.sign(this.kmac, Crypto.DES_MAC_EMV, t.getBytes());
		return at.equals(authToken);
	} else {
		var at = this.crypto.sign(this.kmac, Crypto.AES_CMAC, t.getBytes());
		return at.left(8).equals(authToken);
	}
}



/**
 * Calculate the authentication token over the public key received from
 * the other side
 *
 * @param {ByteString} the MAC over the authentication data
 * @return true if the MAC is valid
 * @type Boolean
 */
ChipAuthentication.prototype.calculateAuthenticationToken = function() {
	var t = ChipAuthentication.encodePublicKey(this.algo.toString(OID), this.pukCA, this.includeDPinAuthToken);
	GPSystem.trace("Authentication Token:");
	GPSystem.trace(t);

	if (this.algo.equals(ChipAuthentication.id_CA_ECDH_3DES_CBC_CBC)) {
		var at = this.crypto.sign(this.kmac, Crypto.DES_MAC_EMV, t.getBytes());
	} else {
		var at = this.crypto.sign(this.kmac, Crypto.AES_CMAC, t.getBytes()).left(8);
	}
	return at;
}



/**
 * Strips leading zeros of a ByteString
 *
 * @param {ByteString} value the ByteString value
 * @return the stripped ByteString object, may be an empty ByteString
 * @type ByteString
 */
ChipAuthentication.stripLeadingZeros = function(value) {
	var i = 0;
	for (; (i < value.length) && (value.byteAt(i) == 0); i++);
	
	return value.right(value.length - i);
}



/**
 * Encode an ECC public key in the format defined by the EAC 2.0 specification
 *
 * @param {String} oid the object identifier to encode
 * @param {Key} key the EC public key
 * @param {Boolean} withDP true to encode domain parameter as well
 */
ChipAuthentication.encodePublicKey = function(oid, key, withDP) {

	var t = new ASN1("ecPublicKey", 0x7F49);
	t.add(new ASN1("objectIdentifier", ASN1.OBJECT_IDENTIFIER, new ByteString(oid, OID)));
	if (withDP) {
		t.add(new ASN1("primeModulus", 0x81, key.getComponent(Key.ECC_P)));
		t.add(new ASN1("firstCoefficient", 0x82, key.getComponent(Key.ECC_A)));
		t.add(new ASN1("secondCoefficient", 0x83, key.getComponent(Key.ECC_B)));

		var point = new ByteString("04", HEX);
		point = point.concat(key.getComponent(Key.ECC_GX));
		point = point.concat(key.getComponent(Key.ECC_GY));
		t.add(new ASN1("basePoint", 0x84, point));
		
		t.add(new ASN1("orderOfTheBasePoint", 0x85, key.getComponent(Key.ECC_N)));
	}
	var point = new ByteString("04", HEX);
	point = point.concat(key.getComponent(Key.ECC_QX));
	point = point.concat(key.getComponent(Key.ECC_QY));
	t.add(new ASN1("publicPoint", 0x86, point));

	if (withDP) {
		var cofactor = key.getComponent(Key.ECC_H);
		cofactor = ChipAuthentication.stripLeadingZeros(cofactor);
		
		t.add(new ASN1("cofactor", 0x87, cofactor));
	}
	
	return t;
}



