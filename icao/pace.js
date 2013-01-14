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
 * @fileoverview Implementation of the PACE/SAC protocol for both card and terminal
 */



/**
 * Create a PACEInfo object
 *
 * @class <p>This class encodes and decodes PACEInfo objects.</p>
 * <p>The class implements the following ASN.1 syntax:</p>
 * <pre>
 * PACEInfo ::= SEQUENCE {
 * 		protocol	OBJECT IDENTIFIER,
 * 		version INTEGER, -- MUST be 1 or 2
 * 		parameterId INTEGER OPTIONAL
 * }
 * </pre>
 * @constructor
 * @param {ASN1} the optional tlv structure to initialize the object
 */
function PACEInfo(tlv) {
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
			this.parameterId = t.value.toSigned();
		}
	}
}



/**
 * Convert object to TLV structure
 *
 * @return the TLV structure
 * @type ASN1
 */
PACEInfo.prototype.toTLV = function() {
	var t = new ASN1(ASN1.SEQUENCE);
	
	t.add(new ASN1(ASN1.OBJECT_IDENTIFIER, this.protocol));
	
	var bb = new ByteBuffer();
	bb.append(this.version);
	t.add(new ASN1(ASN1.INTEGER, bb.toByteString()));
	
	if (typeof(this.parameterId) != "undefined") {
		var bb = new ByteBuffer();
		bb.append(this.parameterId);
		t.add(new ASN1(ASN1.INTEGER, bb.toByteString()));
	}
	return t;
}



PACEInfo.prototype.toString = function() {
	return "PACEInfo(protocol=" + this.protocol + ", version=" + this.version + ", parameterId=" + this.protocolId + ")";
}



/**
 * Create a PACEDomainParameterInfo object
 *
 * @class <p>This class encodes and decodes PACEDomainParameterInfo objects.</p>
 * <p>The class implements the following ASN.1 syntax:</p>
 * <pre>
 *   PACEDomainParameterInfo ::= SEQUENCE {
 *   	protocol OBJECT IDENTIFIER(id-PACE-DH | id-PACE-ECDH),
 *   	domainParameter AlgorithmIdentifier,
 *   	parameterId INTEGER OPTIONAL
 *   }
 * </pre>
 * @constructor
 * @param {ASN1} the optional tlv structure to initialize the object
 */
function PACEDomainParameterInfo(tlv) {
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
			this.domainParameter = ECCUtils.decodeECParameters(t.get(1));
		} else {
			this.domainParameter = new Key();
			this.domainParameter.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP256r1", OID));
		}
		
		if (i < tlv.elements) {
			var t = tlv.get(i++);
			assert(t.tag == ASN1.INTEGER);
			this.parameterId = t.value.toSigned();
		}
		
	}
}



/**
 * Convert object to TLV structure
 *
 * @return the TLV structure
 * @type ASN1
 */
PACEDomainParameterInfo.prototype.toTLV = function() {
	var t = new ASN1(ASN1.SEQUENCE);
	
	t.add(new ASN1(ASN1.OBJECT_IDENTIFIER, this.protocol));
	
	t.add(new ASN1(ASN1.SEQUENCE));
	// TODO domainParameter
	
	if (typeof(this.parameterId) != "undefined") {
		var bb = new ByteBuffer();
		bb.append(this.parameterId);
		t.add(new ASN1(ASN1.INTEGER, bb.toByteString()));
	}
	return t;
}



PACEDomainParameterInfo.getStandardizedDomainParameter = function(id) {
	var key = new Key();
	key.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP256r1", OID));
	return key;
}



PACEDomainParameterInfo.prototype.toString = function() {
	return "PACEDomainParameterInfo(protocol=" + this.protocol + ", parameterId=" + this.protocolId + ")";
}



/**
 * Create a PACE protocol object
 *
 * @class This class implements the PACE protocol
 *
 * @constructor
 *
 * @param {Crypto} crypto the crypto provider
 * @param {ByteString} algo the algorithm OID
 * @param {Key} domainparam the key object holding ECC domain parameter
 * @param {Number} version protocol version (1 or 2)
 */
function PACE(crypto, algo, domparam, version) {
	this.crypto = crypto;
	this.algo = algo.toString(OID);
	this.domparam = domparam;

	if (typeof(version) != "undefined") {
		this.version = version;
	} else {
		this.version = 1;
	}

	if (this.algo == PACE.id_PACE_ECDH_GM_3DES_CBC_CBC) {
		this.symalgo = Key.DES;
	} else {
		this.symalgo = Key.AES;
	}

	this.sym = Crypto.AES;
}



/**
 * Return algorithm type
 *
 * @type Number
 * @returns Either Key.DES or Key.AES
 */
PACE.prototype.getSymmetricAlgorithm = function() {
	return this.symalgo;
}



/**
 * Derive key from input parameter, counter and optional nonce
 *
 * @param {ByteString} input the first part of the hash input
 * @param {Number} counter the counter value
 * @param {nonce} the optional nonce inserted between the input and the counter
 * @return the key object
 * @type Key
 */
PACE.prototype.deriveKey = function(input, counter, nonce) {
	if (typeof(nonce) != "undefined") {
		input = input.concat(nonce);
	}
	
	var bb = new ByteBuffer("000000", HEX);
	bb.append(counter);
	
	input = input.concat(bb.toByteString());

	var key = new Key();
	
	if (this.algo == PACE.id_PACE_ECDH_GM_3DES_CBC_CBC) {
		var digest = this.crypto.digest(Crypto.SHA_1, input);
		key.setComponent(Key.DES, digest.left(16));
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
	return key;
}



/**
 * Set the password and derive the PACE key.
 * @param {ByteString} pwd the PACE password (Hash Value for MRZ and ASCII string for others)
 * @return the PACE key.
 */
PACE.prototype.setPassword = function(pwd) {
	this.pacekey = this.deriveKey(pwd, 3);
}



/**
 * Generate nonce and encrypt using PACE key.
 * @return the encrypted nonce
 * @type ByteString
 */
PACE.prototype.getEncryptedNonce = function() {
	this.nonce = this.crypto.generateRandom(16);
	if (this.symalgo == Key.DES) {
		var encnonce = this.crypto.encrypt(this.pacekey, Crypto.DES_CBC, this.nonce);
	} else {
		var encnonce = this.crypto.encrypt(this.pacekey, Crypto.AES_ECB, this.nonce);
	}
	return encnonce;
}



/**
 * Decrypt and store nonce using PACE key.
 * 
 * @param {ByteString} nonce the encrypted nonce
 */
PACE.prototype.decryptNonce = function(encnonce) {
	if (this.symalgo == Key.DES) {
		this.nonce = this.crypto.decrypt(this.pacekey, Crypto.DES_CBC, encnonce);
	} else {
		this.nonce = this.crypto.decrypt(this.pacekey, Crypto.AES_ECB, encnonce);
	}
}



/**
 * Returns true, if the nonce is known.
 * @return true if the nonce is known
 * @type Boolean
 */
PACE.prototype.hasNonce = function() {
	return (typeof(this.nonce) != "undefined");
}



/**
 * Generate ephemeral ECC key pair.
 *
 * @param domainParameter the domain parameter for the key pair
 * @return the ephemeral public key
 * @type Key
 */
PACE.prototype.generateEphemeralKeyPair = function(domainParameter) {
	this.prk = new Key(domainParameter);
	this.prk.setType(Key.PRIVATE);
	
	this.puk = new Key(domainParameter);
	this.puk.setType(Key.PUBLIC);
	
	this.crypto.generateKeyPair(Crypto.EC, this.puk, this.prk);
	
	return this.puk;
}



/**
 * Generates and returns the mapping data for this instance
 * @return the mapping data
 * @type ByteString
 */
PACE.prototype.getMappingData = function() {
	if (typeof(this.prk) == "undefined") {
		this.generateEphemeralKeyPair(this.domparam);
	}
	
	var ecpk = new ByteString("04", HEX);
	ecpk = ecpk.concat(this.puk.getComponent(Key.ECC_QX));
	ecpk = ecpk.concat(this.puk.getComponent(Key.ECC_QY));
	return ecpk;
}



/**
 * Performs the mapping operation with mapping data from the other side
 *
 */
PACE.prototype.performMapping = function(mappingData) {
	if (mappingData.byteAt(0) != 0x04) 
		throw new GPError("PACE", GPError.INVALID_DATA, 0, "Public key must start with '04'");

	if (typeof(this.nonce) == "undefined")
		throw new GPError("PACE", GPError.INVALID_MECH, 0, "Nonce is not yet defined");

	var h = this.crypto.decrypt(this.prk, Crypto.ECDHP, mappingData.bytes(1));
	
	var l = h.length >> 1;
	var H = new Key(this.domparam);
	H.setComponent(Key.ECC_QX, h.bytes(0, l));
	H.setComponent(Key.ECC_QY, h.bytes(l, l));
	
	var G = new Key(this.domparam);
	// Copy generator point into public key point
	G.setComponent(Key.ECC_QX, G.getComponent(Key.ECC_GX));
	G.setComponent(Key.ECC_QY, G.getComponent(Key.ECC_GY));

	// Calculate G' = s * G + P, where P is initially stored in H and
	// G' is finally stored in H.
	this.crypto.deriveKey(G, Crypto.EC_MULTIPLY_ADD, this.nonce, H);
	
	// Create new domain parameter with G'
	this.ephDomParam = new Key(this.domparam);
	this.ephDomParam.setComponent(Key.ECC_GX, H.getComponent(Key.ECC_QX));
	this.ephDomParam.setComponent(Key.ECC_GY, H.getComponent(Key.ECC_QY));
}



/**
 * Returns the ephemeral public key based on the new domain parameter
 *
 * @return the encoded public key
 * @type ByteString
 */
PACE.prototype.getEphemeralPublicKey = function() {
	this.generateEphemeralKeyPair(this.ephDomParam);
	var ecpk = new ByteString("04", HEX);
	ecpk = ecpk.concat(this.puk.getComponent(Key.ECC_QX));
	ecpk = ecpk.concat(this.puk.getComponent(Key.ECC_QY));
	return ecpk;
}



/**
 * Performs the mapping operation with mapping data from the other side
 *
 * @param {ByteString} publicKey the public key in encoded format
 */
PACE.prototype.performKeyAgreement = function(publicKey) {
	if (publicKey.byteAt(0) != 0x04) 
		throw new GPError("PACE", GPError.INVALID_DATA, 0, "Public key must start with '04'");

	if (typeof(this.nonce) == "undefined")
		throw new GPError("PACE", GPError.INVALID_MECH, 0, "Nonce is not yet defined");

	var l = (publicKey.length - 1) >> 1;
	this.otherPuK = new Key(this.ephDomParam);
	this.otherPuK.setComponent(Key.ECC_QX, publicKey.bytes(    1, l));
	this.otherPuK.setComponent(Key.ECC_QY, publicKey.bytes(l + 1, l));

	var k = this.crypto.decrypt(this.prk, Crypto.ECDH, publicKey.bytes(1));
	GPSystem.trace("Shared Secret K:");
	GPSystem.trace(k);
	this.kenc = this.deriveKey(k, 1);
	this.kmac = this.deriveKey(k, 2);
	
}



/**
 * Strips leading zeros of a ByteString
 *
 * @param {ByteString} value the ByteString value
 * @return the stripped ByteString object, may be an empty ByteString
 * @type ByteString
 */
PACE.stripLeadingZeros = function(value) {
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
 * @type ASN1
 * @returns the ASN1 encoded public key object
 */
PACE.encodePublicKey = function(oid, key, withDP) {

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
		cofactor = PACE.stripLeadingZeros(cofactor);
		
		t.add(new ASN1("cofactor", 0x87, cofactor));
	}
	
	return t;
}



/**
 * Calculate the authentication token over the public key received from
 * the other side
 *
 * @return the MAC over the authentication data
 * @type ByteString
 */
PACE.prototype.calculateAuthenticationToken = function() {
	var t = PACE.encodePublicKey(this.algo, this.otherPuK, (this.version == 1));
	GPSystem.trace("Authentication Token:");
	GPSystem.trace(t);

	if (this.symalgo == Key.DES) {
		var inp = t.getBytes().pad(Crypto.ISO9797_METHOD_2);
		var at = this.crypto.sign(this.kmac, Crypto.DES_MAC_EMV, inp);
	} else {
		var at = this.crypto.sign(this.kmac, Crypto.AES_CMAC, t.getBytes()).left(8);
	}

	return at;
}



/**
 * Calculate and verify the authentication token over the public key received from
 * the other side
 *
 * @param {ByteString} the MAC over the authentication data
 * @return true if the MAC is valid
 * @type Boolean
 */
PACE.prototype.verifyAuthenticationToken = function(authToken) {
	var t = PACE.encodePublicKey(this.algo, this.puk, (this.version == 1));
	GPSystem.trace("Authentication Token:");
	GPSystem.trace(t);

	if (this.symalgo == Key.DES) {
		var inp = t.getBytes().pad(Crypto.ISO9797_METHOD_2);
		var at = this.crypto.sign(this.kmac, Crypto.DES_MAC_EMV, inp);
	} else {
		var at = this.crypto.sign(this.kmac, Crypto.AES_CMAC, t.getBytes()).left(8);
	}

	return at.equals(authToken);
}



/**
 * Returns true, if the mapping has been performed.
 * @return true if the mapping has been performed
 * @type Boolean
 */
PACE.prototype.hasMapping = function() {
	return (typeof(this.ephDomParam) != "undefined");
}



/**
 * Describe key
 * @param {Key} the key
 * @return the string describing the key
 * @type String
 */
PACE.keyToString = function(key) {
	var str = "";
	var kval = key.getComponent(Key.AES);
	if (kval) {
		str += "(AES) " + kval + "\n";
	}
	var kval = key.getComponent(Key.DES);
	if (kval) {
		str += "(DES) " + kval + "\n";
	}
	return str;
}



/**
 * Returns a human readable presentation of the current pace state.
 * return {String} the object information
 */
PACE.prototype.toString = function() {
	var str = "Algorithm " + this.algo + "\n";
	
	if (typeof(this.pacekey) != "undefined") {
		str += "PACE Key " + PACE.keyToString(this.pacekey);
	}
	
	if (typeof(this.nonce) != "undefined") {
		str += "Nonce " + this.nonce + "\n";
	}
	
	if (typeof(this.ephDomParam) != "undefined") {
		str += "Point G' " + this.ephDomParam.getComponent(Key.ECC_GX) + " " + this.ephDomParam.getComponent(Key.ECC_GY) + "\n";
	}

	if (typeof(this.kenc) != "undefined") {
		str += "Kenc " + PACE.keyToString(this.kenc);
	}
	
	if (typeof(this.kmac) != "undefined") {
		str += "Kmac" + PACE.keyToString(this.kmac);
	}

	return str;
}


PACE.bsi_de = "0.4.0.127.0.7";
PACE.id_PACE = PACE.bsi_de + ".2.2.4";
PACE.id_PACE_ECDH_GM = PACE.id_PACE + ".2";
PACE.id_PACE_ECDH_GM_3DES_CBC_CBC     = PACE.id_PACE_ECDH_GM + ".1";
PACE.id_PACE_ECDH_GM_AES_CBC_CMAC_128 = PACE.id_PACE_ECDH_GM + ".2";
PACE.id_PACE_ECDH_GM_AES_CBC_CMAC_192 = PACE.id_PACE_ECDH_GM + ".3";
PACE.id_PACE_ECDH_GM_AES_CBC_CMAC_256 = PACE.id_PACE_ECDH_GM + ".4";

PACE.id_roles = PACE.bsi_de + ".3.1.2";
PACE.id_IS = PACE.id_roles + ".1";

