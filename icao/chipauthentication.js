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
				this.domainParameter = new Key();
				// ToDo: Match ID to table entry
				this.domainParameter.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP256r1", OID));
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
	this.algo = algo.toString(OID);
	this.domparam = domparam;
	
//	print(ECCUtils.ECParametersToString(domparam));
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
ChipAuthentication.prototype.deriveKey = function(input, counter, nonce) {
	if (typeof(nonce) != "undefined") {
		input = input.concat(nonce);
	}
	
	var bb = new ByteBuffer("000000", HEX);
	bb.append(counter);
	
	input = input.concat(bb.toByteString());

	var key = new Key();

	var digest = this.crypto.digest(Crypto.SHA_1, input);
	key.setComponent(Key.AES, digest.left(16));
	
/*	
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
*/
	return key;
}



ChipAuthentication.prototype.generateEphemeralCAKeyPair = function() {
	this.prkCA = new Key(this.domparam);
	this.prkCA.setType(Key.PRIVATE);
	
	this.pukCA = new Key(this.domparam);
	this.pukCA.setType(Key.PUBLIC);
	
	this.crypto.generateKeyPair(Crypto.EC, this.pukCA, this.prkCA);
}



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
 * Performs the mapping operation with mapping data from the other side
 *
 * @param {ByteString} publicKey the public key in encoded format
 */
ChipAuthentication.prototype.performKeyAgreement = function(publicKey, nonce) {
	if (publicKey.byteAt(0) != 0x04) 
		throw new GPError("ChipAuthentication", GPError.INVALID_DATA, 0, "Public key must start with '04'");

	if (!(nonce instanceof ByteString))
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
	var t = PACE.encodePublicKey(this.algo, this.pukCA, true);
	GPSystem.trace("Authentication Token:");
	GPSystem.trace(t);
	
	var at = this.crypto.sign(this.kmac, Crypto.AES_CMAC, t.getBytes());
	
	return at.left(8).equals(authToken);
}

