/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2010 CardContact Software & System Consulting
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
 * @fileoverview Implementation of Simple CV request generator based on 
 * TR-03110 "Advanced Security Mechanisms for Machine Readable Travel Documents", Version 2.0
 *
 */

load("tools/eccutils.js");

if (typeof(__ScriptingServer) == "undefined") {
	load("cvc.js");
}


/**
 * Constructor for request generator
 *
 * @class Class implementing a generator for CVC requests
 * 
 * @constructor
 * @param {Crypto} Crypto object to use
 */
function EAC2CVRequestGenerator(crypto) {
	this.crypto = crypto;
}



/*
 * Convert x/y coordinates to uncompressed format
 *
 * x/y - coordinates of EC point
 * 
 * return ByteString containing compressed format
 *
 * TODO: Move to ECUtils
 */ 
EAC2CVRequestGenerator.encodeUncompressedECPoint = function(x, y) {
    
    bb = new ByteBuffer();
    
    // uncompressed encoding
    bb.append(new ByteString("04", HEX));
    bb.append(new ByteString(x, HEX));
    bb.append(new ByteString(y, HEX));
    
    return bb.toByteString();
}
 


/**
 * Strips leading zeros of a ByteString
 *
 * @param {ByteString} value the ByteString value
 * @return the stripped ByteString object, may be an empty ByteString
 * @type ByteString
 *
 * TODO: Move to Utils
 */
EAC2CVRequestGenerator.stripLeadingZeros = function(value) {
	var i = 0;
	for (; (i < value.length) && (value.byteAt(i) == 0); i++);
	
	return value.right(value.length - i);
}



/**
 * Set the public key that should be encoded within the request
 *
 * @param {Key} publicKey Public Key
 */
EAC2CVRequestGenerator.prototype.setPublicKey = function(publicKey) {
	this.publicKey = publicKey;
}



/**
 * Set the certficate holder reference (CHR) for the request
 *
 * @param {String} chr CHR for the request
 */
EAC2CVRequestGenerator.prototype.setCHR = function(chr) {
	if (chr instanceof ByteString) {
		this.CHR = chr;
	} else if (chr instanceof PublicKeyReference) {
		this.CHR = chr.getBytes();
	} else {
		this.CHR = new ByteString(chr.toString(), ASCII);
	}
}



/**
 * Reset the current generator object
 *
 * TODO: Implement me
 */
EAC2CVRequestGenerator.prototype.reset = function() {
}



/**
 * Set the certificate profile identifier (CPI) for the request
 *
 * @param {Number} profileID CPI for the request
 */
EAC2CVRequestGenerator.prototype.setProfileIdentifier = function(profileID) {
	this.profileIdentifier = profileID;
}



/**
 * Set the certficate authorization reference (CAR) for the request
 *
 * The usage of this method is optional - if no CAR is set, there will be no
 * "inner" CAR included within the certficate request
 *
 * @param {String} car CAR for the request
 */
EAC2CVRequestGenerator.prototype.setCAR = function(car) {
	if (car instanceof ByteString) {
		this.CAR = car;
	} else if (car instanceof PublicKeyReference) {
		this.CAR = car.getBytes();
	} else {
		this.CAR = new ByteString(car.toString(), ASCII);
	}
}



/**
 * Set the extension values that should be included within the request
 *
 * @param {ByteString[]} extensions Array of DER-encoded extensions
 */
EAC2CVRequestGenerator.prototype.setExtensions = function(extensions) {
	this.extensions = extensions;
}



/**
 * Set the object identifier that should be included in the public key domain parameters
 *
 * @param {ByteString} oid Object identifier as specified in appendix A.6.4
 */
EAC2CVRequestGenerator.prototype.setTAAlgorithmIdentifier = function(oid) {
	this.taOID = oid;
}



/**
 * Get the CAR as ByteString object
 *
 * @private
 */
EAC2CVRequestGenerator.prototype.getCAR = function() {
	var t = new ASN1("Certification Authority Reference", 0x42, this.CAR);
	return t;
}



/**
 * Get the CHR as ByteString object
 *
 * @private
 */
EAC2CVRequestGenerator.prototype.getCHR = function() {
	var t = new ASN1("Certification Holder Reference", 0x5F20, this.CHR);
	return t;
}



/**
 * Get the encoded public key including domain parameters
 *
 * @private
 */
EAC2CVRequestGenerator.prototype.getPublicKey = function() {

	var t = new ASN1("Public Key", 0x7F49);
	t.add(new ASN1("Object Identifier", 0x06, this.taOID));

	if (typeof(this.publicKey.getComponent(Key.ECC_P)) != "undefined") {
		t.add(new ASN1("Prime Modulus", 0x81, this.publicKey.getComponent(Key.ECC_P)));
		t.add(new ASN1("First coefficient a", 0x82, this.publicKey.getComponent(Key.ECC_A)));
		t.add(new ASN1("Second coefficient b", 0x83, this.publicKey.getComponent(Key.ECC_B)));
		t.add(new ASN1("Base Point G", 0x84, EAC2CVRequestGenerator.encodeUncompressedECPoint(this.publicKey.getComponent(Key.ECC_GX), this.publicKey.getComponent(Key.ECC_GY))));
		t.add(new ASN1("Order of the base point", 0x85, this.publicKey.getComponent(Key.ECC_N)));

		t.add(new ASN1("Public Point y", 0x86, EAC2CVRequestGenerator.encodeUncompressedECPoint(this.publicKey.getComponent(Key.ECC_QX), this.publicKey.getComponent(Key.ECC_QY))));

		t.add(new ASN1("Cofactor f", 0x87, EAC2CVRequestGenerator.stripLeadingZeros(this.publicKey.getComponent(Key.ECC_H))));
	} else {
		t.add(new ASN1("Composite Modulus", 0x81, this.publicKey.getComponent(Key.MODULUS)));
		t.add(new ASN1("Public Exponent", 0x82, this.publicKey.getComponent(Key.EXPONENT)));
	}

	return t;
}



/**
 * Get the encoded CPI as ByteString
 *
 * @private
 */
EAC2CVRequestGenerator.prototype.getProfileIdentifier = function() {
	var bb = new ByteBuffer();
	bb.append(this.profileIdentifier);
	
	var t = new ASN1("Certificate Profile Identifier", 0x5F29, bb.toByteString());
	return t;
}



/**
 * Get the DER-encoded extension vector
 *
 * @private
 */
EAC2CVRequestGenerator.prototype.getExtensions = function() {
	var t = new ASN1("Certificate Extensions", 0x7F49);
	for (var i = 0; i < this.extensions.length; i++)
		t.add(this.extensions[i]);
	return t;
}



/**
 * Get the encoded certificate request body
 *
 * @private
 */
EAC2CVRequestGenerator.prototype.getCertificateBody = function() {
	
	var t = new ASN1("Certificate Body", 0x7F4E);
	t.add(this.getProfileIdentifier());
	
	if (this.CAR) {
		t.add(this.getCAR());
	}

	t.add(this.getPublicKey());
	t.add(this.getCHR());

	if (this.extensions) {
		t.add(this.getExtensions());
	}
	return t;
}



/**
 * Generate initial certificate request using the specified private key for signing
 *
 * @param {Key} privateKey Private key for signature creation
 * @return The DER-encoded CV request
 * @type ASN1
 */
EAC2CVRequestGenerator.prototype.generateCVRequest = function(privateKey) {
	var request = new ASN1("CV Certificate", 0x7F21);
	
	var body = this.getCertificateBody();

	request.add(body);

	var mech = CVC.getSignatureMech(this.taOID);
	var signature = this.crypto.sign(privateKey, mech, body.getBytes());
	if (CVC.isECDSA(this.taOID)) {
		var keylen = privateKey.getComponent(Key.ECC_P).length;
		var signatureValue = new ASN1("Signature", 0x5F37, ECCUtils.unwrapSignature(signature, keylen));
	} else {
		var signatureValue = new ASN1("Signature", 0x5F37, signature);
	}
	
	request.add(signatureValue);
	
	return request;
}



/**
 * Generate authenticated request
 *
 * @param {Key} requestKey Private key for the request signature
 * @param {Key} authenticationKey Private key for used for signing and authenticating the request
 * @param {PublicKeyReference} authCHR CHR of the authenticating authority 
 * @param {ByteString} taOID the public key object identifier of the authentication key
 *
 * @return The DER-encoded authenticated CV request
 * @type ASN1
 */
EAC2CVRequestGenerator.prototype.generateAuthenticatedCVRequest = function(requestKey, authenticationKey, authCHR, taOID) {
	var authRequest = new ASN1("Authentication", 0x67);

	var request = this.generateCVRequest(requestKey);

	var chr = new ASN1("Certification Authority Reference", 0x42, authCHR.getBytes());

	var signatureInput = request.getBytes().concat(chr.getBytes());

	if (typeof(taOID) == "undefined") {
		taOID = this.taOID;
	}
	var mech = CVC.getSignatureMech(taOID);
	var signature = this.crypto.sign(authenticationKey, mech, signatureInput);

	if (CVC.isECDSA(this.taOID)) {
		var keylen = authenticationKey.getComponent(Key.ECC_P).length;
		var signatureValue = new ASN1("Signature", 0x5F37, ECCUtils.unwrapSignature(signature, keylen));
	} else {
		var signatureValue = new ASN1("Signature", 0x5F37, signature);
	}

	authRequest.add(request);
	authRequest.add(chr);
	authRequest.add(signatureValue);

	return authRequest;
}
