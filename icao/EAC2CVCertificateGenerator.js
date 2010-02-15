/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2006 CardContact Software & System Consulting
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
 * @fileoverview EAC2CVCertificateGenerator - Simple CV certificate generator class
 * based on "Advanced Security Mechanisms for Machine Readable Travel Documents", Version 2.0
 *
 *
 * TODO: For now we only support ECC crypto
 *
 */

load("tools/eccutils.js");
load("cvc.js");


/**
 * Define a generator object for CV certificates
 * 
 * @class Class implementing a generator for CV certificates according to EAC 1.1 and EAC 2.0 specifications.
 * 
 * @constructor
 * @param {Crypto} crypto the crypto provider to be used
 */
function EAC2CVCertificateGenerator(crypto) {
	this.crypto = crypto;
}



/**
 * Convert x/y coordinates to uncompressed format
 *
 * @param {ByteString} x the x-coordinate of the point
 * @param {ByteString} y the y-coordinate of the point
 * @return the point in uncompressed format
 * @type ByteString
 */
EAC2CVCertificateGenerator.encodeUncompressedECPoint = function(x,y) {

	bb = new ByteBuffer();

	// uncompressed encoding
	bb.append(new ByteString("04", HEX));
	bb.append(new ByteString(x, HEX));
	bb.append(new ByteString(y, HEX));

	return bb.toByteString();
}



/**
 * Decode x/y coordinates from uncompressed format
 *
 * @param {ByteString} uncompressedPoint the uncompressed point
 * @return the x-/y-coordinate of the point
 * @type ByteString
 */

EAC2CVCertificateGenerator.decodeUncompressedECPoint = function(uncompressedPoint) {
	
	// Determine the size of the coordinates ignoring the indicator byte '04'
	var length = uncompressedPoint.length - 1;

	var sizeOfCoordinate = length / 2;

	var xValue = uncompressedPoint.bytes(1, sizeOfCoordinate);
	var yValue = uncompressedPoint.bytes(1 + sizeOfCoordinate, sizeOfCoordinate);

	return { x:xValue, y:yValue };
} 



/**
 * Convert integer to fixed length string with leading zeros.
 *
 * @private
 * @param {Number} value the value to convert to a string.
 * @param {Number} digits the number of digits in output string. Must be <= 20.
 * @return the 0-padded string
 * @type String
 */
EAC2CVCertificateGenerator.itos = function(value, digits) {
	if (digits > 20) {
		throw new Error("Digits must be <= 20");
	}
	var str = "" + value;
	str = "0000000000000000000".substr(19 - (digits - str.length)).concat(str);
	return str;
}



/**
 * Convert date to string with format YYMMDD.
 *
 * @param {Date} d the date object.
 * @return the date/time string.
 * @type String
 */
EAC2CVCertificateGenerator.dtos = function(d) {
	var s = EAC2CVCertificateGenerator.itos(d.getFullYear() % 100, 2) +
			EAC2CVCertificateGenerator.itos(d.getMonth() + 1, 2) +
			EAC2CVCertificateGenerator.itos(d.getDate(), 2);
	return s;
}



/**
 * Set the profile identifier
 *
 * @param {Number} profileID the profile identifier
 */
EAC2CVCertificateGenerator.prototype.setProfileIdentifier = function(profileID) {
	this.profileIdentifier = profileID;
}



/**
 * Set the certification authority reference
 *
 * @param {String} CAR the CAR value
 * @param {ByteString} CAR the CAR value
 * @param {PublicKeyReference} CAR the CAR value
 */
EAC2CVCertificateGenerator.prototype.setCAR = function(CAR) {
	if (CAR instanceof ByteString) {
		this.CAR = CAR;
	} else if (CAR instanceof PublicKeyReference) {
		this.CAR = CAR.getBytes();
	} else {
		this.CAR = new ByteString(CAR.toString(), ASCII);
	}
}



/**
 * Set the certificate holder reference
 *
 * @param {String} CHR the CHR value
 * @param {ByteString} CHR the CHR value
 * @param {PublicKeyReference} CHR the CHR value
 */
EAC2CVCertificateGenerator.prototype.setCHR = function(CHR) {
	if (CHR instanceof ByteString) {
		this.CHR = CHR;
	} else if (CHR instanceof PublicKeyReference) {
		this.CHR = CHR.getBytes();
	} else {
		this.CHR = new ByteString(CHR.toString(), ASCII);
	}
}



/**
 * Set the effective date
 *
 * @param {String} effectiveDate the effective date in the format YYMMDD
 * @param {Date} effectiveDate the effective date as Date object
 */
EAC2CVCertificateGenerator.prototype.setEffectiveDate = function(effectiveDate) {
	if (effectiveDate instanceof Date) {
		this.effectiveDate = EAC2CVCertificateGenerator.dtos(effectiveDate);
	} else {
		this.effectiveDate = effectiveDate;
	}
}



/**
 * Set the expiry date
 *
 * @param {String} expiryDate the expiry date in the format YYMMDD
 * @param {Date} expiryDate the expiry date as Date object
 */
EAC2CVCertificateGenerator.prototype.setExpiryDate = function(expiryDate) {
	if (expiryDate instanceof Date) {
		this.expiryDate = EAC2CVCertificateGenerator.dtos(expiryDate);
	} else {
		this.expiryDate = expiryDate;
	}
}



/**
 * Set the object identifier of the authorization template for the generated certificate
 *
 * @param {ByteString} oid the object identifier for the chat
 */
EAC2CVCertificateGenerator.prototype.setChatOID = function(oid) {
	this.chatOID = oid;
}



/**
 * Set the authorization level of the authorization template for the generated certificate
 *
 * @param {ByteString} authLevel the encoded authorization level
 */
EAC2CVCertificateGenerator.prototype.setChatAuthorizationLevel = function(authLevel) {
	this.chatAuthorizationLevel = authLevel;
}



/**
 * Set the algorithm identifier for terminal authentication
 *
 * @param {ByteString} oid the object identifier as specified in appendix A.6.4
 */
EAC2CVCertificateGenerator.prototype.setTAAlgorithmIdentifier = function(oid) {
	this.taOID = oid;
}



/**
 * Set some additional extensions 
 *
 * @param {Array of ASN.1 objects} extensions array containing the ASN.1 encoded extensions for the certificate
 */
EAC2CVCertificateGenerator.prototype.setExtensions = function(extensions) {
	this.extensions = extensions;
}



/**
 * Set the public key to be included in the certificate
 *
 * @param {Key} publicKey the public key object to be certified
 */
EAC2CVCertificateGenerator.prototype.setPublicKey = function(publicKey) {
	this.publicKey = publicKey;
}



/**
 * Set whether to include domain parameters in the certificate or not
 *
 * @param {Boolean} value the flag indicator
 */
EAC2CVCertificateGenerator.prototype.setIncludeDomainParameters = function(value) {
	this.includeDomainParameters = value;
}



/**
 * Internal functions for the generation of a certificate
 * @private
 */
EAC2CVCertificateGenerator.prototype.getCAR = function() {
	var t = new ASN1("Certification Authority Reference", 0x42, this.CAR);
	return t;
}



/**
 * Internal functions for the generation of a certificate
 * @private
 */
EAC2CVCertificateGenerator.prototype.getCHR = function() {
	var t = new ASN1("Certification Holder Reference", 0x5F20, this.CHR);
	return t;
}



/**
 * Internal functions for the generation of a certificate
 * @private
 */
EAC2CVCertificateGenerator.convertDate = function(date) {

	var temp = new ByteString(date, ASCII);
	var bb = new ByteBuffer();
	var singleByte;
	
	for (var i = 0; i < temp.length; i++) {
		bb.append(temp.byteAt(i) - 0x30);
	}
	
	return bb.toByteString();
}



/**
 * Internal functions for the generation of a certificate
 * @private
 */
EAC2CVCertificateGenerator.prototype.getEffectiveDate = function() {
	var t = new ASN1("Certificate Effective Date", 0x5F25, 
			EAC2CVCertificateGenerator.convertDate(this.effectiveDate));
	return t;
}



/**
 * Internal functions for the generation of a certificate
 * @private
 */
EAC2CVCertificateGenerator.prototype.getExpiryDate = function() {
	var t = new ASN1("Certificate Expiration Date", 0x5F24, 
			EAC2CVCertificateGenerator.convertDate(this.expiryDate));
	return t;
}



/**
 * Internal functions for the generation of a certificate
 * @private
 */
EAC2CVCertificateGenerator.prototype.getCHAT = function() {
	var t = new ASN1("Certificate Holder Authorization Template", 0x7F4C);

	var oid = new ASN1("Object Identifier", ASN1.OBJECT_IDENTIFIER, this.chatOID);
	var authLevel = new ASN1("Authorization Level", 0x53, this.chatAuthorizationLevel);

	t.add(oid);
	t.add(authLevel);

	return t;
}



/**
 * Strips leading zeros of a ByteString
 *
 * @param {ByteString} value the ByteString value
 * @return the stripped ByteString object, may be an empty ByteString
 * @type ByteString
 */
EAC2CVCertificateGenerator.prototype.stripLeadingZeros = function(value) {
	var i = 0;
	for (; (i < value.length) && (value.byteAt(i) == 0); i++);
	
	return value.right(value.length - i);
}



/**
 * Internal functions for the generation of a certificate
 * @private
 */
EAC2CVCertificateGenerator.prototype.getPublicKey = function() {

	var t = new ASN1("Public Key", 0x7F49);
	
	t.add(new ASN1("Object Identifier", 0x06, this.taOID));

	if (this.includeDomainParameters == true) {

		t.add(new ASN1("Prime Modulus", 0x81, this.publicKey.getComponent(Key.ECC_P)));
		t.add(new ASN1("First coefficient a", 0x82, this.publicKey.getComponent(Key.ECC_A)));
		t.add(new ASN1("Second coefficient b", 0x83, this.publicKey.getComponent(Key.ECC_B)));

		t.add(new ASN1("Base Point G", 0x84, EAC2CVCertificateGenerator.encodeUncompressedECPoint(this.publicKey.getComponent(Key.ECC_GX), this.publicKey.getComponent(Key.ECC_GY))));

		t.add(new ASN1("Order of the base point", 0x85, this.publicKey.getComponent(Key.ECC_N)));
	}

	t.add(new ASN1("Public Point y", 0x86, EAC2CVCertificateGenerator.encodeUncompressedECPoint(this.publicKey.getComponent(Key.ECC_QX), this.publicKey.getComponent(Key.ECC_QY))));

	if (this.includeDomainParameters == true) {
		t.add(new ASN1("Cofactor f", 0x87, this.stripLeadingZeros(this.publicKey.getComponent(Key.ECC_H))));
	}

	return t;
}



/**
 * Internal functions for the generation of a certificate
 * @private
 */
EAC2CVCertificateGenerator.prototype.getProfileIdentifier = function() {

	var bb = new ByteBuffer();
	bb.append(this.profileIdentifier);
	
	var t = new ASN1("Certificate Profile Identifier", 0x5F29, bb.toByteString());
	return t;
}



/**
 * Internal functions for the generation of a certificate
 * @private
 */
EAC2CVCertificateGenerator.prototype.getExtensions = function() {
	var t = new ASN1("Certificate Extensions", 0x65);
	for (var i = 0; i < this.extensions.length; i++)
		t.add(this.extensions[i]);
	return t;
}



/**
 * Internal functions for the generation of a certificate
 * @private
 */
EAC2CVCertificateGenerator.prototype.getCertificateBody = function() {
	
	var t = new ASN1("Certificate Body", 0x7F4E);

	t.add(this.getProfileIdentifier());

	t.add(this.getCAR());

	t.add(this.getPublicKey());

	t.add(this.getCHR());

	t.add(this.getCHAT());

	t.add(this.getEffectiveDate());

	t.add(this.getExpiryDate());

	if (this.extensions) {
		t.add(this.getExtensions());
	}
	
	return t;
}



/**
 * Generate a certificate based on the parameter set using the setter methods.
 *
 * @param {Key} signingKey the key to be used for signing the certificate
 * @param {Number} mech the mechanims to be used for signing the certificate (Crypto.ECDSA*)
 * @return the CVC certificate
 * @type CVC
 */
EAC2CVCertificateGenerator.prototype.generateCVCertificate = function(signingKey) {
	
	var certificate = new ASN1("CV Certificate", 0x7F21);
	
	var body = this.getCertificateBody();
	
	var keylen = signingKey.getComponent(Key.ECC_P).length;
	
	var signature = this.crypto.sign(signingKey, Crypto.ECDSA_SHA256, body.getBytes());
	var signatureValue = new ASN1("Signature", 0x5F37, ECCUtils.unwrapSignature(signature, keylen));
	
	certificate.add(body);

	certificate.add(signatureValue);
	
	return new CVC(certificate);
}