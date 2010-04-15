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
 * @fileoverview Support for card verifiable certificates and certificate requests according to EAC 1.1/2.0
 */



load("tools/eccutils.js");

if (typeof(__ScriptingServer) == "undefined") {
	load("publickeyreference.js");
}



/**
 * Create a CVC object from a DER encoded ByteString.
 *
 * @class Class implementing a decoder for card verifiable certificates or requests according to 
 *        Extended Access Control (EAC) as defined in BSI TR-03110 1.11 and 2.02.
 * @constructor
 * @param {ByteString} param the DER encoded certificate
 * @return
 */
function CVC() {
	if (arguments.length > 0) {
		var arg = arguments[0];
		if (arg instanceof ASN1) {
			this.asn = arg;
			this.bin = this.asn.getBytes();
		} else if (arg instanceof ByteString) {
			this.bin = arg;
			this.asn = new ASN1(this.bin);
		} else {
			throw new GPError("CVC", GPError.INVALID_DATA, 0, "Argument must be of type ByteString or ASN1");
		}
		if (this.asn.tag == CVC.TAG_AT) {
			this.body = this.asn.get(0).get(0);
		} else if (this.asn.tag == CVC.TAG_CVC) {
			this.body = this.asn.get(0);
		} else {
			throw new GPError("CVC", GPError.INVALID_DATA, 0, "Argument is neither a CVC or CVC request");
		}
	}
}



/** Authentication Template */
CVC.TAG_AT = 0x67;
/** CV Certificate */
CVC.TAG_CVC = 0x7F21;
/** Certificate Body */
CVC.TAG_BODY = 0x7F4E;
/** Certificate Profile Identifier */
CVC.TAG_CPI = 0x5F29;
/** Certification Authority Reference */
CVC.TAG_CAR = 0x42;
/** Public Key */
CVC.TAG_PUK = 0x7F49;
/** Prime Modulus */
CVC.TAG_ECC_P = 0x81;
/** First coefficient a */
CVC.TAG_ECC_A = 0x82;
/** Second coefficient b */
CVC.TAG_ECC_B = 0x83;
/** Base Point G */
CVC.TAG_ECC_G = 0x84;
/** Order of the base point */
CVC.TAG_ECC_N = 0x85;
/** Public Point y */
CVC.TAG_ECC_Q = 0x86;
/** Cofactor f */
CVC.TAG_ECC_H = 0x87;
/** Certificate Holder Reference */
CVC.TAG_CHR = 0x5F20;
/** Certificate Holder Authorisation Template */
CVC.TAG_CHAT = 0x7F4C;
/** Certificate Extension */
CVC.TAG_EXTN = 0x65;
/** Certificate Effective Date */
CVC.TAG_CED = 0x5F25;
/** Certificate Expiration Date */
CVC.TAG_CXD = 0x5F24;
/** Signature */
CVC.TAG_SIG = 0x5F37;


/** Table of tag names */
CVC.OBJECTNAMES = []
CVC.OBJECTNAMES[CVC.TAG_AT] = "Authentication Template 67";
CVC.OBJECTNAMES[CVC.TAG_CVC] = "CV Certificate 7F21";
CVC.OBJECTNAMES[CVC.TAG_BODY] = "Certificate Body 7F4E";
CVC.OBJECTNAMES[CVC.TAG_CPI] = "Certificate Profile Indicator 5F29";
CVC.OBJECTNAMES[CVC.TAG_CAR] = "Certification Authority Reference 42";
CVC.OBJECTNAMES[CVC.TAG_PUK] = "Public Key 7F49";
CVC.OBJECTNAMES[CVC.TAG_ECC_P] = "Prime Modulus 81";
CVC.OBJECTNAMES[CVC.TAG_ECC_A] = "First coefficient a 82";
CVC.OBJECTNAMES[CVC.TAG_ECC_B] = "Second coefficient b 83";
CVC.OBJECTNAMES[CVC.TAG_ECC_G] = "Base Point G 84";
CVC.OBJECTNAMES[CVC.TAG_ECC_N] = "Order of the base point 85";
CVC.OBJECTNAMES[CVC.TAG_ECC_Q] = "Public Point y 86";
CVC.OBJECTNAMES[CVC.TAG_ECC_H] = "Cofactor f 87";
CVC.OBJECTNAMES[CVC.TAG_CHR] = "Certificate Holder Reference 5F20";
CVC.OBJECTNAMES[CVC.TAG_CHAT] = "Certificate Holder Authentication Template 7F4C";
CVC.OBJECTNAMES[CVC.TAG_EXTN] = "Extension 65";
CVC.OBJECTNAMES[CVC.TAG_CED] = "Certificate Effective Date 5F25";
CVC.OBJECTNAMES[CVC.TAG_CXD] = "Certificate Expiration Date 5F24";
CVC.OBJECTNAMES[CVC.TAG_SIG] = "Signature 5F37";


/** Table of rights description for id-IS */
CVC.ISRIGHTS = [
	"Read access to ePassport application: DG 3 (Fingerprint)",
	"Read access to ePassport application: DG 4 (Iris)",
	"RFU (Bit 3)",
	"RFU (Bit 4)",
	"RFU (Bit 5)",
	"Read access to eID application"
];
CVC.idIS = new ByteString("id-IS", OID);


/** Table of rights description for id-AT */
CVC.ATRIGHTS = [
	"Age Verification",
	"Community ID Verification",
	"Restricted Identification",
	"RFU (Bit 3)",
	"CAN allowed",
	"PIN Management",
	"Install Certificate",
	"Install Qualified Certificate",
	
	"Read Access DG 1 (Document Type)",
	"Read Access DG 2 (Issuing State)",
	"Read Access DG 3 (Date of Expiration)",
	"Read Access DG 4 (Given Name)",
	"Read Access DG 5 (Surname)",
	"Read Access DG 6 (Pseudonym)",
	"Read Access DG 7 (Academic Grade)",
	"Read Access DG 8 (Date of Birth)",

	"Read Access DG 9 (Place of Birth)",
	"Read Access DG 10",
	"Read Access DG 11",
	"Read Access DG 12",
	"Read Access DG 13",
	"Read Access DG 14",
	"Read Access DG 15",
	"Read Access DG 16",

	"Read Access DG 17 (Place of Residence)",
	"Read Access DG 18 (Community ID)",
	"Read Access DG 19",
	"Read Access DG 20",
	"Read Access DG 21",
	"RFU (Bit 29)",
	"RFU (Bit 30)",
	"RFU (Bit 31)",

	"RFU (Bit 32)",
	"Write Access DG 21",
	"Write Access DG 20",
	"Write Access DG 19",
	"Write Access DG 18 (Community ID)",
	"Write Access DG 17 (Place of Residence)"
];
CVC.idAT = new ByteString("id-AT", OID);


/** Table of rights description for id-ST */
CVC.STRIGHTS = [
	"Generate electronic signature",
	"Generate qualified electronic signature",
	"RFU (Bit 2)",
	"RFU (Bit 3)",
	"RFU (Bit 4)",
	"RFU (Bit 5)"
];
CVC.idST = new ByteString("id-ST", OID);



/** TA constants */
CVC.id_TA_ECDSA_SHA_1 = new ByteString("id-TA-ECDSA-SHA-1", OID);
CVC.id_TA_ECDSA_SHA_224 = new ByteString("id-TA-ECDSA-SHA-224", OID);
CVC.id_TA_ECDSA_SHA_256 = new ByteString("id-TA-ECDSA-SHA-256", OID);
CVC.id_TA_ECDSA_SHA_384 = new ByteString("id-TA-ECDSA-SHA-384", OID);
CVC.id_TA_ECDSA_SHA_512 = new ByteString("id-TA-ECDSA-SHA-512", OID);



/**
 * Return signature mechanism for object identifier
 *
 * @param {ByteString} oid the object identifer from the public key object
 * @returns the signature mechanism as Crypto. constant or -1 if not defined
 * @type Number
 */
CVC.getSignatureMech = function(oid) {
	if (oid.equals(CVC.id_TA_ECDSA_SHA_1))
		return Crypto.ECDSA_SHA1;
	if (oid.equals(CVC.id_TA_ECDSA_SHA_224))
		return Crypto.ECDSA_SHA224;
	if (oid.equals(CVC.id_TA_ECDSA_SHA_256))
		return Crypto.ECDSA_SHA256;
	if (oid.equals(CVC.id_TA_ECDSA_SHA_384))
		return Crypto.ECDSA_SHA384;
	if (oid.equals(CVC.id_TA_ECDSA_SHA_512))
		return Crypto.ECDSA_SHA512;
	return -1;
}



/**
 * Returns the certification authority reference (CAR).
 *
 * @return the CAR or null
 * @type PublicKeyReference
 */
CVC.prototype.getCAR = function() {
	var cardo = this.body.find(CVC.TAG_CAR);
	
	if (!cardo) {
		return null
	}
	
	return new PublicKeyReference(cardo.value);
}



/**
 * Returns the certificate holder reference (CHR).
 *
 * @return the CHR
 * @type PublicKeyReference
 */
CVC.prototype.getCHR = function() {
	var chrdo = this.body.find(CVC.TAG_CHR);
	
	if (!chrdo) {
		throw new GPError("CVC", GPError.OBJECT_NOT_FOUND, 0, "Certificate does not contain a CHR");
	}
	
	return new PublicKeyReference(chrdo.value);
}



/**
 * Returns the certificate effective date (CED).
 *
 * @return the CED or null
 * @type Date
 */
CVC.prototype.getCED = function() {
	var ceddo = this.body.find(CVC.TAG_CED);
	
	if (!ceddo) {
		return null
	}
	
	var b = ceddo.value;
	
	var d = new Date();
	d.setFullYear(b.byteAt(0) * 10 + b.byteAt(1) + 2000, 
				  b.byteAt(2) * 10 + b.byteAt(3) - 1,
				  b.byteAt(4) * 10 + b.byteAt(5));
	return d;
}



/**
 * Returns the certificate expiration date (CXD).
 *
 * @return the CXD or null
 * @type Date
 */
CVC.prototype.getCXD = function() {
	var cxddo = this.body.find(CVC.TAG_CXD);
	
	if (!cxddo) {
		return null
	}
	
	var b = cxddo.value;
	
	var d = new Date();
	d.setFullYear(b.byteAt(0) * 10 + b.byteAt(1) + 2000, 
				  b.byteAt(2) * 10 + b.byteAt(3) - 1,
				  b.byteAt(4) * 10 + b.byteAt(5));
	return d;
}



/**
 * Returns the extension identified by the object identifier.
 *
 * @return the extension including the OID or null if not defined
 * @type ASN1
 */
CVC.prototype.getExtension = function(extoid) {
	var extdo = this.body.find(CVC.TAG_EXTN);
	
	if (!extdo) {
		throw new GPError("CVC", GPError.OBJECT_NOT_FOUND, 0, "Certificate does not contain an extension");
	}

//	print(extdo);
	
	for (var i = 0; i < extdo.length; i++) {
		var ext = extdo.get(i);
		var oid = ext.get(0);
		assert(oid.tag == ASN1.OBJECT_IDENTIFIER);
		if (oid.value.equals(extoid)) {
			return ext;
		}
	}
	return null;
}



/**
 * Returns the extension identified by the object identifier.
 *
 * @return the extension including the OID or null if not defined
 * @type ASN1
 */
CVC.prototype.getCHAT = function() {
	var chat = this.body.find(CVC.TAG_CHAT);
	
	return chat;
}



/**
 * Returns the public key object identifier
 * 
 * @returns the object identifier assigned to the public key
 * @type ByteString
 */
CVC.prototype.getPublicKeyOID = function() {
	var pdo = this.body.find(CVC.TAG_PUK);
	if (pdo == null) {
		throw new GPError("CVC", GPError.OBJECT_NOT_FOUND, 0, "Certificate does not contain a public key");
	}
	
	var d = pdo.find(ASN1.OBJECT_IDENTIFIER);
	if (d == null) {
		throw new GPError("CVC", GPError.OBJECT_NOT_FOUND, 0, "Public key does not contain an object identifier");
	}
	return d.value;
}



/**
 * Returns the public key contained in the certificate.
 *
 * @param {Key} domParam optional domain parameter if they are not contained in certificate
 * @return the public key object
 * @type Key
 */
CVC.prototype.getPublicKey = function(domParam) {
	if (typeof(domParam) != "undefined") {
		var key = new Key(domParam);
	} else {
		var key = new Key();
	}
	
	key.setType(Key.PUBLIC);
	
	var pdo = this.body.find(CVC.TAG_PUK);
	if (pdo == null) {
		throw new GPError("CVC", GPError.OBJECT_NOT_FOUND, 0, "Certificate does not contain a public key");
	}
	
	var d = pdo.find(0x86);		// Public point
	if (d == null) {
		throw new GPError("CVC", GPError.OBJECT_NOT_FOUND, 0, "Certificate does not contain a public key value");
	}

	var b = d.value.bytes(1);
	key.setComponent(Key.ECC_QX, b.left(b.length >> 1));
	key.setComponent(Key.ECC_QY, b.right(b.length >> 1));

	var d = pdo.find(0x81);		// Prime modulus
	if (d != null) {
		key.setComponent(Key.ECC_P, d.value);
	}

	var d = pdo.find(0x82);		// First coefficient a
	if (d != null) {
		key.setComponent(Key.ECC_A, d.value);
	}

	var d = pdo.find(0x83);		// First coefficient b
	if (d != null) {
		key.setComponent(Key.ECC_B, d.value);
	}

	var d = pdo.find(0x84);		// Base Point G
	if (d != null) {
		var b = d.value.bytes(1);
		key.setComponent(Key.ECC_GX, b.left(b.length >> 1));
		key.setComponent(Key.ECC_GY, b.right(b.length >> 1));
	}

	var d = pdo.find(0x85);		// Order of the base point
	if (d != null) {
		key.setComponent(Key.ECC_N, d.value);
	}

	var d = pdo.find(0x87);		// Cofactor f
	if (d != null) {
		key.setComponent(Key.ECC_H, d.value);
	}
	
	return key;
}



/**
 * Determine if this is an authenticated request
 *
 * @returns true, if authenticated request
 * @type Boolean
 */
CVC.prototype.isAuthenticatedRequest = function() {
	return (this.asn.tag == CVC.TAG_AT);
}



/**
 * Verify certificate signature with public key
 *
 * @param {Key} puk the public key
 * @returns true if the signature is valid
 * @type Boolean
 */
CVC.prototype.verifyWith = function(crypto, puk) {
	if (this.asn.tag == CVC.TAG_AT) {
		var signature = this.asn.get(0).get(1);
	} else {
		var signature = this.asn.get(1);
	}
	
	var oid = this.getPublicKeyOID();
	var mech = CVC.getSignatureMech(oid);
	
	var signatureValue = ECCUtils.wrapSignature(signature.value);
	return crypto.verify(puk, mech, this.body.getBytes(), signatureValue);
}



/**
 * Verify outer signature of an authenticated request with public key
 *
 * @param {Key} puk the public key
 * @returns true if the signature is valid
 * @type Boolean
 */
CVC.prototype.verifyATWith = function(crypto, puk) {
	if (!this.isAuthenticatedRequest()) {
		throw new GPError("CVC", GPError.INVALID_DATA, 0, "Not an authenticated request");
	}
	
	var signature = this.asn.get(2);
	var signatureInput = this.asn.get(0).getBytes().concat(this.asn.get(1).getBytes());
	
	var oid = this.getPublicKeyOID();
	var mech = CVC.getSignatureMech(oid);
	
	var signatureValue = ECCUtils.wrapSignature(signature.value);
	return crypto.verify(puk, mech, signatureInput, signatureValue);
}



/**
 * Returns the encoded certificate
 *
 * @return the DER encoded certificate
 * @type ByteString
 */
CVC.prototype.getBytes = function() {
	return this.bin;
}



/**
 * Returns the certificate as ASN1 structure
 *
 * @return the certificate as ASN1 structure
 * @type ASN1
 */
CVC.prototype.getASN1 = function() {
	return this.asn;
}



/**
 * Function to recursively walk the ASN.1 tree
 */
CVC.decorateTree = function(node) {
	var name = CVC.OBJECTNAMES[node.tag];
	
	if (name) {
		node.setName(name);
	}

	if (node.isconstructed) {
		for (var i = 0; i < node.elements; i++) {
			CVC.decorateTree(node.get(i));
		}
	}
}



/**
 * Decorate the ASN.1 object with the correct name
 */
CVC.prototype.decorate = function() {
	CVC.decorateTree(this.asn);
	var cxddo = this.body.find(CVC.TAG_CXD);
	if (cxddo == null) {
		if (this.asn.tag == CVC.TAG_AT) {
			this.asn.setName("Authenticated CVC Request");
		} else {
			this.asn.setName("CVC Request");
		}
	}
}



/**
 * Return list of rights granted by the certificate
 *
 * @returns the list of rights
 * @type String[]
 */
CVC.prototype.getRightsAsList = function() {
	var list = [];
	
	var rtab;
	var chat = this.getCHAT();
	if (chat == null) {
		return list;
	}
	
	var oid = chat.get(0).value;
	
	if (oid.equals(CVC.idIS)) {
		rtab = CVC.ISRIGHTS;
	} else if (oid.equals(CVC.idAT)) {
		rtab = CVC.ATRIGHTS;
	} else if (oid.equals(CVC.idST)) {
		rtab = CVC.STRIGHTS;
	} else {
		return null;
	}
	
	var mask = chat.get(1).value;
	var c = 0;
	for (var i = mask.length - 1; i >= 0; i--) {
		var akku = mask.byteAt(i);
		for (var j = 0; j < (i == 0 ? 6 : 8); j++) {
			if (akku & 1) {
				list.push(rtab[c]);
			}
			c++;
			akku >>= 1;
		}
	}
	return list;
}



/**
 * Return a string describing the certificate type
 *
 * @returns a describing string
 * @type String
 */
CVC.prototype.getType = function() {
	var ced = this.getCED();
	var chat = this.getCHAT();
	
	// Decode certificate / request type
	var str = "CVC ";
	if (ced == null) {
		if (this.asn.tag == CVC.TAG_AT) {
			str = "AT-CVREQ ";
		} else {
			str = "CVREQ ";
		}
	}
	
	// Decode CA type
	if (chat != null) {
		var oid = chat.get(0).value;
	
		var trustedDV = "";
		var untrustedDV = "";
		
		if (oid.equals(CVC.idIS)) {
			str += "id-IS ";
			trustedDV = "(official domestic) ";
			untrustedDV = "(official foreign) ";
		} else if (oid.equals(CVC.idAT)) {
			str += "id-AT ";
			trustedDV = "(official domestic) ";
			untrustedDV = "(non-official / foreign) ";
		} else if (oid.equals(CVC.idST)) {
			str += "id-ST ";
			trustedDV = "(accreditation body) ";
			untrustedDV = "(certification service provider) ";
		} else {
			str += oid.toString(OID) + " ";
		}
		
		switch(chat.get(1).value.byteAt(0) & 0xC0) {
			case 0xC0: str += "CVCA "; break;
			case 0x80: str += "DV " + trustedDV; break;
			case 0x40: str += "DV " + untrustedDV; break;
			case 0x00: str += "Terminal "; break;
		}
	}
	
	return str;
}



/**
 * Return a textual description of the certificate
 *
 * @returns a string containing information about the certificate
 * @type String
 */
CVC.prototype.toString = function() {
	var car = this.getCAR();
	var ced = this.getCED();

	var str = this.getType();

	if (car) {
		str += "CAR=" + car.toString() + " ";
	}

	str += "CHR=" + this.getCHR().toString() + " ";
	
	if (ced) {
		str += "CED=" + ced.toLocaleDateString() + " ";
	}

	var cxd = this.getCXD();
	if (cxd) {
		str += "CXD=" + cxd.toLocaleDateString() + " ";
	}

	return str;
}

