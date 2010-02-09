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
 * @fileoverview Support for card verifiable certificates according to EAC 2.0
 */



load("publickeyreference.js");




/**
 * Create a CVC object from a DER encoded ByteString.
 *
 * @class Class implementing a decoder for card verifiable certificates or requests according to 
 *        Extended Access Control (EAC) as defined in BSI TR-03110 1.11 and 2.02.
 * @constructor
 * @param {ByteString} the DER encoded certificate
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
/** Certificate Profile Identifier */
CVC.TAG_CPI = 0x5F29;
/** Certification Authority Reference */
CVC.TAG_CAR = 0x42;
/** Public Key */
CVC.TAG_PUK = 0x7F49;
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
 * Returns the public key contained in the certificate.
 *
 * @param {Key} domParam domain parameter if they are not contained in certificate
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
	
	var signatureValue = ECCUtils.wrapSignature(signature.value);
	return crypto.verify(puk, Crypto.ECDSA_SHA256, this.body.getBytes(), signatureValue);
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
	
	var signatureValue = ECCUtils.wrapSignature(signature.value);
	return crypto.verify(puk, Crypto.ECDSA_SHA256, signatureInput, signatureValue);
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
 * Return a textual description of the certificate
 */
CVC.prototype.toString = function() {
	var car = this.getCAR();
	var ced = this.getCED();
	
	var str = "CVC ";
	if (ced == null) {
		if (this.asn.tag == CVC.TAG_AT) {
			str = "AT-CVREQ ";
		} else {
			str = "CVREQ ";
		}
	}
	
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

