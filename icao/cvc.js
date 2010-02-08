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
 * @class Class implementing a decoder for card verifiable certificates according to 
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
			if (this.bin.bytes(0, 2).toString(HEX) != "7F21") {
				throw new GPError("CVC", GPError.INVALID_DATA, 0, "Data does not seem to be CV certificate");
			}
			this.asn = new ASN1(this.bin);
		} else {
			throw new GPError("CVC", GPError.INVALID_DATA, 0, "Argument must be of type ByteString or ASN1");
		}
	}
}



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
 * @return the CAR
 * @type PublicKeyReference
 */
CVC.prototype.getCAR = function() {
	var cardo = this.asn.get(0).find(CVC.TAG_CAR);
	
	if (!cardo) {
		throw new GPError("CVC", GPError.OBJECT_NOT_FOUND, 0, "Certificate does not contain a CAR");
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
	var chrdo = this.asn.get(0).find(CVC.TAG_CHR);
	
	if (!chrdo) {
		throw new GPError("CVC", GPError.OBJECT_NOT_FOUND, 0, "Certificate does not contain a CHR");
	}
	
	return new PublicKeyReference(chrdo.value);
}



/**
 * Returns the extension identified by the object identifier.
 *
 * @return the extension including the OID or null if not defined
 * @type ASN1
 */
CVC.prototype.getExtension = function(extoid) {
	var extdo = this.asn.get(0).find(CVC.TAG_EXTN);
	
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
	var str = "CVC CAR=" + this.getCAR().toString() + " CHR=" + this.getCHR().toString();
	return str;
}

