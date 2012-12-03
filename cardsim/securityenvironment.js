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
 * @fileoverview Security environment - a container for security related data elements
 */



/**
 * Creates a security environment container that collects cryptographic reference templates (CRT)
 * 
 * @class Class implementing a security environment for cryptographic operations.
 * @constructor
 */
function SecurityEnvironment() {
	this.t = { AT:null, KAT: null, HT: null, CCT:null, DST:null, CT: null };
}



/**
 * Adds CRT elements to a named template.
 *
 * @param {String} tname the CRT name one of AT, KAT, HT, CCT, DST or CT
 * @param {ASN1} tlv the tlv object containing the CRT elements
 **/
SecurityEnvironment.prototype.addElements = function(tname, tlv) {
	var t = this.t[tname];
	if (t) {
		for (var i = 0; i < tlv.elements; i++) {
			var o = tlv.get(i);
			SecurityEnvironment.decorateCRT(o);
			var j = 0;
			while(j < t.elements) {
				if (t.get(j).tag == o.tag) {
					t.remove(j);
				} else {
					j++;
				}
			}
			t.add(o);
		}
	} else {
		for (var i = 0; i < tlv.elements; i++) {
			var o = tlv.get(i);
			SecurityEnvironment.decorateCRT(o);
		}
		this.t[tname] = tlv;
	}
}



/**
 * Adds a CRT identified by it's tag
 *
 * @param {ASN1} tlv the tlv object
 */
SecurityEnvironment.prototype.add = function(tlv) {
	switch(tlv.tag) {
	case 0xA4:
		tlv.setName("AT");
		break;
	case 0xA6:
		tlv.setName("KAT");
		break;
	case 0xAA:
		tlv.setName("HT");
		break;
	case 0xB4:
		tlv.setName("CCT");
		break;
	case 0xB6:
		tlv.setName("DST");
		break;
	case 0xB8:
		tlv.setName("CT");
		break;
	default:
		throw new GPError("SecurityEnvironment", GPError.INVALID_DATA, tlv.tag, "Invalid tag for CRT");
	}
	this.addElements(tlv.name, tlv);
}



/**
 * Return textual representation of security environment container
 */
SecurityEnvironment.prototype.toString = function() {
	var str = "";
	
	if (this.t.AT) {
		str += "Authentication Template (AT)\n" + this.t.AT;
	}
	if (this.t.KAT) {
		str += "Key Agreement Template (KAT)\n" + this.t.KAT;
	}
	if (this.t.HT) {
		str += "Hash Template (HT)\n" + this.t.HT;
	}
	if (this.t.CCT) {
		str += "Cryptographic Checksum Template (CCT)\n" + this.t.CCT;
	}
	if (this.t.DST) {
		str += "Digital Signature Template (DST)\n" + this.t.DST;
	}
	if (this.t.CT) {
		str += "Confidentiality Template (CT)\n" + this.t.CT;
	}
	return str;	
}	



/**
 * Decorates a tlv object from the CRT
 */
SecurityEnvironment.decorateCRT = function(asn1) {
	switch(asn1.tag) {
	case 0x80:
		asn1.setName("cryptographicMechanism 80");
		break;
	case 0x81:
		asn1.setName("fileIdentifierOrPath 81");
		break;
	case 0x82:
		asn1.setName("dFName 82");
		break;
	case 0x83:
		asn1.setName("secretOrPublicKeyReference 83");
		break;
	case 0x84:
		asn1.setName("sessionOrPrivateKeyReference 84");
		break;
	case 0x85:
		asn1.setName("nullBlock 85");
		break;
	case 0x86:
		asn1.setName("chainingBlock 86");
		break;
	case 0x87:
		asn1.setName("initialBlock 87");
		break;
	case 0x88:
		asn1.setName("previousChallenge 88");
		break;
	case 0x89:
		asn1.setName("proprietaryDataElementIndex 89");
		break;
	case 0x8A:
		asn1.setName("proprietaryDataElementIndex 8A");
		break;
	case 0x8B:
		asn1.setName("proprietaryDataElementIndex 8B");
		break;
	case 0x8C:
		asn1.setName("proprietaryDataElementIndex 8C");
		break;
	case 0x8D:
		asn1.setName("proprietaryDataElementIndex 8D");
		break;
	case 0x90:
		asn1.setName("cardHashCode 90");
		break;
	case 0x91:
		asn1.setName("ephemeralPublicKey 91");
		break;
	case 0x92:
		asn1.setName("cardTimeStamp 92");
		break;
	case 0x93:
		asn1.setName("dsiCounter 93");
		break;
	case 0x94:
		asn1.setName("challengeOrDerivationParameter 94");
		break;
	case 0x95:
		asn1.setName("usageQualifier 95");
		break;
	case 0x8E:
		asn1.setName("cryptographicContentReference 8E");
		break;
	case 0x67:
		asn1.setName("auxiliaryAuthenticatedData 67");
		break;
	case 0x67:
		asn1.setName("auxiliaryAuthenticatedData 67");
		break;
	case 0x7F4C:
		asn1.setName("certificateHolderAuthorisationTemplate 7F4C");
		break;
	}
}
