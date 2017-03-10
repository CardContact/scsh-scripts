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
 *  @fileoverview
 *  Classes to parse PKCS#15 data structures
 */



/**
 * Return the BIT STRING as integer value
 *
 * @param {ByteString} the ASN.1 BIT STRING to convert
 * @return the converted integer
 * @type Number
 */
function IntFromBitString(b) {
	assert(b.length < 5);
	var bits = b.bytes(1).toUnsigned();
	return bits << ((4 - b.length) << 3);
}

/*
print("0080 - ", IntFromBitString(new ByteString("0080", HEX)).toString(16));
print("0180 - ", IntFromBitString(new ByteString("0180", HEX)).toString(16));
print("0780 - ", IntFromBitString(new ByteString("0780", HEX)).toString(16));
print("078000 - ", IntFromBitString(new ByteString("078000", HEX)).toString(16));
print("07800000 - ", IntFromBitString(new ByteString("07800000", HEX)).toString(16));
*/



/**
 * Creates a PKCS#15 path from the encoded TLV structure
 *
 * @class <p>This class provides for access to PKCS#15 structures.</p>
 * <p>The class decodes the following ASN.1 syntax:</p>
 * <pre>
 * Path ::= SEQUENCE {
 * 		efidOrPath OCTET STRING,
 *		index INTEGER (0..cia-ub-index) OPTIONAL,
 *		length [0] INTEGER (0..cia-ub-index) OPTIONAL
 *	}( WITH COMPONENTS {..., index PRESENT, length PRESENT}|
 * 	   WITH COMPONENTS {..., index ABSENT, length ABSENT})
 * </pre>
 * @constructor
 * @param {ASN1} the tlv structure containing the path
 */
function PKCS15_Path(tlv) {
	assert(tlv.elements > 0);

	var t = tlv.get(0);
	assert(t.tag == ASN1.OCTET_STRING);

	t.setName("efidOrPath");
	this.efidOrPath = "";

	for (var i = 0; i < t.length; i += 2) {
		if (t.length - i >= 2) {
			this.efidOrPath += ":" + t.value.bytes(i, 2).toString(HEX);
		} else {
			this.efidOrPath += ":" + ByteString.valueOf(t.value.byteAt(i)).toString(HEX);
		}
	}

	if (tlv.elements == 3) {
		t = tlv.get(1);
		assert(t.tag == ASN1.INTEGER);
		assert(t.length > 0);
		t.setName("index");
		this.index = t.value.toSigned();

		t = tlv.get(2);
		assert(t.tag == 0x80);
		assert(t.length > 0);
		t.setName("length");
		this.length = t.value.toSigned();
	}
}



/**
 * Gets the absolute in the OCF format.
 *
 * @param {String} df the current directory
 * @return the path in OCF encoding
 * @type String
 */
PKCS15_Path.prototype.getAbsolutePath = function(df) {
	if (this.aid) {
		return this.aid + this.efidOrPath;
	}

	var p = this.efidOrPath;
	if (p.slice(0, 5) != ":3F00") {
		p = df + p;
	}

	return p;
}



/**
 * Convert the object to a human readable string
 *
 * @return the string representation of the object
 * @type String
 */
PKCS15_Path.prototype.toString = function() {
	var str = "{";

	if (this.efidOrPath) {
		str += "efidOrPath=" + this.efidOrPath;
	}

	if (this.index) {
		str += ",index=" + this.index;
	}

	if (this.length) {
		str += ",length=" + this.length;
	}
	str += "}";
	return str;
}



/**
 * Creates a CIO DDO object from data usually stored in EF_DIR.
 *
 * @class <p>Class to decode CIO DDO objects.</p>
 * <p>The class decodes the following ASN.1 syntax:</p>
 * <pre>
 * CIODDO ::= SEQUENCE {
 * 		providerId OBJECT IDENTIFIER OPTIONAL,
 * 		odfPath Path OPTIONAL,
 *		ciaInfoPath [0] Path OPTIONAL,
 *		aid [APPLICATION 15] OCTET STRING (SIZE(1..16)),
 *		(CONSTRAINED BY {-- Must be an AID in accordance with ISO/IEC 7816-4--})
 *		OPTIONAL,
 *		... -- For future extensions
 * } -- Context tag 1 is historical and shall not be used
 * </pre>
 * @constructor
 * @param {ASN1} the tlv structure containing the CIO DDO
 */
function PKCS15_CIODDO(tlv) {
	assert(tlv.tag == 0x73);

	var i = 0;

	if (i < tlv.elements) {
		var t = tlv.get(i);
		if (t.tag == ASN1.OBJECT_IDENTIFIER) {
			this.providerId = t.toString();
			i++;
		}
	}

	if (i < tlv.elements) {
		var t = tlv.get(i);
		if (t.tag == ASN1.SEQUENCE) {
			this.odfPath = new PKCS15_Path(t);
			i++;
		}
	}

	if (i < tlv.elements) {
		var t = tlv.get(i);
		if (t.tag == 0xA0) {
			this.ciaInfoPath = new PKCS15_Path(t);
			i++;
		}
	}
}



/**
 * Convert the object to a human readable string
 *
 * @return the string representation of the object
 * @type String
 */
PKCS15_CIODDO.prototype.toString = function() {
	var str = "{";

	if (this.providerId) {
		str += "providerId=" + this.providerId + ",\n";
	}

	if (this.odfPath) {
		str += "odfPath=" + this.odfPath + ",\n";
	}

	if (this.ciaInfoPath) {
		str += "ciaInfoPath=" + this.ciaInfoPath + ",\n";
	}
	str += "}";
	return str;
}



/**
 * Creates a structure to access an application template from EF_DIR.
 *
 * @class <p>This class provides for access to an application template.</p>
 * @constructor
 * @constructor
 * @param {ASN1} the tlv structure containing the CIO DDO
 */
function PKCS15_ApplicationTemplate(tlv) {
	assert(tlv.tag == 0x61);
	assert(tlv.elements > 0);

	for (var i = 0; i < tlv.elements; i++) {
		var t = tlv.get(i);
		switch(t.tag) {
			case 0x4F:
				this.aid = t.value.toString(HEX);
				break;
			case 0x50:
				this.label = t.value.toString(UTF8);
				break;
			case 0x51:
				this.path = ":" + t.value.toString(HEX);
				break;
			case 0x73:
				this.ddo = new PKCS15_CIODDO(t);
				break;
		}
	}
}

/**
 * The application identifier for this application.
 * @type String
 */
PKCS15_ApplicationTemplate.prototype.aid = "";

/**
 * The application label for this application.
 * @type String
 */
PKCS15_ApplicationTemplate.prototype.label = "";

/**
 * The path for this application.
 * @type String
 */
PKCS15_ApplicationTemplate.prototype.path = "";

/**
 * The PKCS#15 Directory Data Object (DDO) for this application.
 * @type PKCS15_CIODDO
 */
PKCS15_ApplicationTemplate.prototype.ddo = "";

/**
 * The list of Cryptographic Information Objects (CIO).
 * @see PKCS15.readObjectListForApplication
 * @type PKCS15_CIO[]
 */
PKCS15_ApplicationTemplate.prototype.objlist = null;



/**
 * Convert the object to a human readable string
 */
PKCS15_ApplicationTemplate.prototype.toString = function() {
	var str = "{";

	if (this.aid) {
		str += "aid=" + this.aid + ",\n";
	}

	if (this.label) {
		str += "label=" + this.label + ",\n";
	}

	if (this.path) {
		str += "path=" + this.path + ",\n";
	}

	if (this.ddo) {
		str += "ddo=" + this.ddo + ",\n";
	}
	str += "}";
	return str;
}



/**
 * Creates a CIAInfo object.
 *
 * @class <p>Class to decode CIAInfo objects.</p>
 * <p>The class decodes the following ASN.1 syntax:</p>
 * <pre>
 * CIAInfo ::= SEQUENCE {
 *		version INTEGER {v1(0),v2(1)} (v1|v2,...),
 *		serialNumber OCTET STRING OPTIONAL,
 *		manufacturerID Label OPTIONAL,
 *		label [0] Label OPTIONAL,
 *		cardflags CardFlags,
 *		seInfo SEQUENCE OF SecurityEnvironmentInfo OPTIONAL,
 *		recordInfo [1] RecordInfo OPTIONAL,
 *		supportedAlgorithms [2] SEQUENCE OF AlgorithmInfo OPTIONAL,
 *		issuerId [3] Label OPTIONAL,
 *		holderId [4] Label OPTIONAL,
 *		lastUpdate [5] LastUpdate OPTIONAL,
 *		preferredLanguage PrintableString OPTIONAL, -- In accordance with IETF RFC 1766
 *		profileIndication [6] SEQUENCE OF ProfileIndication OPTIONAL,
 *		...
 *		} (CONSTRAINED BY { -- Each AlgorithmInfo.reference value shall be unique --})
 * </pre>
 * @constructor
 * @param {ASN1} the tlv structure containing the CIAInfo
 */
function PKCS15_CIAInfo(tlv) {
	assert(tlv.tag == ASN1.SEQUENCE);
	assert(tlv.elements > 2);

	this.tlv = tlv;
	var i = 0;
	var t;

	tlv.setName("CIAInfo");

	// version
	t = tlv.get(i);
	assert(t.tag == ASN1.INTEGER);
	t.setName("version");
	this.version = t.value.toSigned();
	i++;

	// serialNumber
	if ((i < tlv.elements) && ((t = tlv.get(i)).tag == ASN1.OCTET_STRING)) {
		t.setName("serialNumber");
		this.serialNumber = t.value;
		i++;
	}

	// manufacturerID
	if ((i < tlv.elements) && ((t = tlv.get(i)).tag == ASN1.UTF8String)) {
		t.setName("manufacturerID");
		this.manufacturerID = t.value.toString(UTF8);
		i++;
	}

	// label
	if ((i < tlv.elements) && ((t = tlv.get(i)).tag == 0x80)) {
		t.setName("label");
		this.label = t.value.toString(UTF8);
		i++;
	}

	t = tlv.get(i);
	assert(t.tag == ASN1.BIT_STRING);
	if (t.length > 1) {
		this.cardflags = t.value.bytes(1,1).toUnsigned();
		t.setName("cardflags {" + this.getCardflagsAsString() + " }");
	} else {
		this.cardflags = 0;
	}
	i++;

	// seInfo SEQUENCE OF SecurityEnvironmentInfo OPTIONAL,
	if ((i < tlv.elements) && ((t = tlv.get(i)).tag == ASN1.SEQUENCE)) {
		t.setName("seInfo");
		print("CIAInfo.seInfo not further decoded : " + t);
		this.seInfo = "### not implemented ###";
		i++;
	}

	// recordInfo [1] RecordInfo OPTIONAL,
	if ((i < tlv.elements) && ((t = tlv.get(i)).tag == 0xA1)) {
		t.setName("recordInfo");
		print("CIAInfo.recordInfo not further decoded : " + t);
		this.recordInfo = "### not implemented ###";
		i++;
	}

	// supportedAlgorithms [2] SEQUENCE OF AlgorithmInfo OPTIONAL,
	if ((i < tlv.elements) && ((t = tlv.get(i)).tag == 0xA2)) {
		t.setName("supportedAlgorithms");
		this.supportedAlgorithms = new Array();
		for (var j = 0; j < t.elements; j++) {
			var alg = new AlgorithmInfo(t.get(j));
			this.supportedAlgorithms.push(alg);
		}
		i++;
	}

	// issuerId [3] Label OPTIONAL,
	if ((i < tlv.elements) && ((t = tlv.get(i)).tag == 0xA3)) {
		t.setName("issuerId");
		print("CIAInfo.issuerId not further decoded : " + t);
		this.issuerId = "### not implemented ###";
		i++;
	}

	// holderId [4] Label OPTIONAL,
	if ((i < tlv.elements) && ((t = tlv.get(i)).tag == 0xA4)) {
		t.setName("holderId");
		print("CIAInfo.holderId not further decoded : " + t);
		this.holderId = "### not implemented ###";
		i++;
	}

	// lastUpdate [5] LastUpdate OPTIONAL,
	if ((i < tlv.elements) && ((t = tlv.get(i)).tag == 0xA5)) {
		t.setName("lastUpdate");
		print("CIAInfo.lastUpdate not further decoded : " + t);
		this.lastUpdate = "### not implemented ###";
		i++;
	}

	// preferredLanguage PrintableString OPTIONAL, -- In accordance with IETF RFC 1766
	if ((i < tlv.elements) && ((t = tlv.get(i)).tag == ASN1.PrintableString)) {
		t.setName("preferredLanguage");
		this.preferredLanguage = t.value.toString(ASCII);
		i++;
	}

	// profileIndication [6] SEQUENCE OF ProfileIndication OPTIONAL,
	if ((i < tlv.elements) && ((t = tlv.get(i)).tag == 0xA6)) {
		t.setName("profileIndicator");
		print("CIAInfo.profileIndicator not further decoded : " + t);
		this.profileIndication = "### not implemented ###";
		i++;
	}
}



/**
 * Gets the card flags as string of concatenated flags.
 * @return the string containing the flags separated by a blank
 * @type String
 */
PKCS15_CIAInfo.prototype.getCardflagsAsString = function() {
	return (this.cardflags & 0x80 ? " readonly" : "") +
	       (this.cardflags & 0x40 ? " authRequired" : "") +
	       (this.cardflags & 0x20 ? " prnGeneration" : "");
}



/**
 * Convert the object to a human readable string
 *
 * @return the string representation of the object
 * @type String
 */
PKCS15_CIAInfo.prototype.toString = function() {
	var str = "CIAInfo { ";

	str += "version=" + this.version + ",\n";

	if (typeof(this.serialNumber) != "undefined") {
		str += "serialNumber=" + this.serialNumber + ",\n";
	}

	if (typeof(this.manufacturerID) != "undefined") {
		str += "manufacturerID=" + this.manufacturerID + ",\n";
	}

	if (typeof(this.label) != "undefined") {
		str += "label=" + this.label + ",\n";
	}

	str += "cardflags=" + this.getCardflagsAsString() + ",\n";

	if (typeof(this.supportedAlgorithms) != "undefined") {
		str += "supportedAlgorithms={\n";
		for (var i = 0; i < this.supportedAlgorithms.length; i++) {
			str += this.supportedAlgorithms[i].toString() + "\n";
		}
		str += "},\n";
	}

	if (typeof(this.preferredLanguage) != "undefined") {
		str += "preferredLanguage=" + this.preferredLanguage + ",\n";
	}

	str += "}";
	return str;
}



/**
 * Create an AlgorithmInfo object from TLV data
 *
 * <p>The class decodes the following ASN.1 syntax:</p>
 * <pre>
 * AlgorithmInfo ::= SEQUENCE {
 *   reference Reference,
 *   algorithm CIO-ALGORITHM.&id({AlgorithmSet}),
 *   parameters CIO-ALGORITHM.&Parameters({AlgorithmSet}{@algorithm}),
 *   supportedOperations CIO-ALGORITHM.&Operations({AlgorithmSet}{@algorithm}),
 *   objId CIO-ALGORITHM.&objectIdentifier ({AlgorithmSet}{@algorithm}),
 *   algRef Reference OPTIONAL
 * }
 *
 * CIO-ALGORITHM ::= CLASS {
 *   &id INTEGER UNIQUE,
 *   &Parameters,
 *   &Operations Operations,
 *   &objectIdentifier OBJECT IDENTIFIER OPTIONAL
 *   } WITH SYNTAX {
 *   PARAMETERS &Parameters OPERATIONS &Operations ID &id [OID &objectIdentifier]
 * }
 * </pre>
 * @constructor
 * @param {ASN1} the tlv structure containing the AlgorithmInfo
 */
function AlgorithmInfo(tlv) {
	if (tlv && (tlv instanceof ASN1)) {
		assert(tlv.isconstructed);
		assert(tlv.elements >= 5);

		this.tlv = tlv;

		var i = 0;
		var t;

		assert((t = tlv.get(i)).tag == ASN1.INTEGER);
		t.setName("reference");
		this.reference = t.value.toSigned();
		i++;

		assert((t = tlv.get(i)).tag == ASN1.INTEGER);
		t.setName("algorithm");
		this.algorithm = t.value.toSigned();
		i++;

		t = tlv.get(i);
		t.setName("parameters");
		this.parameters = t;
		i++;

		assert((t = tlv.get(i)).tag == ASN1.BIT_STRING);
		this.supportedOperations = t.value.bytes(1,1).toUnsigned();
		t.setName("supportedOperations {" + this.getOperationsAsString() + " }");
		i++;

		if (i < tlv.elements) {
			assert((t = tlv.get(i)).tag == ASN1.OBJECT_IDENTIFIER);
			t.setName("objId");
			this.objId = t.value.toString(OID);
			i++;
		}

		if (i < tlv.elements) {
			assert((t = tlv.get(i)).tag == ASN1.INTEGER);
			t.setName("algRef");
			this.algRef = t.value.toSigned();
			i++;
		}
	}
}



/**
 * Gets the operations flags as string of concatenated tokens.
 * @return the string containing the flags separated by a blank
 * @type String
 */
AlgorithmInfo.prototype.getOperationsAsString = function() {
	return (this.supportedOperations & 0x80 ? " compute-checksum" : "") +
           (this.supportedOperations & 0x40 ? " compute-signature" : "") +
           (this.supportedOperations & 0x20 ? " verify-checksum" : "") +
           (this.supportedOperations & 0x10 ? " verify-signature" : "") +
           (this.supportedOperations & 0x08 ? " encipher" : "") +
           (this.supportedOperations & 0x04 ? " decipher" : "") +
           (this.supportedOperations & 0x02 ? " hash" : "") +
           (this.supportedOperations & 0x01 ? " generate-key" : "");

}



/**
 * Convert the object to a human readable string
 *
 * @return the string representation of the object
 * @type String
 */
AlgorithmInfo.prototype.toString = function() {
	var str = "AlgorithmInfo { ";

	if (typeof(this.reference) != "undefined") {
		str += "reference=" + this.reference + ",\n";
	}

	if (typeof(this.algorithm) != "undefined") {
		str += "algorithm=0x" + this.algorithm.toString(16) + ",\n";
	}

	if (typeof(this.parameters) != "undefined") {
		str += "parameters=" + this.parameters + ",\n";
	}

	if (typeof(this.supportedOperations) != "undefined") {
		str += "supportedOperations=" + this.getOperationsAsString() + ",\n";
	}

	if (typeof(this.objId) != "undefined") {
		str += "objId=" + this.objId + ",\n";
	}

	if (typeof(this.algRef) != "undefined") {
		str += "algRef=" + this.algRef + ",\n";
	}

	str += "}";

	return str;
}



/**
 * Create a Cryptographic Information Object (CIO)
 *
 * @class <p>This is the base class for all cryptographic objects in a PKCS#15 data structure.</p>
 * <p>The class decodes the following ASN.1 syntax:</p>
 * <pre>
 * CommonObjectAttributes ::= SEQUENCE {
 *		label Label OPTIONAL,
 *		flags CommonObjectFlags OPTIONAL,
 *		authId Identifier OPTIONAL,
 *		userConsent INTEGER (1..cia-ub-userConsent) OPTIONAL,
 *		accessControlRules SEQUENCE SIZE (1..MAX) OF AccessControlRule OPTIONAL,
 *		...
 *	} (CONSTRAINED BY {-- authId should be present if flags.private is set.
 *	-- It shall equal an authID in one authentication object in the AOD -- })
 * </pre>
 * @constructor
 * @param {ASN1} the tlv structure containing the CIO
 */
function PKCS15_CIO(tlv) {
	if (tlv && (tlv instanceof ASN1)) {
		assert(tlv.isconstructed);
		assert(tlv.elements >= 3);

		this.tlv = tlv;

		var coa = tlv.get(0);
		assert(coa.tag == ASN1.SEQUENCE);

		coa.setName("commonObjectAttributes");
		var i = 0;
		var t;

		if ((i < coa.elements) && ((t = coa.get(i)).tag == ASN1.UTF8String)) {
			t.setName("label");
			this.label = t.value.toString(UTF8);
			i++;
		}

		// D-Trust card has empty bitstring element
		if ((i < coa.elements) && ((t = coa.get(i)).tag == ASN1.BIT_STRING) && (t.value.length > 1)) {
			this.flags = t.value.bytes(1,1).toUnsigned();
			t.setName("flags {" + this.getFlagsAsString() + " }");
			i++;
		}

		if ((i < coa.elements) && ((t = coa.get(i)).tag == ASN1.OCTET_STRING)) {
			t.setName("authId");
			this.authId = t.value;
			i++;
		}

		if ((i < coa.elements) && ((t = coa.get(i)).tag == ASN1.INTEGER)) {
			t.setName("userConsent");
			this.userConsent = t.value.toSigned();
			i++;
		}

		if ((i < coa.elements) && ((t = coa.get(i)).tag == ASN1.SEQUENCE)) {
			t.setName("accessControlRules");
			this.accessControlRules = t.value;
			i++;
		}
	}
}



/**
 * Gets the common object flags as string of concatenated flags.
 * @return the string containing the flags separated by a blank
 * @type String
 */
PKCS15_CIO.prototype.getFlagsAsString = function() {
	return  (this.flags & 0x80 ? " private" : "") +
		(this.flags & 0x40 ? " modifiable" : "") +
		(this.flags & 0x20 ? " internal" : "");
}



/**
 * Convert the object to a human readable string
 *
 * @return the string representation of the object
 * @type String
 */
PKCS15_CIO.prototype.toString = function() {
	var str = "CommonObjectAttributes { ";

	if (typeof(this.label) != "undefined") {
		str += "label=" + this.label + ",\n";
	}

	if (typeof(this.flags) != "undefined") {
		str += "flags=" + this.getFlagsAsString() + ",\n";
	}

	if (typeof(this.authId) != "undefined") {
		str += "authId=" + this.authId + ",\n";
	}

	if (typeof(this.userConsent) != "undefined") {
		str += "userConsent=" + this.userConsent + ",\n";
	}

	if (typeof(this.accessControlRules) != "undefined") {
		str += "accessControlRules=" + this.accessControlRules + ",\n";
	}

	str += "}";
	return str;
}



/**
 * Create a Common Key Attribute Object
 *
 * @class <p>This class adds common key attributes to the base CIO class.</p>
 * <p>The class decodes the following ASN.1 syntax:</p>
 * <pre>
 * CommonKeyAttributes ::= SEQUENCE {
 *		iD Identifier,
 *		usage KeyUsageFlags,
 *		native BOOLEAN DEFAULT TRUE,
 *		accessFlags KeyAccessFlags OPTIONAL,
 *		keyReference KeyReference OPTIONAL,
 *		startDate GeneralizedTime OPTIONAL,
 *		endDate [0] GeneralizedTime OPTIONAL,
 *		algReference [1] SEQUENCE OF Reference OPTIONAL,
 *		... -- For future extensions
 *		}
 * </pre>
 * @constructor
 * @param {ASN1} the tlv structure containing the CIO
 * @see PKCS15_CIO PKCS15_CIO is the base class
 */
function PKCS15_CommonKeyAttributes(tlv) {
	// Call superclass constructor
	PKCS15_CIO.call(this, tlv);

	if (tlv && (tlv instanceof ASN1)) {
		tlv = tlv.get(1);
		tlv.setName("commonKeyAttributes");
		var i = 0;
		var t;

		assert((t = tlv.get(i)).tag == ASN1.OCTET_STRING);
		t.setName("iD");
		this.iD = t.value;
		i++;

		assert((t = tlv.get(i)).tag == ASN1.BIT_STRING);
		this.usage = t.value.bytes(1).toUnsigned(true);
		t.setName("usage {" + this.getUsageAsString() + " }");
		i++;

		if ((i < tlv.elements) && ((t = tlv.get(i)).tag == ASN1.BOOLEAN)) {
			t.setName("native");
			this.native_ = t.value.toUnsigned();
			i++;
		} else {
			this.native_ = true;
		}

		if ((i < tlv.elements) && ((t = tlv.get(i)).tag == ASN1.BIT_STRING)) {
			this.accessFlags = t.value.bytes(1).toUnsigned(true);
			t.setName("accessFlags {" + this.getAccessFlagsAsString() + " }");
			i++;
		}

		if ((i < tlv.elements) && ((t = tlv.get(i)).tag == ASN1.INTEGER)) {
			t.setName("keyReference");
			this.keyReference = t.value.toSigned();
			i++;
		}

		if ((i < tlv.elements) && ((t = tlv.get(i)).tag == ASN1.GeneralizedTime)) {
			t.setName("startDate");
			this.startDate = t.getDate();
			i++;
		}

		if ((i < tlv.elements) && ((t = tlv.get(i)).tag == 0x80)) {
			t.setName("endDate");
			this.endDate = t.getDate();
			i++;
		}

		if ((i < tlv.elements) && ((t = tlv.get(i)).tag == 0xA1)) {
			assert(t.isconstructed);
			t.setName("algReference");
			this.algReference = new Array();
			for (var j = 0; j < t.elements; j++) {
				assert(t.get(j).tag == ASN1.INTEGER);
				t.get(j).setName("reference");
				this.algReference.push(t.get(j).value.toSigned());
			}
			i++;
		}
	}
}

PKCS15_CommonKeyAttributes.prototype = new PKCS15_CIO();



/**
 * Gets the key usage flags as string of concatenated flags.
 * @return the string containing the flags separated by a blank
 * @type String
 */
PKCS15_CommonKeyAttributes.prototype.getUsageAsString = function() {
	return  (this.usage & 0x0080 ? " encipher" : "") +
		(this.usage & 0x0040 ? " decipher" : "") +
		(this.usage & 0x0020 ? " sign" : "") +
		(this.usage & 0x0010 ? " signRecover" : "") +
		(this.usage & 0x0008 ? " keyEncipher" : "") +
		(this.usage & 0x0004 ? " keyDecipher" : "") +
		(this.usage & 0x0002 ? " verify" : "") +
		(this.usage & 0x0001 ? " verifyRecover" : "") +
		(this.usage & 0x8000 ? " derive" : "") +
		(this.usage & 0x4000 ? " nonRepudiation" : "");
}



/**
 * Gets the key access flags as string of concatenated flags.
 * @return the string containing the flags separated by a blank
 * @type String
 */
PKCS15_CommonKeyAttributes.prototype.getAccessFlagsAsString = function() {
	return	(this.accessFlags & 0x80 ? " sensitive" : "") +
		(this.accessFlags & 0x40 ? " extractable" : "") +
		(this.accessFlags & 0x20 ? " alwaysSensitive" : "") +
		(this.accessFlags & 0x10 ? " neverExtractable" : "") +
		(this.accessFlags & 0x08 ? " cardGenerated" : "");
}



/**
 * Convert the object to a human readable string
 * @return content information
 * @type String
 */
PKCS15_CommonKeyAttributes.prototype.toString = function() {

	var str = PKCS15_CIO.prototype.toString.call(this);
	str += "\nCommonKeyAttributes { ";

	if (typeof(this.iD) != "undefined") {
		str += "iD=" + this.iD + ",\n";
	}

	if (typeof(this.usage) != "undefined") {
		str += "usage=" + this.getUsageAsString() + ",\n";
	}

	if (typeof(this.native_) != "undefined") {
		str += "native=" + this.native_ + ",\n";
	}

	if (typeof(this.accessFlags) != "undefined") {
		str += "accessFlags=" + this.getAccessFlagsAsString() + ",\n";
	}

	if (typeof(this.keyReference) != "undefined") {
		str += "keyReference=" + this.keyReference + ",\n";
	}

	if (typeof(this.startDate) != "undefined") {
		str += "startDate=" + this.startDate + ",\n";
	}

	if (typeof(this.endDate) != "undefined") {
		str += "endDate=" + this.endDate + ",\n";
	}

	if (typeof(this.algReference) != "undefined") {
		str += "algReference=" + this.algReference + ",\n";
	}

	str += "}";
	return str;
}



/**
 * Create a Common Private Key Attribute Object
 *
 * @class <p>This class adds common private key attributes to the common key attribute class.</p>
 * <p>The class decodes the following ASN.1 syntax:</p>
 * <pre>
 * CommonPrivateKeyAttributes ::= SEQUENCE {
 * name Name OPTIONAL,
 * keyIdentifiers [0] SEQUENCE OF CredentialIdentifier {{KeyIdentifiers}} OPTIONAL,
 * generalName [1] GeneralNames OPTIONAL,
 * ... -- For future extensions
 * }
 * </pre>
 * @constructor
 * @param {ASN1} the tlv structure containing the CIO
 * @see PKCS15_CommonKeyAttributes PKCS15_CommonKeyAttributes is the base class
 */
function PKCS15_CommonPrivateKeyAttributes(tlv) {
	// Call superclass constructor
	PKCS15_CommonKeyAttributes.call(this, tlv);

	if (tlv && (tlv instanceof ASN1)) {
		var t = tlv.get(2);
		if (t.tag == 0xA0) {
			t.setName("subClassAttributes");

			assert(t.elements == 1);
			t = t.get(0);
			t.setName("commonPrivateKeyAttributes");

			var i = 0;
			if (t.elements > i) {
				print("### Not decoded ### " + t);
			}
		}
	}
}

PKCS15_CommonPrivateKeyAttributes.prototype = new PKCS15_CommonKeyAttributes();



/**
 * Create a Private Key Object
 *
 * @class <p>This class adds private key attributes to the common private key attribute class.</p>
 * <p>The class supports RSA and ECC keys.</p>
 * <p>RSA keys are decoded from the following ASN.1 structure:</p>
 * <pre>
 * PrivateRSAKeyAttributes ::= SEQUENCE {
 * value Path,
 * modulusLength INTEGER, -- modulus length in bits, e.g. 1024
 * keyInfo KeyInfo {NULL, PublicKeyOperations} OPTIONAL,
 * ... -- For future extensions
 * }
 * </pre>
 * <p>ECC keys are decoded from the following ASN.1 structure:</p>
 * <pre>
 * PrivateECKeyAttributes ::= SEQUENCE {
 * value Path,
 * keyInfo KeyInfo {Parameters, PublicKeyOperations} OPTIONAL,
 * ... -- For future extensions
 * }
 * </pre>
 * @constructor
 * @param {ASN1} the tlv structure containing the CIO
 * @see PKCS15_CommonPrivateKeyAttributes PKCS15_CommonPrivateKeyAttributes is the base class
 */
function PKCS15_PrivateKey(tlv) {
	// Call superclass constructor
	PKCS15_CommonPrivateKeyAttributes.call(this, tlv);

	if (tlv && (tlv instanceof ASN1)) {
		var t = tlv.get(tlv.elements - 1);

		assert(t.tag == 0xA1);
		assert(t.elements >= 1);
		t.setName("typeAttributes");

		t = t.get(0);

		switch(tlv.tag) {
		case 0x30: this.decodePrivateRSAKey(t); break;
		case 0xA0: this.decodePrivateECCKey(t); break;
		default:
			this.type = "PrivateKey"; break;
			print("### Not decoded ### " + t);
		}
	}
}

PKCS15_PrivateKey.prototype = new PKCS15_CommonPrivateKeyAttributes();



/**
 * Decodes the RSA key structure.
 *
 * @private
 * @param {ASN1} tlv the TLV structure
 */
PKCS15_PrivateKey.prototype.decodePrivateRSAKey = function(tlv) {
	this.type = "PrivateRSAKey";
	tlv.setName("privateRSAKeyAttributes");

	var t = tlv.get(0);
	this.value = new PKCS15_Path(t);
	t.setName("value");

	t = tlv.get(1);
	assert(t.tag == ASN1.INTEGER);
	this.modulusLength = t.value.toSigned();
	t.setName("modulusLength");

	if (tlv.elements > 2) {
		t = tlv.get(2);
		if (t.tag == ASN1.INTEGER) {
			t.setName("reference");
		} else {
			t.setName("paramsAndOps");
		}
	}
}



/**
 * Decodes the ECC key structure.
 *
 * @private
 * @param {ASN1} tlv the TLV structure
 */
PKCS15_PrivateKey.prototype.decodePrivateECCKey = function(tlv) {
	this.type = "PrivateECCKey";
	tlv.setName("privateECCKeyAttributes");

	var t = tlv.get(0);
	this.value = new PKCS15_Path(t);
	t.setName("value");

	if (tlv.elements > 1) {
		t = tlv.get(1);
		if (t.tag == ASN1.INTEGER) {
			t.setName("reference");
		} else {
			t.setName("paramsAndOps");
		}
	}
}



/**
 * Create a Common Certificate Attribute Object
 *
 * @class <p>This class adds common certificate attributes to the base CIO class.</p>
 * <p>The class decodes the following ASN.1 syntax:</p>
 * <pre>
 * CommonCertificateAttributes ::= SEQUENCE {
 * iD Identifier,
 * authority BOOLEAN DEFAULT FALSE,
 * identifier CredentialIdentifier {{KeyIdentifiers}} OPTIONAL,
 * certHash [0] CertHash OPTIONAL,
 * trustedUsage [1] Usage OPTIONAL,
 * identifiers [2] SEQUENCE OF CredentialIdentifier {{KeyIdentifiers}} OPTIONAL,
 * validity [4] Validity OPTIONAL,
 * ...
 * } -- Context tag [3] is reserved for historical reasons
 * NOTE PKCS #15 uses context tag [3].
 * Usage ::= SEQUENCE {
 * keyUsage KeyUsage OPTIONAL,
 * extKeyUsage SEQUENCE SIZE (1..MAX) OF OBJECT IDENTIFIER OPTIONAL,
 * ...
 * } (WITH COMPONENTS {..., keyUsage PRESENT} | WITH COMPONENTS {..., extKeyUsage PRESENT})
 * </pre>
 * @constructor
 * @param {ASN1} the tlv structure containing the CIO
 * @see PKCS15_CIO PKCS15_CIO is the base class
 */
function PKCS15_CommonCertificateAttributes(tlv) {
	// Call superclass constructor
	PKCS15_CIO.call(this, tlv);

	if (tlv && (tlv instanceof ASN1)) {
		var tlv = tlv.get(1);
		tlv.setName("commonCertificateAttributes");
		var i = 0;
		var t;

		assert((t = tlv.get(i)).tag == ASN1.OCTET_STRING);
		t.setName("iD");
		this.iD = t.value;
		i++;

		if ((i < tlv.elements) && ((t = tlv.get(i)).tag == ASN1.BOOLEAN)) {
			t.setName("authority");
			this.authority = (t.value.toUnsigned() > 0);
			i++;
		}

		if ((i < tlv.elements) && ((t = tlv.get(i)).tag == ASN1.SEQUENCE)) {
			t.setName("identifier");
			this.identifier = t.value;
			i++;
		}

		// Uncommon fields missing
	}
}

PKCS15_CommonCertificateAttributes.prototype = new PKCS15_CIO();



/**
 * Convert the object to a human readable string
 * @return content information
 * @type String
 */
PKCS15_CommonCertificateAttributes.prototype.toString = function() {
	var str = PKCS15_CIO.prototype.toString.call(this);
	str += "\nCommonCertificateAttributes { ";

	str += "iD=" + this.iD + ",\n";

	if (typeof(this.authority) != "undefined") {
		str += "authority=" + this.authority + ",\n";
	}

	if (typeof(this.identifier) != "undefined") {
		str += "identifier=" + this.identifier + ",\n";
	}
	str += "}";
	return str;
}



/**
 * Create a Certificate Attribute Object
 *
 * @class <p>This class adds X.509 certificate attributes to the common certificate attribute class.</p>
 * <p>The class decodes the following ASN.1 syntax for X.509 certificates:</p>
 * <pre>
 * X509CertificateAttributes ::= SEQUENCE {
 * value ObjectValue { Certificate },
 * subject Name OPTIONAL,
 * issuer [0] Name OPTIONAL,
 * serialNumber CertificateSerialNumber OPTIONAL,
 * ... -- For future extensions
 * }
 * </pre>
 * @constructor
 * @param {ASN1} the tlv structure containing the CIO
 * @see PKCS15_CommonCertificateAttributes PKCS15_CommonCertificateAttributes is the base class
 */
function PKCS15_Certificate(tlv) {
	// Call superclass constructor
	PKCS15_CommonCertificateAttributes.call(this, tlv);

	if (tlv && (tlv instanceof ASN1)) {

		var t = tlv.get(2);
		assert(t.tag == 0xA1);
		assert(t.elements == 1);
		t.setName("typeAttributes");
		t = t.get(0);
		t.setName("certificateAttributes");

		switch(tlv.tag) {
		case 0x30: this.decodeX509Certificate(t); break;
		default:
			this.type = "Certificate"; break;
			print("### Not decoded ### " + t);
		}
//		print("Certificate:" + t);
	}
}

PKCS15_Certificate.prototype = new PKCS15_CommonCertificateAttributes();



/**
 * Decodes a X.509 certificate structure.
 *
 * @private
 * @param {ASN1} the tlv structure containing the certificate data
 */
PKCS15_Certificate.prototype.decodeX509Certificate = function(tlv) {
	this.type = "X509Certificate";
	tlv.setName("x509CertificateAttributes");

	var t = tlv.get(0);
	t.setName("value");

	if (t.tag == ASN1.SEQUENCE) {
		this.value = new PKCS15_Path(t);
	}

	var i = 1;

	if ((i < tlv.elements) && ((t = tlv.get(i)).tag == ASN1.SEQUENCE)) {
		t.setName("subject");
		i++;
	}

	if ((i < tlv.elements) && ((t = tlv.get(i)).tag == 0xA0)) {
		t.setName("issuer");
		i++;
	}

	if ((i < tlv.elements) && ((t = tlv.get(i)).tag == ASN1.INTEGER)) {
		t.setName("serialNumber");
		this.serialNumber = t.value;
		i++;
	}
}



/**
 * Create a Common Authentication Object Attribute Object
 *
 * @class <p>This class adds common authentication object attributes to the base CIO class.</p>
 * <p>The class decodes the following ASN.1 syntax:</p>
 * <pre>
 * CommonAuthenticationObjectAttributes ::= SEQUENCE {
 *    authId Identifier OPTIONAL,
 *    authReference Reference OPTIONAL,
 *    seIdentifier [0] Reference OPTIONAL,
 *    ... -- For future extensions
 * }
 * </pre>
 * @constructor
 * @param {ASN1} the tlv structure containing the CIO
 * @see PKCS15_CIO PKCS15_CIO is the base class
 */
function PKCS15_CommonAuthenticationObjectAttributes(tlv) {
	// Call superclass constructor
	PKCS15_CIO.call(this, tlv);

	if (tlv && (tlv instanceof ASN1)) {
		var tlv = tlv.get(1);
		tlv.setName("commonAuthenticationObjectAttributes");
//		print("CommonAuthenticationObjectAttributes:" + tlv);

		var i = 0;
		var t;

		if ((i < tlv.elements) && ((t = tlv.get(i)).tag == ASN1.OCTET_STRING)) {
			t.setName("authIdThis");
			this.authIdThis = t.value;
			i++;
		}

		if ((i < tlv.elements) && ((t = tlv.get(i)).tag == ASN1.INTEGER)) {
			t.setName("authReference");
			this.authReference = t.value.toSigned();
			i++;
		}

		if ((i < tlv.elements) && ((t = tlv.get(i)).tag == 0x80)) {
			t.setName("seIdentifier");
			this.seIdentifier = t.value.toSigned();
			i++;
		}
	}
}

PKCS15_CommonAuthenticationObjectAttributes.prototype = new PKCS15_CIO();



/**
 * Convert the object to a human readable string
 *
 * @return the string representation of the object
 * @type String
 */
PKCS15_CommonAuthenticationObjectAttributes.prototype.toString = function() {

	var str = PKCS15_CIO.prototype.toString.call(this);
	str += "\nCommonAuthenticationObjectAttributes { ";

	if (typeof(this.authIdThis) != "undefined") {
		str += "authIdThis=" + this.authIdThis + ",\n";
	}

	if (typeof(this.authReference) != "undefined") {
		str += "authReference=" + this.authReference + ",\n";
	}

	if (typeof(this.seIdentifier) != "undefined") {
		str += "seIdentifier=" + this.seIdentifier + ",\n";
	}

	if (typeof(this.pwd) != "undefined") {
		str += "pwd=" + this.pwd.toString() + ",\n";
	}

	str += "}";
	return str;
}



/**
 * Create an Authentication Object
 *
 * @class <p>This class adds authentication object attributes to the common authentication object class.</p>
 * <p>The class supports password objects.</p>
 * @constructor
 * @param {ASN1} the tlv structure containing the CIO
 * @see PKCS15_CommonAuthenticationObjectAttributes PKCS15_CommonAuthenticationObjectAttributes is the base class
 */
function PKCS15_AuthenticationObject(tlv) {
	// Call superclass constructor
	PKCS15_CommonAuthenticationObjectAttributes.call(this, tlv);

	if (tlv && (tlv instanceof ASN1)) {
		var t = tlv.get(tlv.elements - 1);
		assert(t.tag == 0xA1);
//		assert(t.elements == 1);
		t.setName("typeAttribute");
		t = t.get(0);

		switch(t.tag) {
		case 0x30:
			this.pwd = new PKCS15_PasswordAuthenticationObject(t);
			break;
		default:
			print("### Unsupported authentication object type : " + t);
			break;
		}
	}
}

PKCS15_AuthenticationObject.prototype = new PKCS15_CommonAuthenticationObjectAttributes();



/**
 * Create a Password Authentication Object
 *
 * @class <p>This class supports password authentication objects.</p>
 * <p>The class decodes the following ASN.1 syntax:</p>
 * <pre>
 * PasswordAttributes ::= SEQUENCE {
 *	pwdFlags PasswordFlags,
 *	pwdType PasswordType,
 *	minLength INTEGER (cia-lb-minPasswordLength..cia-ub-minPasswordLength),
 *	storedLength INTEGER (0..cia-ub-storedPasswordLength),
 *	maxLength INTEGER OPTIONAL,
 *	pwdReference [0] Reference DEFAULT 0,
 *	padChar OCTET STRING (SIZE(1)) OPTIONAL,
 *	lastPasswordChange GeneralizedTime OPTIONAL,
 *	path Path OPTIONAL,
 *	... -- For future extensions
 * }
 * PasswordFlags ::= BIT STRING {
 *	case-sensitive (0),
 *	local (1),
 *	change-disabled (2),
 *	unblock-disabled (3),
 *	initialized (4),
 *	needs-padding (5),
 *	unblockingPassword (6),
 *	soPassword (7),
 *	disable-allowed (8),
 *	integrity-protected (9),
 *	confidentiality-protected (10),
 *	exchangeRefData (11)
 *	} (CONSTRAINED BY { -- "unblockingPassword" and "soPassword" cannot both be set -- })
 * PasswordType ::= ENUMERATED {bcd, ascii-numeric, utf8, half-nibble-bcd, iso9564-1, ...}
 * </pre>
 * @constructor
 * @param {ASN1} the tlv structure containing the CIO
 */
function PKCS15_PasswordAuthenticationObject(tlv) {
	if (tlv && (tlv instanceof ASN1)) {

		tlv.setName("passwordAuthenticationObject");

		var i = 0;
		var t;

		assert((t = tlv.get(i)).tag == ASN1.BIT_STRING);
		this.pwdFlags = IntFromBitString(t.value);
		t.setName("pwdFlags {" + this.getPwdFlagsAsString() + " }");
		i++;

		assert((t = tlv.get(i)).tag == ASN1.ENUMERATED);
		this.pwdType = t.value.toUnsigned();
		t.setName("pwdType {" + this.getPwdTypeAsString() + " }");
		i++;

		assert((t = tlv.get(i)).tag == ASN1.INTEGER);
		t.setName("minLength");
		this.minLength = t.value.toSigned();
		i++;

		assert((t = tlv.get(i)).tag == ASN1.INTEGER);
		t.setName("storedLength");
		this.storedLength = t.value.toSigned();
		i++;

		if ((i < tlv.elements) && ((t = tlv.get(i)).tag == ASN1.INTEGER)) {
			t.setName("maxLength");
			this.maxLength = t.value.toSigned();
			i++;
		}

		if ((i < tlv.elements) && ((t = tlv.get(i)).tag == 0x80)) {
			t.setName("pwdReference");
			this.pwdReference = t.value.toSigned();
			i++;
		}
	}
}



/**
 * Gets the password flags as string of concatenated flags.
 * @return the string containing the flags separated by a blank
 * @type String
 */
PKCS15_PasswordAuthenticationObject.prototype.getPwdFlagsAsString = function() {
	return	(this.pwdFlags & 0x800000 ? " case-sensitive" : "") +
		(this.pwdFlags & 0x400000 ? " local" : "") +
		(this.pwdFlags & 0x200000 ? " change-disabled" : "") +
		(this.pwdFlags & 0x100000 ? " unblock-disabled" : "") +
		(this.pwdFlags & 0x080000 ? " initialized" : "") +
		(this.pwdFlags & 0x040000 ? " needs-padding" : "") +
		(this.pwdFlags & 0x020000 ? " unblockingPassword" : "") +
		(this.pwdFlags & 0x010000 ? " soPassword" : "") +
		(this.pwdFlags & 0x008000 ? " disable-allowed" : "") +
		(this.pwdFlags & 0x004000 ? " integrity-protected" : "") +
		(this.pwdFlags & 0x002000 ? " confidentiality-protected" : "") +
		(this.pwdFlags & 0x001000 ? " exchangeRefData" : "") +
		(this.pwdFlags & 0x000800 ? " resetRetryCounter1" : "") +
		(this.pwdFlags & 0x000400 ? " resetRetryCounter2" : "");
}



/**
 * Gets the password type.
 * @return the string containing the password type (BCD, ASCII-NUMERIC, UTF8, HALF-NIBBLE-BCD or ISO9564-1)
 * @type String
 */
PKCS15_PasswordAuthenticationObject.prototype.getPwdTypeAsString = function() {

	var str = "" + this.pwdType;
	switch(this.pwdType) {
		case  0 : str = "BCD"; break;
		case  1 : str = "ASCII-NUMERIC"; break;
		case  2 : str = "UTF8"; break;
		case  3 : str = "HALF-NIBBLE-BCD"; break;
		case  4 : str = "ISO9564-1"; break;
	}
	return str;
}



/**
 * Convert the object to a human readable string
 *
 * @return the string representation of the object
 * @type String
 */
PKCS15_PasswordAuthenticationObject.prototype.toString = function() {
	var str = "Password { ";

	if (typeof(this.pwdFlags) != "undefined") {
		str += "pwdFlags=" + this.getPwdFlagsAsString() + ",\n";
	}

	if (typeof(this.pwdType) != "undefined") {
		str += "pwdType=" + this.getPwdTypeAsString() + ",\n";
	}

	if (typeof(this.minLength) != "undefined") {
		str += "minLength=" + this.minLength + ",\n";
	}

	if (typeof(this.storedLength) != "undefined") {
		str += "storedLength=" + this.storedLength + ",\n";
	}

	if (typeof(this.maxLength) != "undefined") {
		str += "maxLength=" + this.maxLength + ",\n";
	}

	if (typeof(this.pwdReference) != "undefined") {
		str += "pwdReference=" + this.pwdReference + ",\n";
	}

	str += "}";
	return str;
}



/**
 * Create a Common Data Container Object Attribute Object
 *
 * @class <p>This class adds common data container attributes to the base CIO class.</p>
 * <p>The class decodes the following ASN.1 syntax:</p>
 * <pre>
 * CommonDataContainerObjectAttributes ::= SEQUENCE {
 * 		applicationName Label OPTIONAL,
 * 		applicationOID OBJECT IDENTIFIER OPTIONAL,
 * 		iD Identifier OPTIONAL,
 * 		... -- For future extensions
 * 		} (WITH COMPONENTS {..., applicationName PRESENT}
 * 		| WITH COMPONENTS {..., applicationOID PRESENT})
 * </pre>
 * @constructor
 * @param {ASN1} the tlv structure containing the CIO
 * @see PKCS15_CIO PKCS15_CIO is the base class
 */
function PKCS15_CommonDataContainerObjectAttributes(tlv) {
	// Call superclass constructor
	PKCS15_CIO.call(this, tlv);

	if (tlv && (tlv instanceof ASN1)) {
		var tlv = tlv.get(1);
		tlv.setName("commonDataContainerObjectAttributes");
		var i = 0;
		var t;

		if ((i < tlv.elements) && ((t = tlv.get(i)).tag == ASN1.UTF8String)) {
			t.setName("applicationName");
			this.applicationName = t.value.toString(UTF8);
			i++;
		}

		if ((i < tlv.elements) && ((t = tlv.get(i)).tag == ASN1.OBJECT_IDENTIFIER)) {
			t.setName("applicationOID");
			this.applicationOID = t.value.toString(OID);
			i++;
		}

		if ((i < tlv.elements) && ((t = tlv.get(i)).tag == ASN1.ASN1.OCTET_STRING)) {
			t.setName("iD");
			this.iD = t.value;
			i++;
		}
	}
}

PKCS15_CommonDataContainerObjectAttributes.prototype = new PKCS15_CIO();



/**
 * Convert the object to a human readable string
 *
 * @return the string representation of the object
 * @type String
 */
PKCS15_CommonDataContainerObjectAttributes.prototype.toString = function() {

	var str = PKCS15_CIO.prototype.toString.call(this);
	str += "\nCommonDataContainerObjectAttributes { ";

	if (typeof(this.applicationName) != "undefined") {
		str += "applicationName=" + this.applicationName + ",\n";
	}

	if (typeof(this.applicationOID) != "undefined") {
		str += "applicationOID=" + this.applicationOID + ",\n";
	}

	if (typeof(this.iD) != "undefined") {
		str += "iD=" + this.iD + ",\n";
	}

	str += "}";
	return str;
}



/**
 * Create a Data Container Object
 *
 * @class <p>This class adds data container objects to the common data container object attributes class.</p>
 * <p>The class decodes the following ASN.1 syntax for opaque data objects with indirect path reference:</p>
 * <pre>
 * OpaqueDOAttributes ::= ObjectValue {CIO-OPAQUE.&Type}
 *
 * ObjectValue { Type } ::= CHOICE {
 * 		indirect ReferencedValue,
 * 		direct [0] Type,
 * 		... -- For future extensions
 * }
 *
 * ReferencedValue ::= CHOICE {
 * 		path Path,
 * 		url URL
 * } -- The syntax of the object is determined by the context
 * </pre>
 * @constructor
 * @param {ASN1} the tlv structure containing the CIO
 * @see PKCS15_CommonDataContainerObjectAttributes PKCS15_CommonDataContainerObjectAttributes is the base class
 */
function PKCS15_DataContainerObject(tlv) {
	// Call superclass constructor
	PKCS15_CommonDataContainerObjectAttributes.call(this, tlv);

	if (tlv && (tlv instanceof ASN1)) {

		var t = tlv.get(2);
		assert(t.tag == 0xA1);
		assert(t.elements == 1);
		t.setName("typeAttributes");
		t = t.get(0);
		t.setName("dataContainerAttributes");

		switch(tlv.tag) {
		case 0x30: this.decodeOpaqueDOIndirectPath(t); break;
		default:
			print("### Unsupported data container object type : " + t);
		}
	}
}

PKCS15_DataContainerObject.prototype = new PKCS15_CommonDataContainerObjectAttributes();



/**
 * Decodes an oqaque data object.
 *
 * @private
 * @param {ASN1} the tlv structure containing the opaque data object
 */
PKCS15_DataContainerObject.prototype.decodeOpaqueDOIndirectPath = function(tlv) {
	this.type = "OpaqueDOIndirectPath";
	tlv.setName("OpaqueDOIndirectPath");

	this.indirectPath = new PKCS15_Path(tlv);
}



/**
 * Convert the object to a human readable string
 *
 * @return the string representation of the object
 * @type String
 */
PKCS15_DataContainerObject.prototype.toString = function() {

	var str = PKCS15_CommonDataContainerObjectAttributes.prototype.toString.call(this);
	str += "\nDataContainerObject { ";

	if (typeof(this.indirectPath) != "undefined") {
		str += "indirectPath=" + this.indirectPath + ",\n";
	}

	str += "}";
	return str;
}



/**
 * Create an object to access the PKCS#15 structure on a card.
 *
 * @class <p>This class provides for direct access to a PKCS#15 data structure on a card.</p>
 * <p>The calling application will typically use:</p>
 * <pre>
 * var card = new Card(_scsh3.reader);
 * var p15 = new PKCS15(card);
 * var appllist = p15.readApplicationDirectory();
 * var aid;
 * for (var i in appllist) {
 *   print(i);
 *   aid = i;
 * }
 * var at = appllist[aid];
 * p15.readObjectListForApplication(at);
 * for (var i = 0; i < at.objlist.length; i++) {
 *   print(at.objlist[i]);
 * }
 * </pre>
 * @constructor
 * @param {Card} card the card object to use for card access.
 */
function PKCS15(card) {
	this.card = card;
}



/**
 * Reads the application directory from EF_DIR.
 *
 * <p>The method supports linear variable and transparent EFs. It creates an internal table of
 *    of applications.</p>
 *
 * @return hash table of application templates index by application identifier
 * @type PKCS15_ApplicationTemplate[]
 */
PKCS15.prototype.readApplicationDirectory = function() {
	this.ef_dir = new CardFile(this.card, ":3F00:2F00");

	this.aidlist = new Array();

	if (this.ef_dir.isTransparent()) {
		var data = this.ef_dir.readBinary();
//		print(data);

		while((data.length > 0) && (data.byteAt(0) == 0x61)) {
			var tlv = new ASN1(data);
//			print(tlv);
			data = data.bytes(tlv.size);
//			print(data);

			var at = new PKCS15_ApplicationTemplate(tlv);
			this.aidlist[at.aid] = at;
		}

	} else {
		var rec = 1;
		while(rec < 256) {
			var data;
			try {
				data = this.ef_dir.readRecord(rec);
			}
			catch(e) {
				if (!(e instanceof GPError) || (e.error != GPError.CARD_COMM_ERROR)) {
					print(e);
					throw(e);
				}
				break;
			}

			var tlv = new ASN1(data);
			var at = new PKCS15_ApplicationTemplate(tlv);
			this.aidlist[at.aid] = at;
			rec++;
		}
	}
	return this.aidlist;
}



/**
 * Reads from the transparent file referenced in the PKCS#15 path object.
 *
 * @private
 * @param {String} df the current DF in OCF path notation.
 * @param {PKCS15_Path} path the relative or absolute path to the EF
 * @return the content of the file
 * @type ByteString
 */
PKCS15.prototype.readCardObject = function(df, path) {

	var p = path.getAbsolutePath(df);
	print("Reading from: " + p);
	var ef = new CardFile(this.card, p);
	var data;
	if (path.index) {
		data = ef.readBinary(path.index, path.length);
	} else {
		data = ef.readBinary(0);
	}
	return data;
}



/**
 * Parse a list of TLV objects
 *
 * @param {ByteString} data the binary data with TLV objects
 * @return the list of ASN1 objects
 * @type ASN1[]
 */
PKCS15.parseObjectList = function(data) {

	var list = new Array();
	var len = data.length;

	while(len > 0) {
		if ((data.byteAt(0) == 0x00) || (data.byteAt(0) == 0xFF)) {
			len--;
			data = data.bytes(1);
		} else {
//			print(data);
			var tlv = new ASN1(data);
			var tlvsize = tlv.size;
			len -= tlvsize;
			data = data.bytes(tlvsize);
			list.push(tlv);
//			print("parseObjectList: " + tlv);
		}
	}
	return list;
}



/**
 * Reads PKCS#15 objects from card file which can be either transparent or record oriented.
 *
 * @param {String} df the current DF in OCF path notation.
 * @param {PKCS15_Path} path the relative or absolute path to the EF
 * @return the array of TLV objects read from the file
 * @type ASN1[]
 */
PKCS15.prototype.readCardObjects = function(df, path) {

	var p = path.getAbsolutePath(df);
	print("Reading from: " + p);
	var ef = new CardFile(this.card, p);
	var list = new Array();

	var isTransparent = true;
	try	{
		isTransparent = ef.isTransparent();
	}
	catch(e) {
		// Ignore
	}
	if (isTransparent) {
		var data;
		if (path.index) {
			data = ef.readBinary(path.index, path.length);
		} else {
			try	{
				var len = ef.getLength();
				data = ef.readBinary(0, len);
			}
			catch(e) {
				data = ef.readBinary(0);
			}
		}

		var len = data.length;

		try	{
			while(len > 0) {
				if ((data.byteAt(0) == 0x00) || (data.byteAt(0) == 0xFF)) {
					len--;
					data = data.bytes(1);
				} else {
//					print(data);
					var tlv = new ASN1(data);
					var tlvsize = tlv.size;
					len -= tlvsize;
					data = data.bytes(tlvsize);
					list.push(tlv);
//					print("readCardObjects: " + tlv);
				}
			}
		}
		catch(e) {
			print("Error reading cryptographic information object: " + e);
			print(data);
		}
	} else {
		var rec = 1;
		while(rec < 256) {
			var data;
			try {
				data = ef.readRecord(rec);
			}
			catch(e) {
				if (!(e instanceof GPError) || (e.error != GPError.CARD_COMM_ERROR)) {
					print(e);
					throw(e);
				}
				break;
			}

			data = data.bytes(2);	// Strip of first two bytes
//			print("Data : " + data);
			if (data.length > 2) {	// Record might be empty
				try	{
					var tlv = new ASN1(data);
					list.push(tlv);
//					print("readCardObjects: " + tlv);
				}
				catch(e) {
					print("Error reading cryptographic information object: " + e);
					print(data);
				}
			}
			rec++;
		}
	}
	return list;
}



/**
 * Reads all CIO objects for an application and adds the CIO objects to the objlist property
 *
 * @param {PKCS15_ApplicationTemplate} at the application template
 */
PKCS15.prototype.readObjectListForApplication = function(at) {
	if (!at.ddo) {
		throw new Error("Application has no PKCS#15 information");
	}

	if (!at.ddo.odfPath) {
		throw new Error("Application has no odfPath");
	}

	at.objlist = new Array();

	var dos = this.readCardObjects(":3F00", at.ddo.odfPath);

	// Determine current DF
	var df = at.ddo.odfPath.getAbsolutePath(":3F00");
	df = df.slice(0, -5);
	this.df = df;

	for (var i = 0; i < dos.length; i++) {
		var tlv = dos[i];
		assert(tlv.isconstructed);
		var ciotype = tlv.tag;
		var path = new PKCS15_Path(tlv.get(0));

//		print("Path = " + path);
		var cios = this.readCardObjects(df, path);

		for (var j = 0; j < cios.length; j++) {
			var tlv = cios[j];

			var cio;
			switch(ciotype) {
				case 0xA0:
					cio = new PKCS15_PrivateKey(tlv);
//					cio.type = "PrivateKey";
					break;
				case 0xA1:
//					cio = new PKCS15_PublicKey(tlv);
					cio = new PKCS15_CIO(tlv);
					cio.type = "PublicKey";
					break;
				case 0xA2:
//					cio = new PKCS15_PublicKey(tlv);
					cio = new PKCS15_CIO(tlv);
					cio.type = "TrustedPublicKey";
					break;
				case 0xA3:
//					cio = new PKCS15_SecretKey(tlv);
					cio = new PKCS15_CIO(tlv);
					cio.type = "SecretKey";
					break;
				case 0xA4:
					cio = new PKCS15_Certificate(tlv);
//					cio.type = "Certificate";
					break;
				case 0xA5:
					cio = new PKCS15_Certificate(tlv);
					cio.type = "Trusted" + cio.type;
					break;
				case 0xA6:
					cio = new PKCS15_Certificate(tlv);
					cio.type = "Useful" + cio.type;
					break;
				case 0xA7:
					cio = new PKCS15_DataContainerObject(tlv);
					cio.type = "DataContainerObject";
					break;
				case 0xA8:
					cio = new PKCS15_AuthenticationObject(tlv);
					cio.type = "AuthObject";
					break;
				default:
					assert(false);
			}
			at.objlist.push(cio);
		}
	}
}



/**
 * Reads and return the CIAInfo structure referenced by the PKCS#15 path element.
 *
 * @param {PKCS15_Path} path the path to the CIAInfo file
 * @return the CIAInfo description
 * @type PKCS15_CIAInfo
 */
PKCS15.prototype.getCIAInfo = function(path) {

	var cia = this.readCardObject(":3F00", path);
	var tlv = new ASN1(cia);
	return new PKCS15_CIAInfo(tlv);
}



/**
 * Return the hash table of application templates
 *
 * @return the hash table of application templates
 * @type PKCS15_ApplicationTemplate[]
 */
PKCS15.prototype.getAidList = function() {
	return this.aidlist;
}

