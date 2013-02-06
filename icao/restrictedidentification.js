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
 * @fileoverview Implementation of the ASN.1 structures for restricted identification
 */



/**
 * Create a RestrictedIdentificationInfo object
 *
 * @class <p>This class encodes and decodes RestrictedIdentificationInfo objects.</p>
 * <p>The class implements the following ASN.1 syntax:</p>
 * <pre>
 * RestrictedIdentificationInfo ::= SEQUENCE {
 *   protocol  OBJECT IDENTIFIER(
 *             id-RI-DH-SHA-1  |
 *             id-RI-DH-SHA-224  |
 *             id-RI-DH-SHA-256  |
 *             id-RI-DH-SHA-384 |
 *             id-RI-DH-SHA-512 |
 *             id-RI-ECDH-SHA-1  |
 *             id-RI-ECDH-SHA-224  |
 *             id-RI-ECDH-SHA-256 |
 *             id-RI-ECDH-SHA-384 |
 *             id-RI-ECDH-SHA-512),
 *   params    ProtocolParams,
 *   maxKeyLen INTEGER OPTIONAL
 * }
 * ProtocolParams ::= SEQUENCE {
 *   version         INTEGER, -- MUST be 1
 *   keyId           INTEGER,
 *   authorizedOnly  BOOLEAN
 * }
 * </pre>
 * @constructor
 * @param {ASN1} the optional tlv structure to initialize the object
 */
function RestrictedIdentificationInfo(tlv) {
	if (tlv && (tlv instanceof ASN1)) {
		assert(tlv.isconstructed);
		assert(tlv.elements >= 2);

		var i = 0;
		var t = tlv.get(i++);
		assert(t.tag == ASN1.OBJECT_IDENTIFIER);
		this.protocol = t.value;

		var params = tlv.get(i++);
		assert(params.tag == ASN1.SEQUENCE);
		assert(params.elements == 3);

		assert(params.get(0).tag == ASN1.INTEGER);
		this.version = params.get(0).value.toSigned();

		assert(params.get(1).tag == ASN1.INTEGER);
		this.keyId = params.get(1).value.toSigned();

		assert(params.get(2).tag == ASN1.BOOLEAN);
		this.authorizedOnly = params.get(2).value.toSigned();

		if (i < tlv.elements) {
			var t = tlv.get(i++);
			assert(t.tag == ASN1.INTEGER);
			this.maxKeyLen = t.value.toSigned();
		}
	}
}



/**
 * Convert object to TLV structure
 *
 * @return the TLV structure
 * @type ASN1
 */
RestrictedIdentificationInfo.prototype.toTLV = function() {
	var t = new ASN1(ASN1.SEQUENCE,
				new ASN1(ASN1.OBJECT_IDENTIFIER, this.protocol),
				new ASN1(ASN1.SEQUENCE,
					new ASN1(ASN1.INTEGER, ByteString.valueOf(this.version)),
					new ASN1(ASN1.INTEGER, ByteString.valueOf(this.keyId)),
					new ASN1(ASN1.BOOLEAN, ByteString.valueOf(this.authorizedOnly ? 0xFF : 0x00))
				)
	);

	if (typeof(this.maxKeyLen) != "undefined") {
		t.add(new ASN1(ASN1.INTEGER, ByteString.valueOf(this.maxKeyLen)));
	}
	return t;
}



RestrictedIdentificationInfo.prototype.toString = function() {
	return "RestrictedIdentificationInfo(protocol=" + this.protocol + ", version=" + this.version + ", keyId=" + this.keyId + ",authOnly=" + this.authorizedOnly + ",maxKeyLen=" + this.maxKeyLen + ")";
}



/**
 * Create a RestrictedIdentificationDomainParameterInfo object
 *
 * @class <p>This class encodes and decodes RestrictedIdentificationDomainParameterInfo objects.</p>
 * <p>The class implements the following ASN.1 syntax:</p>
 * <pre>
 *	RestrictedIdentificationDomainParameterInfo ::= SEQUENCE {
 *		protocol OBJECT IDENTIFIER(id-CA-DH | id-CA-ECDH),
 *		domainParameter AlgorithmIdentifier,
 * }
 * </pre>
 * @constructor
 * @param {ASN1} the optional tlv structure to initialize the object
 */
function RestrictedIdentificationDomainParameterInfo(tlv) {
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
				this.standardizedDomainParameter = t.get(1).value.toUnsigned();
				var curveoid = RestrictedIdentification.standardizedDomainParameter[this.standardizedDomainParameter];
				if (!curveoid) {
					throw new GPError("RestrictedIdentificationPublicKeyInfo", GPError.INVALID_DATA, 0, "Standardized domain parameter " + this.standardizedDomainParameter + " is unknown");
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
	}
}



/**
 * Convert object to TLV structure
 *
 * @return the TLV structure
 * @type ASN1
 */
RestrictedIdentificationDomainParameterInfo.prototype.toTLV = function() {
	var t = new ASN1(ASN1.SEQUENCE);

	t.add(new ASN1(ASN1.OBJECT_IDENTIFIER, this.protocol));

	var c = new ASN1(ASN1.SEQUENCE);
	if (this.standardizedDomainParameter) {
		c.add(new ASN1(ASN1.OBJECT_IDENTIFIER, new ByteString("standardizedDomainParameter", OID)));
		c.add(new ASN1(ASN1.INTEGER, ByteString.valueOf(this.standardizedDomainParameter)));
	} else {

	}
	t.add(c);

	return t;
}



RestrictedIdentificationDomainParameterInfo.prototype.toString = function() {
	return "RestrictedIdentificationDomainParameterInfo(protocol=" + this.protocol + ", keyId=" + this.keyId + ")";
}


RestrictedIdentification = {
	id_RI: new ByteString("id-RI", OID),
	id_RI_DH: new ByteString("id-RI-DH", OID),
	id_RI_ECDH: new ByteString("id-RI-ECDH", OID)
};

RestrictedIdentification.standardizedDomainParameter = [];
RestrictedIdentification.standardizedDomainParameter[8] = "secp192r1";
RestrictedIdentification.standardizedDomainParameter[9] = "brainpoolP192r1";
RestrictedIdentification.standardizedDomainParameter[10] = "secp224r1";
RestrictedIdentification.standardizedDomainParameter[11] = "brainpoolP224r1";
RestrictedIdentification.standardizedDomainParameter[12] = "secp256r1";
RestrictedIdentification.standardizedDomainParameter[13] = "brainpoolP256r1";
RestrictedIdentification.standardizedDomainParameter[14] = "brainpoolP320r1";
RestrictedIdentification.standardizedDomainParameter[15] = "secp384r1";
RestrictedIdentification.standardizedDomainParameter[16] = "brainpoolP384r1";
RestrictedIdentification.standardizedDomainParameter[17] = "brainpoolP512r1";
RestrictedIdentification.standardizedDomainParameter[18] = "secp521r1";
