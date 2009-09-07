/**
 * @fileoverview Simulator for EAC 2.0 Protocol
 */

load("pace.js");


/**
 * Create a EAC 2.0 simulation object
 *
 * @constructor
 */
function EAC20Sim() {
	this.reset(0);
	
	this.pacedp = new Key();
	this.pacedp.setComponent(Key.ECC_CURVE_OID, new ByteString("1.3.36.3.3.2.8.1.1.7", OID));
}


EAC20Sim.emptyData = new ByteString("", HEX);


/**
 * Resets the card and all internal variables.
 *
 * @param {Number} procedure one of Card.RESET_COLD or Card.RESET_WARM - has no relevance
 */
EAC20Sim.prototype.reset = function(procedure) {
	this.SW = 0x9000;
	this.se = { VEXK: new SecurityEnvironment(), CDIK: new SecurityEnvironment(), SMRES: new SecurityEnvironment(), SMCOM: new SecurityEnvironment()};
	this.pace = null;
}



/**
 * Manage security environment.
 * 
 * <p>Only the SET variante is supported.</p>
 * <p>Called internally with INS 22.</p>
 */
EAC20Sim.prototype.manageSE = function(p1, p2, data) {
	if ((p1 & 0x0F) == 1) { 	// SET
		var tlv = new ASN1(p2, data);
		tlv = new ASN1(tlv.getBytes());		// Dirty trick to deserialize as TLV tree

		if (p1 & 0x80) {					// Verification, Encryption, External Authentication and Key Agreement
			this.se.VEXK.add(tlv);
		}
		if (p1 & 0x40) {					// Calculation, Decryption, Internal Authentication and Key Agreement
			this.se.CDIK.add(tlv);
		}
		if (p1 & 0x20) {					// Secure Messaging Response
			this.se.SMRES.add(tlv);
		}
		if (p1 & 0x10) {					// Secure Messaging Command
			this.se.SMCOM.add(tlv);
		}
		print(tlv);
	} else {
		this.SW = 0x8A61; // Function not supported
	}
}



EAC20Sim.prototype.generalAuthenticate = function(p1, p2, data, le) {
	var a = new ASN1(data);
	
	if (a.tag != 0x7C)
		throw new GPError("EACSIM", GPError.INVALID_DATA, 0, "Body must contain data element 0x7C");

	var response;
	
	if (a.elements == 0) {		// 1st General Authenticate
		// ToDo use info from SE
		this.pace = new PACE(PACE.id_PACE_ECDH_GM_AES_CBC_CMAC_128, this.pacedp);
		this.pace.setPassword(new ByteString("000001", ASCII));
		var encnonce = this.pace.getEncryptedNonce();
		response = new ASN1(0x80, encnonce);
	} else {
		if (!this.pace)
			throw new GPError("EACSIM", GPError.INVALID_MECH, 0, "PACE must have been initialized");

		if (a.elements != 1)
			throw new GPError("EACSIM", GPError.INVALID_DATA, 0, "Dynamic Authentication Data may only contain 1 element");

		a = a.get(0);
		
		switch(a.tag) {
		case 0x81:
			if (!this.pace.hasNonce())
				throw new GPError("EACSIM", GPError.INVALID_DATA, 0, "Invalid sequence. First GA missing");

			if (this.pace.hasMapping())
				throw new GPError("EACSIM", GPError.INVALID_DATA, 0, "Invalid sequence. Steps was already performed");
			
			if (a.value.byteAt(0) != 0x04) 
				throw new GPError("EACSIM", GPError.INVALID_DATA, 0, "Public key does not start with '04'");
			
			var mappingData = this.pace.getMappingData();
			response = new ASN1(0x82, mappingData);
			
			this.pace.performMapping(a.value);
			break;
		case 0x83:
			if (!this.pace.hasMapping())
				throw new GPError("EACSIM", GPError.INVALID_DATA, 0, "Invalid sequence. Second GA missing");
			
			if (a.value.byteAt(0) != 0x04) 
				throw new GPError("EACSIM", GPError.INVALID_DATA, 0, "Public key does not start with '04'");
			
			var ephKey = this.pace.getEphemeralPublicKey();
			response = new ASN1(0x84, ephKey);
			
			this.pace.performKeyAgreement(a.value);
			break;
		case 0x85:
			if (!this.pace.verifyAuthenticationToken(a.value)) {
				throw new GPError("EACSIM", GPError.INVALID_DATA, 0, "Verification of authentication token failed");
			}
			
			var authToken = this.pace.calculateAuthenticationToken();
			
			response = new ASN1(0x86, authToken);
			break;
		default:
			throw new GPError("EACSIM", GPError.INVALID_DATA, 0, "Unsupported Dynamic Authentication Data");
		}
	}
	
	var t = new ASN1(0x7C, response);
	return t.getBytes();
}



/**
 * Send an APDU to the simulation.
 *
 * @param {Number} cla the class byte
 * @param {Number} ins the instruction byte
 * @param {Number} p1 the parameter 1 byte
 * @param {Number} p2 the parameter 2 byte
 * @param {Number} p3 absent or data or Le
 * @param {Number} p4 absent or Le
 * @return the data returned from the simulation or an empty ByteString
 * @type ByteString
 */
  
EAC20Sim.prototype.sendApdu = function(cla, ins, p1, p2, p3, p4) {

	var data = EAC20Sim.emptyData;
	this.SW = 0x9000;
	
	try	{
		switch(ins) {
			case 0x22:
				this.manageSE(p1, p2, p3);
				break;
			case 0x86:
				data = this.generalAuthenticate(p1, p2, p3, p4);
				break;
		}
	}
	catch(e) {
		print("Exception " + e);
		if (e instanceof GPError) {
			if (e.reason != 0) {
				this.SW = e.reason;
			} else {
				this.SW = 0x6300;
			}
		}
		
	}
	
	return data;
}



/**
 * Displays all internal informations.
 */
EAC20Sim.prototype.toString = function() {
	var str = "SW1/SW2: " + this.SW + "\n";
	str += "SE for Verification, Encryption, External Authentication and Key Agreement\n";
	str += this.se.VEXK.toString();
	str += "SE for Calculation, Decryption, Internal Authentication and Key Agreement\n";
	str += this.se.CDIK.toString();
	str += "SE for Secure Messaging Response\n";
	str += this.se.SMRES.toString();
	str += "SE for Secure Messaging Command\n";
	str += this.se.SMCOM.toString();
	
	str += this.pace;
	return str;
}



/**
 * Creates a security environment container that collect cryptographic reference templates (CRT)
 *
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
