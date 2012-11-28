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
 * @fileoverview Implementation of the Extended Access Control protocol in version 2.0
 */


load("tools/eccutils.js");

load("pace.js");
load("chipauthentication.js");
load("cvcertstore.js");



/**
 * Create a protocol object for EAC
 *
 * @class Class implementing support for Extended Access Control V2
 * @constructor
 * @param {Crypto} crypto the crypto provider
 * @param {Card} card the card object
 */
function EAC20(crypto, card) {
	this.crypto = crypto;
	this.card = card;
	this.sm = null;
	this.includeDPinAuthToken = false;		// Standard for PACE version >= 2
	
	// ToDo: Determine from CVCA Certificate
	this.oidTerminalAuthentication = EAC20.id_TA_ECDSA_SHA_256;
	
	this.PACEInfos = new Array();
	this.PACEDPs = new Array();

	this.CAInfos = new Array();
	this.CADPs = new Array();

	this.isEAC111 = false;
}


/** PACE PWD is the hashed MRZ */
EAC20.ID_MRZ = 1;
/** PACE PWD is the CAN */
EAC20.ID_CAN = 2;
/** PACE PWD is the PIN */
EAC20.ID_PIN = 3;
/** PACE PWD is the PUK */
EAC20.ID_PUK = 4;



/**
 * Process a list of security infos from EF.CardInfo, EF.CardSecurity or EF.ChipSecurity
 * 
 * @param {ASN1} si the security info ASN Sequence
 * @param {boolean} fromCardSecurity true if security infos are taken from EF.CardSecurity
 */
EAC20.prototype.processSecurityInfos = function(si, fromCardSecurity) {
	GPSystem.trace("SecurityInfos:");
	GPSystem.trace(si);
	
	var id_PACE = new ByteString("id-PACE", OID);
	var id_PACE_DH_GM = new ByteString("id-PACE-DH-GM", OID);
	var id_PACE_ECDH_GM = new ByteString("id-PACE-ECDH-GM", OID);
	var id_PACE_DH_IM = new ByteString("id-PACE-DH-IM", OID);
	var id_PACE_ECDH_IM = new ByteString("id-PACE-ECDH-IM", OID);
	var id_PK_ECDH = new ByteString("id-PK-ECDH", OID);
	var id_CA = new ByteString("id-CA", OID);
	var id_CA_DH = new ByteString("id-CA-DH", OID);
	var id_CA_ECDH = new ByteString("id-CA-ECDH", OID);
	var id_TA = new ByteString("id-TA", OID);
	var id_RI = new ByteString("id-RI", OID);
	var id_RI_DH = new ByteString("id-RI-DH", OID);
	var id_RI_ECDH = new ByteString("id-RI-ECDH", OID);
	
	for (var i = 0; i < si.elements; i++) {
		var o = si.get(i);
		assert((o.elements >= 1) && (o.elements <= 3));
		
		var oid = o.get(0);
		assert(oid.tag == ASN1.OBJECT_IDENTIFIER);
		
		if (oid.value.startsWith(id_TA) == id_TA.length) {
//			print("TA : " + o);
		} else if (oid.value.equals(id_PK_ECDH)) {
//			print("CA Public Key: " + o);
			this.cAPublicKeyObject = o;
			this.cAPublicKey = o.get(1).get(1).value.bytes(1);
//			print(this.cAPublicKey);
		} else if (oid.value.startsWith(id_PACE) == id_PACE.length) {
			if (oid.value.equals(id_PACE_DH_GM) ||
				oid.value.equals(id_PACE_ECDH_GM) ||
				oid.value.equals(id_PACE_DH_IM) ||
				oid.value.equals(id_PACE_ECDH_GM)) {
//				print("PaceDomainParameterInfo : " + o);
				
				var pdpi = new PACEDomainParameterInfo(o);
//				print(pdpi);
				
				var id = pdpi.parameterId;
				
				if (typeof(id) == "undefined") {
					id = 0;
				}
				
				if (!fromCardSecurity && (typeof(this.PACEDPs[id]) != "undefined")) {
					throw new GPError("EAC20", GPError.INVALID_DATA, 0, "Duplicate parameterId " + id + " for PACEDomainParameter");
				}
				
				this.PACEDPs[id] = pdpi;
			} else {
//				print("PaceInfo : " + o);

				var pi = new PACEInfo(o);
//				print(pi);
				
				var id = pi.parameterId;
				
				if (typeof(id) == "undefined") {
					id = 0;
				}
				
				if (pi.version == 1) {
					if (!fromCardSecurity && (typeof(this.PACEInfos[id]) != "undefined")) {
						throw new GPError("EAC20", GPError.INVALID_DATA, 0, "Duplicate parameterId " + id + " for PACEInfo");
					}
				} else {
					id = 0;
				}
				this.PACEInfos[id] = pi;
			}
		} else if (oid.value.startsWith(id_CA) == id_CA.length) {
			if (oid.value.equals(id_CA_DH) ||
				oid.value.equals(id_CA_ECDH)) {
//				print("ChipAuthenticationDomainParameterInfo : " + o);
				
				var cadpi = new ChipAuthenticationDomainParameterInfo(o);
//				print(cadpi);
				
				var id = cadpi.keyId;
				
				if (typeof(id) == "undefined") {
//					print("Using default key id 0");
					id = 0;
				}
				
				if (!fromCardSecurity && (typeof(this.CADPs[id]) != "undefined")) {
					throw new GPError("EAC20", GPError.INVALID_DATA, 0, "Duplicate keyId " + id + " for ChipAuthenticationDomainParameter");
				}
				
				this.CADPs[id] = cadpi;
			} else {
//				print("ChipAuthenticationInfo : " + o);

				var cai = new ChipAuthenticationInfo(o);
//				print(cai);
				
				var id = cai.keyId;
//				print(id);
				
				if (typeof(id) == "undefined") {
//					print("Using default key id 0");
					id = 0;
				}
				
				if (!fromCardSecurity && (typeof(this.CAInfos[id]) != "undefined")) {
					throw new GPError("EAC20", GPError.INVALID_DATA, 0, "Duplicate keyId " + id + " for ChipAuthenticationInfo");
				}
				
				this.CAInfos[id] = cai;
			}
		}
	}
}



/**
 * Select LDS, marking this a EAC 1.11 session
 *
 * @param {Boolean} useEAC2 use EAC2.x instead of EAC1.x
 */
EAC20.prototype.selectLDS = function(useEAC2) {
	if (this.sm) {			// If we use SAC, then we already have a PACE channel open
		var mf = this.getDF();
		this.df = new CardFile(mf, "#A0000002471001");
	} else {
		this.df = new CardFile(this.card, "#A0000002471001");
	}
	if (!useEAC2) {
		this.isEAC111 = true;
	}
}



/**
 * Read EF.DG14 and process security infos
 *
 */
EAC20.prototype.readDG14 = function() {

	var ci = new CardFile(this.getDF(), ":0E");
	var cibin = ci.readBinary();
	var citlv = new ASN1(cibin);
//	print(citlv);
	
	this.processSecurityInfos(citlv.get(0), false);
}



/**
 * Read EF.CVCA and process contained CARs
 *
 */
EAC20.prototype.readCVCA = function() {

	var cvcaef = new CardFile(eac.getDF(), ":011C");
	var cvcabin = cvcaef.readBinary();
	assert(cvcabin.byteAt(0) == 0x42);

	var cvca = new ASN1(cvcabin);
	this.lastCAR = new PublicKeyReference(cvca.value);

	if (cvcabin.byteAt(cvca.size) == 0x42) {
		var cvca = new ASN1(cvcabin.bytes(cvca.size));
		this.previousCAR = new PublicKeyReference(cvca.value);
	}
}



/**
 * Read EF.CardInfo and process security infos
 *
 */
EAC20.prototype.readCardInfo = function() {

	var ci = new CardFile(this.getDF(), ":011C");
	var cibin = ci.readBinary();
	var citlv = new ASN1(cibin);
//	print(citlv);
	
	this.processSecurityInfos(citlv, false);
}



/**
 * Read EF.CardSecurity and process security infos
 */
EAC20.prototype.readCardSecurity = function() {
	var cs = new CardFile(this.getDF(), ":011D");
	var csbin = cs.readBinary();
	var cstlv = new ASN1(csbin);
	GPSystem.trace("EF.CardSecurity:");
	GPSystem.trace(cstlv);
	
	var cms = new CMSSignedData(csbin);

	var certs = cms.getSignedDataCertificates();

	GPSystem.trace("EF.CardSecurity Certificates:");
	for (var i = 0; i < certs.length; i++) {
		GPSystem.trace(certs[i]);
	}

	print("DocSigner Signature is " + (cms.isSignerInfoSignatureValid(0) ? "valid" : "not valid"));

	var data = cms.getSignedContent();

//	print(data);

	var cstlv = new ASN1(data);

//	print(cstlv);
	
	this.processSecurityInfos(cstlv, true);
}



/**
 * Read EF.ChipSecurity and process security infos
 */
EAC20.prototype.readChipSecurity = function() {
	var cs = new CardFile(this.getDF(), ":011B");
	var csbin = cs.readBinary();
	var cstlv = new ASN1(csbin);
	GPSystem.trace("EF.ChipSecurity:");
	GPSystem.trace(cstlv);
	
	var cms = new CMSSignedData(csbin);

	var certs = cms.getSignedDataCertificates();

	GPSystem.trace("EF.ChipSecurity Certificates:");
	for (var i = 0; i < certs.length; i++) {
		GPSystem.trace(certs[i]);
	}

	print("DocSigner Signature is " + (cms.isSignerInfoSignatureValid(0) ? "valid" : "not valid"));

	var data = cms.getSignedContent();

//	print(data);

	var cstlv = new ASN1(data);

//	print(cstlv);
	
	this.processSecurityInfos(cstlv, true);
}



/**
 * Return the list of PACEInfo objects
 *
 * @return the list of PACEInfo objects read from the card, indexed by the parameterId
 * @type PACEInfo[]
 */
EAC20.prototype.getPACEInfos = function() {
	return this.PACEInfos;
}



/**
 * Return the list of PACEDomainParameterInfo objects
 *
 * @return the list of PACEDomainParameterInfo objects read from the card, indexed by the parameterId
 * @type PACEDomainParameterInfo[]
 */
EAC20.prototype.getPACEDomainParameterInfos = function() {
	return this.PACEDPs;
}



/**
 * Return the list of ChipAuthenticationInfo objects
 *
 * @return the list of ChipAuthenticationInfo objects read from the card, indexed by the keyId
 * @type ChipAuthenticationInfo[]
 */
EAC20.prototype.getCAInfos = function() {
	return this.CAInfos;
}



/**
 * Return the list of ChipAuthenticationDomainParameterInfo objects
 *
 * @return the list of ChipAuthenticationDomainParameterInfo objects read from the card, indexed by the keyId
 * @type ChipAuthenticationDomainParameterInfo[]
 */
EAC20.prototype.getCADomainParameterInfos = function() {
	return this.CADPs;
}



/**
 * Return the MF access object with the associated secure channel. Deprecated use getDF instead
 *
 * @return the MF card file object
 * @type CardFile
 */
EAC20.prototype.getMF = function() {
	return this.df;
}



/**
 * Return the DF access object with the associated secure channel
 *
 * @return the DF card file object
 * @type CardFile
 */
EAC20.prototype.getDF = function() {
	if (typeof(this.df) == "undefined") {
		this.df = new CardFile(this.card, ":3F00");
	}
	return this.df;
}



/**
 * Calculate a single Basic Access Control (BAC) key from the second
 * line of the Machine Readable Zone (MRZ).
 *
 * The function extracts the Document Number, Date of Birth and Date of Expiration
 * from the second line of the machine readable zone
 *
 * E.g. MRZ of Silver Data Set
 *   P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<
 *   L898902C<3UTO6908061F9406236ZE184226B<<<<<14
 *   '-DocNo--'   '-DoB-' '-DoE-'
 *
 * This extract is then hashed, concatenated with a key number and
 * hashed again.
 *
 * @param {Crypto} crypto Crypto object used for hashing
 * @param {String} mrz String containing the concatenation of two MRZ lines
 * @param {Number} keyno Number of key to calculate (1 for Kenc and 2 for Kmac)
 * @type Key
 * @returns the key object
 */
EAC20.calculateBACKeyFrom2LineMRZ = function(crypto, mrz, keyno) {

	// Convert to byte string
	var strbin = new ByteString(mrz, ASCII);

	// Extract Document Number, Date of Birth and Date of Expiration
	var hash_input = strbin.bytes(44, 10);
	hash_input = hash_input.concat(strbin.bytes(57, 7));
	hash_input = hash_input.concat(strbin.bytes(65, 7));
//	print("Hash Input   : " + hash_input.toString(ASCII));

	// Hash input	
	var mrz_hash = crypto.digest(Crypto.SHA_1, hash_input);
//	print("MRZ Hash     : " + mrz_hash);

	// Extract first 16 byte and append 00000001 or 00000002
	var bb = new ByteBuffer(mrz_hash.bytes(0, 16));
	bb.append(new ByteString("000000", HEX));
	bb.append(keyno);

	// Hash again to calculate key value	
	var keyval = crypto.digest(Crypto.SHA_1, bb.toByteString());
	keyval = keyval.bytes(0, 16);
//	print("Value of Key : " + keyval);
	var key = new Key();
	key.setComponent(Key.DES, keyval);

	return key;
}



/**
 * Calculate a single Basic Access Control (BAC) key from a 3-line
 * Machine Readable Zone (MRZ).
 *
 * The function extracts the Document Number, Date of Birth and Date of Expiration
 * from the second line of the machine readable zone
 *
 * E.g. MRZ of Silver Data Set
 *   I<UTOL898902C<3<<<<<<<<<<<<<<<
 *        '-DocNo--'
 *   6908061F9406236UTO<<<<<<<<<<<1
 *   '-DoB-' '-DoE-'
 *   ERIKSON<<ANNA<MARIA<<<<<<<<<<<
 *
 * This extract is then hashed, concatenated with a key number and
 * hashed again.
 *
 * @param {Crypto} crypto Crypto object used for hashing
 * @param {String} mrz String containing the concatenation of three MRZ lines
 * @param {Number} keyno Number of key to calculate (1 for Kenc and 2 for Kmac)
 * @type Key
 * @returns the key object
 */
EAC20.calculateBACKeyFrom3LineMRZ = function(crypto, mrz, keyno) {

	// Convert to byte string
	var strbin = new ByteString(mrz, ASCII);

	// Extract Document Number, Date of Birth and Date of Expiration
	var hash_input = strbin.bytes(5, 10);
	hash_input = hash_input.concat(strbin.bytes(30, 7));
	hash_input = hash_input.concat(strbin.bytes(38, 7));
//	print("Hash Input   : " + hash_input.toString(ASCII));

	// Hash input	
	var mrz_hash = crypto.digest(Crypto.SHA_1, hash_input);
//	print("MRZ Hash     : " + mrz_hash);

	// Extract first 16 byte and append 00000001 or 00000002
	var bb = new ByteBuffer(mrz_hash.bytes(0, 16));
	bb.append(new ByteString("000000", HEX));
	bb.append(keyno);

	// Hash again to calculate key value	
	var keyval = crypto.digest(Crypto.SHA_1, bb.toByteString());
	keyval = keyval.bytes(0, 16);
//	print("Value of Key : " + keyval);
	var key = new Key();
	key.setComponent(Key.DES, keyval);

	return key;
}



/**
 * Perform BAC using the provided Kenc and Kmac values.
 *
 * @param {Key} kenc the key Kenc
 * @param {Key} kmac the key Kmac
 */
EAC20.prototype.performBACWithMRZ = function(mrz) {
	if ((mrz.length != 90) && (mrz.length != 88)) {
		throw new GPError("EAC20", GPError.INVALID_DATA, 0, "MRZ must be either 88 or 90 character long");
	}
	if (mrz.length == 90) {
		var kenc = EAC20.calculateBACKeyFrom3LineMRZ(this.crypto, mrz, 1);
		var kmac = EAC20.calculateBACKeyFrom3LineMRZ(this.crypto, mrz, 2);
		var idpicc = mrz.substr(5, 10);
	} else {
		var kenc = EAC20.calculateBACKeyFrom2LineMRZ(this.crypto, mrz, 1);
		var kmac = EAC20.calculateBACKeyFrom2LineMRZ(this.crypto, mrz, 2);
		var idpicc = mrz.substr(44, 10);
	}
	this.setIDPICC(new ByteString(idpicc, ASCII));
	this.performBAC(kenc, kmac);
}



/**
 * Perform BAC using the provided Kenc and Kmac values.
 *
 * @param {Key} kenc the key Kenc
 * @param {Key} kmac the key Kmac
 */
EAC20.prototype.performBAC = function(kenc, kmac) {

	// GET CHALLENGE
	var rndicc = this.card.sendApdu(0x00, 0x84, 0x00, 0x00, 0x08, [0x9000]);

	var rndifd = this.crypto.generateRandom(8);
	var kifd = this.crypto.generateRandom(16);

	var plain = rndifd.concat(rndicc).concat(kifd);

	var cryptogram = this.crypto.encrypt(kenc, Crypto.DES_CBC, plain, new ByteString("0000000000000000", HEX));

	var mac = this.crypto.sign(kmac, Crypto.DES_MAC_EMV, cryptogram.pad(Crypto.ISO9797_METHOD_2));

	// EXTERNAL AUTHENTICATE
	var autresp = this.card.sendApdu(0x00, 0x82, 0x00, 0x00, cryptogram.concat(mac), 0);
	
	if (this.card.SW != 0x9000) {
		print("Mutual authenticate failed with " + this.card.SW.toString(16) + " \"" + this.card.SWMSG + "\". MRZ correct ?");
		throw new GPError("EAC20", GPError.CRYPTO_FAILED, 0, "Card did not accept MAC in BAC establishment");
	}
	
	cryptogram = autresp.bytes(0, 32);
	mac = autresp.bytes(32, 8);

	if (!this.crypto.verify(kmac, Crypto.DES_MAC_EMV, cryptogram.pad(Crypto.ISO9797_METHOD_2), mac)) {
		throw new GPError("EAC20", GPError.CRYPTO_FAILED, 0, "Card MAC did not verify correctly");
	}

	plain = this.crypto.decrypt(kenc, Crypto.DES_CBC, cryptogram, new ByteString("0000000000000000", HEX));

	if (!plain.bytes(0, 8).equals(rndicc)) {
		throw new GPError("EAC20", GPError.CRYPTO_FAILED, 0, "Card response does not contain matching RND.ICC");
	}

	if (!plain.bytes(8, 8).equals(rndifd)) {
		throw new GPError("EAC20", GPError.CRYPTO_FAILED, 0, "Card response does not contain matching RND.IFD");
	}

	var kicc = plain.bytes(16, 16);
	keyinp = kicc.xor(kifd);

	var hashin = keyinp.concat(new ByteString("00000001", HEX));
	var kencval = this.crypto.digest(Crypto.SHA_1, hashin);
	kencval = kencval.bytes(0, 16);
	var kenc = new Key();
	kenc.setComponent(Key.DES, kencval);

	var hashin = keyinp.concat(new ByteString("00000002", HEX));
	var kmacval = this.crypto.digest(Crypto.SHA_1, hashin);
	kmacval = kmacval.bytes(0, 16);
	var kmac = new Key();
	kmac.setComponent(Key.DES, kmacval);

	var ssc = rndicc.bytes(4, 4).concat(rndifd.bytes(4, 4));

	this.sm = new IsoSecureChannel(crypto);
	this.sm.setEncKey(kenc);
	this.sm.setMacKey(kmac);
	this.sm.setSendSequenceCounter(ssc);

	this.df.setCredential(CardFile.ALL, Card.ALL, this.sm);
	this.card.setCredential(this.sm);
}



/**
 * Perform PACE using the indicated parameter set, the identified password, the password value and
 * an optional cardholder authentication template.
 *
 * <p>This method supports PACE version 1 and 2. For version 2, parameterId with a value between 0 and 31 denotes
 * a standardized domain parameter as defined in TR-03110 2.04 or later.</p>
 *
 * @param {Number} parameterId the identifier for the PACEInfo and PACEDomainParameterInfo from EF.CardInfo. Use 0 for
 *                             the default.
 * @param {Number} pwdid one of EAC20.ID_MRZ, EAC20.ID_CAN, EAC20.ID_PIN, EAC20.ID_PUK
 * @param {ByteString} pwd the PACE password
 * @param {ASN1} chat the CHAT data object with tag 7F4C or null
 */
EAC20.prototype.performPACE = function(parameterId, pwdid, pwd, chat) {

	var paceinfo = this.PACEInfos[parameterId];
	if (typeof(paceinfo) == "undefined") {
		throw new GPError("EAC20", GPError.INVALID_DATA, 0, "Unknown parameterId " + parameterId + " for PACEInfo");
	}
	
	var domainParameter;
	
	// Used for Chip Authentication
	this.includeDPinAuthToken = !(paceinfo.version >= 2);
	
	if ((paceinfo.version == 1) || ((paceinfo.version == 2) && (parameterId > 31))) {
		var pacedp = this.PACEDPs[parameterId];
		if (typeof(pacedp) == "undefined") {
			throw new GPError("EAC20", GPError.INVALID_DATA, 0, "Unknown parameterId " + parameterId + " for PACEDomainParameterInfo");
		}
		domainParameter = pacedp.domainParameter;
	} else {
		domainParameter = PACEDomainParameterInfo.getStandardizedDomainParameter(parameterId);
	}
	
	if (!(pwd instanceof ByteString)) {
		throw new GPError("EAC20", GPError.INVALID_TYPE, 0, "Argument pwd must be of type ByteString");
	}
	
	if ((chat != null) && !(chat instanceof ASN1)) {
		throw new GPError("EAC20", GPError.INVALID_TYPE, 0, "Argument chat must be of type ASN1");
	}

	
	var pace = new PACE(this.crypto, paceinfo.protocol, domainParameter, paceinfo.version);
	pace.setPassword(pwd);

	// Manage SE
	var crt = new ByteBuffer();
	crt.append((new ASN1(0x80, paceinfo.protocol)).getBytes());
	crt.append(new ByteString("8301", HEX));
	crt.append(pwdid);
	if (chat != null) {
		crt.append(chat.getBytes());
	}

	this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO, 0x00, 0x22, 0xC1, 0xA4, crt.toByteString(), [0x9000, 0x63C2, 0x63C1, 0x63C0, 0x6283 ]);


	// General Authenticate
	var dado = new ASN1(0x7C);

	dadobin = this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO|Card.RENC, 0x10, 0x86, 0x00, 0x00, dado.getBytes(), 0, [0x9000]);

	var dado = new ASN1(dadobin);
	assert(dado.tag == 0x7C);
	assert(dado.elements == 1);
	var encryptedNonceDO = dado.get(0);
	assert(encryptedNonceDO.tag == 0x80);
	var encryptedNonce = encryptedNonceDO.value;

	GPSystem.trace("Encrypted nonce: " + encryptedNonce);

	pace.decryptNonce(encryptedNonce);

	var mappingData = pace.getMappingData();

	var dado = new ASN1(0x7C, new ASN1(0x81, mappingData));

	dadobin = this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO|Card.RENC, 0x10, 0x86, 0x00, 0x00, dado.getBytes(), 0, [0x9000]);

	var dado = new ASN1(dadobin);
	assert(dado.tag == 0x7C);
	assert(dado.elements == 1);
	var mappingDataDO = dado.get(0);
	assert(mappingDataDO.tag == 0x82);

	pace.performMapping(mappingDataDO.value);

	var ephemeralPublicKeyIfd = pace.getEphemeralPublicKey();

	var dado = new ASN1(0x7C, new ASN1(0x83, ephemeralPublicKeyIfd));

	dadobin = this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO|Card.RENC, 0x10, 0x86, 0x00, 0x00, dado.getBytes(), 0, [0x9000]);

	var dado = new ASN1(dadobin);
	assert(dado.tag == 0x7C);
	assert(dado.elements == 1);
	var ephemeralPublicKeyICC = dado.get(0);
	assert(ephemeralPublicKeyICC.tag == 0x84);

	this.idPICC = ephemeralPublicKeyICC.value.bytes(1, (ephemeralPublicKeyICC.value.length - 1) >> 1);
	GPSystem.trace("ID_PICC : " + this.idPICC);
	
	pace.performKeyAgreement(ephemeralPublicKeyICC.value);


	var authToken = pace.calculateAuthenticationToken();

	var dado = new ASN1(0x7C, new ASN1(0x85, authToken));

	dadobin = this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO|Card.RENC, 0x00, 0x86, 0x00, 0x00, dado.getBytes(), 0, [0x9000, 0x63C2, 0x63C1, 0x63C0, 0x6283 ]);

	var dado = new ASN1(dadobin);
	GPSystem.trace(dado);
	assert(dado.tag == 0x7C);
	assert(dado.elements >= 1);
	assert(dado.elements <= 3);
	var authTokenDO = dado.get(0);
	assert(authTokenDO.tag == 0x86);

	if (dado.elements > 1) {
		var cardo = dado.get(1);
		assert(cardo.tag == 0x87);
		this.lastCAR = new PublicKeyReference(cardo.value);
	}
	
	if (dado.elements > 2) {
		var cardo = dado.get(2);
		assert(cardo.tag == 0x88);
		this.previousCAR = new PublicKeyReference(cardo.value);
	}

	var sm = null;
	
	if (pace.verifyAuthenticationToken(authTokenDO.value)) {
		GPSystem.trace("Authentication token valid");

		sm = new IsoSecureChannel(this.crypto, IsoSecureChannel.SSC_SYNC_ENC_POLICY);
		sm.setEncKey(pace.kenc);
		sm.setMacKey(pace.kmac);
		sm.setMACSendSequenceCounter(new ByteString("00000000000000000000000000000000", HEX));
		this.df.setCredential(CardFile.ALL, Card.ALL, sm);
		this.card.setCredential(sm);
	}
	this.sm = sm;
}



/**
 * Return the trust anchor's CAR as indicated by the card in the PACE protocol
 *
 * @param {boolean} previous, true to return the previous CAR, if any
 * @return the CertificationAuthorityReference (CAR)
 * @type PublicKeyReference
 */
EAC20.prototype.getTrustAnchorCAR = function(previous) {
	if (previous) {
		return this.previousCAR;
	} else {
		return this.lastCAR;
	}
}



/**
 * Submit a list of certificates to the card for verification
 *
 * @param {CVC[]} cvcchain the list of certificates, starting with link certificates, DVCA certificate and terminal certificate.
 */
EAC20.prototype.verifyCertificateChain = function(cvcchain) {
	for (var i = 0; i < cvcchain.length; i++) {
		var cvc = cvcchain[i];
		
		var car = cvc.getCAR().getBytes();
		
		var pukrefdo = new ASN1(0x83, car);
		var pukref = pukrefdo.getBytes();
		
//		print("PuKref: " + pukref);
//		print(pukref);
		this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO, 0x00, 0x22, 0x81, 0xB6, pukref, [0x9000]);
		
		// Extract value of 7F21
		var tl = new TLVList(cvc.getBytes(), TLV.EMV);
		var t = tl.index(0);
		var v = t.getValue();
		
		GPSystem.trace("Certificate: ");
		GPSystem.trace(new ASN1(v));
		this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO, 0x00, 0x2A, 0x00, 0xBE, v, [0x9000]);
	}
	
	this.terminalCHR = cvcchain[cvcchain.length - 1].getCHR();
}



/**
 * Set the ID_PICC used for terminal authentication in EAC 1.11
 *
 * @param {ByteString} id
 * @param {Key} kmac the key Kmac
 */
EAC20.prototype.setIDPICC = function(idPICC) {
	this.idPICC = idPICC;
}



/**
 * Perform terminal authentication using a given terminal key
 *
 * @param {Key} termkey the terminal private key
 * @param {ASN1} auxdata auxiliary data (tag '67') to be included in terminal authentication
 * @param {Crypto} crypto optional alternative crypto provider (e.g. for key in SmartCard-HSM)
 */
EAC20.prototype.performTerminalAuthentication = function(termkey, auxdata, crypto) {
	var signatureInput = this.performTerminalAuthenticationSetup(auxdata);
	
	if (crypto == undefined) {
		var crypto = this.crypto;
	}
	var signature = crypto.sign(termkey, Crypto.ECDSA_SHA256, signatureInput);

	GPSystem.trace("Signature (Encoded):");
	GPSystem.trace(signature);

	var keysize = termkey.getSize();
	if (keysize < 0) {
		keysize = termkey.getComponent(Key.ECC_P).length;
	} else {
		keysize >>= 3;
	}

	signature = ECCUtils.unwrapSignature(signature, keysize);
	GPSystem.trace("Signature (Encoded):");
	GPSystem.trace(signature);

	this.performTerminalAuthenticationFinal(signature);
}



/**
 * Prepare terminal authentication by setting the required security environment
 *
 * @param {ASN1} auxdata auxiliary data (tag '67') to be included in terminal authentication
 */
EAC20.prototype.performTerminalAuthenticationSetup = function(auxdata) {

	var idIFD = this.ca.getCompressedPublicKey();

	var bb = new ByteBuffer();
	
	// ToDo: Copy from root CVCA certificate
	bb.append(new ASN1(0x80, new ByteString("id-TA-ECDSA-SHA-256", OID)).getBytes());
	bb.append(new ASN1(0x83, this.terminalCHR.getBytes()).getBytes());
	if (auxdata) {
		bb.append(auxdata);
	}
	bb.append(new ASN1(0x91, idIFD).getBytes());

	var msedata = bb.toByteString();
	GPSystem.trace("Manage SE data:");
	GPSystem.trace(msedata);
	this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO, 0x00, 0x22, 0x81, 0xA4, msedata, [0x9000]);
	
	var challenge = this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO|Card.RENC, 0x00, 0x84, 0x00, 0x00, 8, [0x9000]);
	
	var bb = new ByteBuffer();
	bb.append(this.idPICC);
	bb.append(challenge);
	bb.append(idIFD);
	
	var signatureInput = bb.toByteString();
	GPSystem.trace("Signature Input:");
	GPSystem.trace(signatureInput);
	return signatureInput;
}



/**
 * Complete terminal authentication by submitting the signature to the card
 *
 * @param {ByteString} signature the signature as concatenation of r and s
 */
EAC20.prototype.performTerminalAuthenticationFinal = function(signature) {
	this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO, 0x00, 0x82, 0x00, 0x00, signature, [0x9000]);
}



/**
 * Perform chip authentication in version 1 and establish a secure channel
 *
 * @return true, if chip authentication was successfull
 * @type boolean
 */
EAC20.prototype.performChipAuthenticationV1 = function() {

	var cainfo = this.CAInfos[0];
	if (typeof(cainfo) == "undefined") {
		throw new GPError("EAC20", GPError.INVALID_DATA, 0, "Unknown keyId " + keyId + " for ChipAuthenticationInfo");
	}
	this.cainfo = cainfo;

	var domainParameter = ECCUtils.decodeECParameters(this.cAPublicKeyObject.get(1).get(0).get(1));

	this.ca = new ChipAuthentication(this.crypto, cainfo.protocol, domainParameter);

	this.ca.generateEphemeralCAKeyPair();

	var bb = new ByteBuffer();
	bb.append(new ASN1(0x91, this.ca.getEphemeralPublicKey()).getBytes());
	
	if (typeof(this.cainfo.keyId) != "undefined") {
		bb.append(new ByteString("8401", HEX));
		bb.append(this.cainfo.keyId);
	}
	
	var msedata = bb.toByteString();
	GPSystem.trace("Manage SE data:");
	GPSystem.trace(msedata);
	this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO, 0x00, 0x22, 0x41, 0xA6, msedata, [0x9000]);
	
	this.ca.performKeyAgreement(this.cAPublicKey);
	
	var sm = new IsoSecureChannel(this.crypto);
	sm.setEncKey(this.ca.kenc);
	sm.setMacKey(this.ca.kmac);
	sm.setSendSequenceCounter(new ByteString("0000000000000000", HEX));

	this.df.setCredential(CardFile.ALL, Card.ALL, sm);
	this.card.setCredential(sm);
	this.sm = sm;
}



/**
 * Prepare chip authentication by generating the ephemeral key pair
 *
 * @param {Number} keyId the key identifier to be used for chip authentication
 */
EAC20.prototype.prepareChipAuthentication = function(keyId) {
	var cainfo = this.CAInfos[keyId];
	if (typeof(cainfo) == "undefined") {
		throw new GPError("EAC20", GPError.INVALID_DATA, 0, "Unknown keyId " + keyId + " for ChipAuthenticationInfo");
	}
	this.cainfo = cainfo;
	
	var cadp = this.CADPs[keyId];
	if (typeof(cadp) == "undefined") {
		throw new GPError("EAC20", GPError.INVALID_DATA, 0, "Unknown keyId " + keyId + " for ChipAuthenticationDomainParameterInfo");
	}
	this.cadp = cadp;

	this.ca = new ChipAuthentication(this.crypto, cainfo.protocol, cadp.domainParameter);

	this.ca.includeDPinAuthToken = this.includeDPinAuthToken;
	this.ca.generateEphemeralCAKeyPair();
}



/**
 * Perform chip authentication in version 2 and establish a secure channel
 *
 * @return true, if chip authentication was successfull
 * @type boolean
 */
EAC20.prototype.performChipAuthenticationV2 = function() {

	var bb = new ByteBuffer();
	bb.append(new ASN1(0x80, this.cainfo.protocol).getBytes());
	
	if (typeof(this.cainfo.keyId) != "undefined") {
		bb.append(new ByteString("8401", HEX));
		bb.append(this.cainfo.keyId);
	}
	
	var msedata = bb.toByteString();
	GPSystem.trace("Manage SE data:");
	GPSystem.trace(msedata);
	this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO, 0x00, 0x22, 0x41, 0xA4, msedata, [0x9000]);
	
	var ephemeralPublicKeyIfd = this.ca.getEphemeralPublicKey();

	var dado = new ASN1(0x7C, new ASN1(0x80, ephemeralPublicKeyIfd));

	var dadobin = this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO|Card.RENC, 0x00, 0x86, 0x00, 0x00, dado.getBytes(), 0, [0x9000]);
	
//	print(dadobin);

	var dado = new ASN1(dadobin);
	assert(dado.tag == 0x7C);
	assert(dado.elements == 2);
	var nonceDO = dado.get(0);
	assert(nonceDO.tag == 0x81);
	var nonce = nonceDO.value;

	var authTokenDO = dado.get(1);
	assert(authTokenDO.tag == 0x82);
	var authToken = authTokenDO.value;
	
	this.ca.performKeyAgreement(this.cAPublicKey, nonce);
	
	var result = this.ca.verifyAuthenticationToken(authToken);
	
	if (result) {
		GPSystem.trace("Authentication token valid");

		if (this.ca.algo.equals(ChipAuthentication.id_CA_ECDH_3DES_CBC_CBC)) {
			var sm = new IsoSecureChannel(this.crypto);
			sm.setEncKey(this.ca.kenc);
			sm.setMacKey(this.ca.kmac);
			sm.setMACSendSequenceCounter(new ByteString("0000000000000000", HEX));
		} else {
			var sm = new IsoSecureChannel(this.crypto, IsoSecureChannel.SSC_SYNC_ENC_POLICY);
			sm.setEncKey(this.ca.kenc);
			sm.setMacKey(this.ca.kmac);
			sm.setMACSendSequenceCounter(new ByteString("00000000000000000000000000000000", HEX));
		}
		this.df.setCredential(CardFile.ALL, Card.ALL, sm);
		this.card.setCredential(sm);
		this.sm = sm;
	} else {
		GPSystem.trace("Authentication token invalid");
	}
	
	
	return result;
}



/**
 * Perform chip authentication and establish a secure channel
 *
 * @return true, if chip authentication was successfull
 * @type boolean
 */
EAC20.prototype.performChipAuthentication = function() {
	if (this.isEAC111) {
		return this.performChipAuthenticationV1();
	} else {
		return this.performChipAuthenticationV2();
	}
}



/**
 * Perform restricted identification
 *
 * @param {Number} keyId restricted identification key identifier
 * @param {ByteString} sectorPublicKey the sector public key data
 * @return the sector specific identifier
 * @type ByteString
 */
EAC20.prototype.performRestrictedIdentification = function(keyId, sectorPublicKey) {
	var bb = new ByteBuffer();
	bb.append(new ASN1(0x80, new ByteString("id-RI-ECDH-SHA-256", OID)).getBytes());
	
	bb.append(new ByteString("8401", HEX));
	bb.append(keyId);
	
	var msedata = bb.toByteString();
	GPSystem.trace("Manage SE data:");
	GPSystem.trace(msedata);
	this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO, 0x00, 0x22, 0x41, 0xA4, msedata, [0x9000]);
	
	// ToDo change to sectorPublicKey.value
	var dado = new ASN1(0x7C, new ASN1(0xA0, sectorPublicKey.bytes(5)));

//	print("GA Input: " + dado.getBytes());
	
	var dadobin = this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO|Card.RENC, 0x00, 0x86, 0x00, 0x00, dado.getBytes(), 65535, [0x9000]);
	
//	print(dadobin);

	var dado = new ASN1(dadobin);
	assert(dado.tag == 0x7C);
	assert(dado.elements == 1);
	var nonceDO = dado.get(0);
	assert((nonceDO.tag == 0x81) || (nonceDO.tag == 0x83));
	var sectorId = nonceDO.value;

//	print("Sector specific identifier: " + sectorId);
	return sectorId;
}
