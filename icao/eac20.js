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
load("restrictedidentification.js");
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

	this.PACEInfos = new Array();
	this.PACEDPs = new Array();

	this.CAInfos = new Array();
	this.CADPs = new Array();
	this.CAPublicKeys = new Array();

	this.RIInfos = new Array();
	this.maxRData = 0;
	this.maxCData = 239;		// Used for update binary
	this.useFID = false;		// Use FIDs rather than SFIs
	this.verbose = true;
	this.selectADFwithoutSM = false;	// Send SELECT ADF without SM (for applets)
}


/** PACE PWD is the hashed MRZ */
EAC20.ID_MRZ = 1;
/** PACE PWD is the CAN */
EAC20.ID_CAN = 2;
/** PACE PWD is the PIN */
EAC20.ID_PIN = 3;
/** PACE PWD is the PUK */
EAC20.ID_PUK = 4;

EAC20.AID_LDS = new ByteString("A0000002471001", HEX);
EAC20.AID_eID = new ByteString("E80704007F00070302", HEX);
EAC20.AID_eSign = new ByteString("A000000167455349474E", HEX);

EAC20.SFI_CVCA = 0x1C;
EAC20.SFI_ChipSecurity = 0x1B;
EAC20.SFI_CardAccess = 0x1C;
EAC20.SFI_CardSecurity = 0x1D;
EAC20.SFI_COM = 0x1E;


EAC20.prototype.log = function(str) {
	if (this.verbose) {
		GPSystem.trace(str);
	}
}



/**
 * Process a list of security infos from EF.CardInfo, EF.CardSecurity or EF.ChipSecurity
 * 
 * @param {ASN1} si the security info ASN Sequence
 * @param {boolean} fromCardSecurity true if security infos are taken from EF.CardSecurity, EF.ChipSecurity or EF.DG14
 */
EAC20.prototype.processSecurityInfos = function(si, fromCardSecurity) {
	this.log("SecurityInfos:");
	this.log(si);
	
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
	
	for (var i = 0; i < si.elements; i++) {
		var o = si.get(i);
		assert((o.elements >= 1) && (o.elements <= 3));

		var oid = o.get(0);
		assert(oid.tag == ASN1.OBJECT_IDENTIFIER);
		
		if (oid.value.startsWith(id_TA) == id_TA.length) {
			this.log("TA : " + o);
		} else if (oid.value.startsWith(id_PACE) == id_PACE.length) {
			if (oid.value.equals(id_PACE_DH_GM) ||
				oid.value.equals(id_PACE_ECDH_GM) ||
				oid.value.equals(id_PACE_DH_IM) ||
				oid.value.equals(id_PACE_ECDH_GM)) {
				this.log("PaceDomainParameterInfo : " + o);
				
				var pdpi = new PACEDomainParameterInfo(o);
				this.log(pdpi);
				
				var id = pdpi.parameterId;
				
				if (typeof(id) == "undefined") {
					id = 0;
				}
				
				if (!fromCardSecurity && (typeof(this.PACEDPs[id]) != "undefined")) {
					throw new GPError("EAC20", GPError.INVALID_DATA, 0, "Duplicate parameterId " + id + " for PACEDomainParameter");
				}
				
				this.PACEDPs[id] = pdpi;
			} else {
				this.log("PaceInfo : " + o);

				var pi = new PACEInfo(o);
				this.log(pi);
				
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
		} else if (oid.value.equals(id_PK_ECDH)) {
			this.log("ChipAuthenticationPublicKeyInfo : " + o);

			var capki = new ChipAuthenticationPublicKeyInfo(o);
			this.log(capki);

			var id = capki.keyId;

			if (typeof(id) == "undefined") {
				this.log("Using default key id 0");
				id = 0;
			}

			if (!fromCardSecurity && (typeof(this.CAPublicKeys[id]) != "undefined")) {
				throw new GPError("EAC20", GPError.INVALID_DATA, 0, "Duplicate keyId " + id + " for ChipAuthenticationPublicKeyInfo");
			}

			this.CAPublicKeys[id] = capki;
		} else if (oid.value.startsWith(id_CA) == id_CA.length) {
			if (oid.value.equals(id_CA_DH) ||
				oid.value.equals(id_CA_ECDH)) {
				this.log("ChipAuthenticationDomainParameterInfo : " + o);

				var cadpi = new ChipAuthenticationDomainParameterInfo(o);
				this.log(cadpi);

				var id = cadpi.keyId;

				if (typeof(id) == "undefined") {
					this.log("Using default key id 0");
					id = 0;
				}

				if (!fromCardSecurity && (typeof(this.CADPs[id]) != "undefined")) {
					throw new GPError("EAC20", GPError.INVALID_DATA, 0, "Duplicate keyId " + id + " for ChipAuthenticationDomainParameter");
				}

				this.CADPs[id] = cadpi;
			} else {
				this.log("ChipAuthenticationInfo : " + o);

				var cai = new ChipAuthenticationInfo(o);
				this.log(cai);

				var id = cai.keyId;

				if (typeof(id) == "undefined") {
					this.log("Using default key id 0");
					id = 0;
				}

				if (!fromCardSecurity && (typeof(this.CAInfos[id]) != "undefined")) {
					throw new GPError("EAC20", GPError.INVALID_DATA, 0, "Duplicate keyId " + id + " for ChipAuthenticationInfo");
				}

				this.CAInfos[id] = cai;
			}
		} else if (oid.value.startsWith(RestrictedIdentification.id_RI) == RestrictedIdentification.id_RI.length) {
			if (oid.value.equals(RestrictedIdentification.id_RI_DH) ||
				oid.value.equals(RestrictedIdentification.id_RI_ECDH)) {
				this.log("RestrictedIdentificationDomainParameterInfo : " + o);

				var ridpi = new RestrictedIdentificationDomainParameterInfo(o);
				this.log(ridpi);

				if (!fromCardSecurity && (typeof(this.RIDP) != "undefined")) {
					throw new GPError("EAC20", GPError.INVALID_DATA, 0, "Duplicate RestrictedIdentificationDomainParameter");
				this.RIDP = ridpi;
				}
			} else {
				this.log("RestrictedIdentificationInfo : " + o);

				var rii = new RestrictedIdentificationInfo(o);
				this.log(rii);

				var id = rii.keyId;
				
				if (typeof(id) == "undefined") {
					this.log("Using default key id 0");
					id = 0;
				}

				if (!fromCardSecurity && (typeof(this.RIInfos[id]) != "undefined")) {
					throw new GPError("EAC20", GPError.INVALID_DATA, 0, "Duplicate keyId " + id + " for RestrictedIdentificationInfo");
				}

				this.RIInfos[id] = rii;
			}
		}
	}
}



/**
 * Select EF using FID and read elementary file
 *
 * @param {ByteString} fid 2 byte file identifier
 * @type ByteString
 * @return the content of the EF
 */
EAC20.prototype.readEFwithFID = function(fid) {
	assert(fid.length == 2, "Length of fid must be 2 bytes");
	this.card.sendSecMsgApdu(Card.ALL, 0x00, 0xA4, 0x02, 0x0C, fid, [0x9000]);

	var bb = new ByteBuffer();
	var offset = 0;
	do	{
		var rsp = this.card.sendSecMsgApdu(Card.ALL, 0x00, 0xB0, offset >> 8, offset & 0xFF, this.maxRData);
		bb.append(rsp);
		offset += rsp.length;
	} while ((this.card.SW == 0x9000) && (rsp.length > 0));
	
	return bb.toByteString();
}



/**
 * Select EF using FID and update content
 *
 * @param {ByteString} fid 2 byte file identifier
 * @param {ByteString} data data to be written
 */
EAC20.prototype.updateEFwithFID = function(fid, data) {
	assert(fid.length == 2, "Length of fid must be 2 bytes");
	this.card.sendSecMsgApdu(Card.ALL, 0x00, 0xA4, 0x02, 0x0C, fid, [0x9000]);

	var offset = 0;
	while (offset < data.length) {
		var len = data.length - offset;
		len = this.maxCData < len ? this.maxCData : len;
		this.card.sendSecMsgApdu(Card.ALL, 0x00, 0xD6, offset >> 8, offset & 0xFF, data.bytes(offset, len), [0x9000]);
		offset += len;
	}
}



/**
 * Select and read EF using SFI
 *
 * @param {Number} short file identifier
 * @type ByteString
 * @return the content of the EF
 */
EAC20.prototype.readEFwithSFI = function(sfi) {
	assert(typeof(sfi) == "number", "Parameter must be a number");

	if (this.useFID) {
		var fid = ByteString.valueOf(0x0100 + sfi, 2);
		return this.readEFwithFID(fid);
	}
	
	var rsp = this.card.sendSecMsgApdu(Card.ALL, 0x00, 0xB0, 0x80 | sfi, 0x00, this.maxRData, [0x9000]);

	var bb = new ByteBuffer(rsp);
	var offset = bb.length;
	do	{
		var rsp = this.card.sendSecMsgApdu(Card.ALL, 0x00, 0xB0, offset >> 8, offset & 0xFF, this.maxRData);
		bb.append(rsp);
		offset += rsp.length;
	} while ((this.card.SW == 0x9000) && (rsp.length > 0));
	
	return bb.toByteString();
}



/**
 * Select EF using SFI and update content
 *
 * @param {Number} short file identifier
 * @param {ByteString} data data to be written
 */
EAC20.prototype.updateEFwithSFI = function(sfi, data) {
	assert(typeof(sfi) == "number", "Parameter must be a number");

	if (this.useFID) {
		var fid = ByteString.valueOf(0x0100 + sfi, 2);
		return this.updateEFwithFID(fid, data);
	}

	var offset = 0;
	var p1 = 0x80 | sfi;
	while (offset < data.length) {
		var len = data.length - offset;
		len = this.maxCData < len ? this.maxCData : len;
		this.card.sendSecMsgApdu(Card.ALL, 0x00, 0xD6, p1, offset & 0xFF, data.bytes(offset, len), [0x9000]);
		offset += len;
		p1 = offset >> 8;
	}
}



/**
 * Select application DF
 *
 * @param {ByteString} aid the application identifier
 */
EAC20.prototype.selectADF = function(aid) {
	if (this.selectADFwithoutSM) {
		this.card.sendApdu(0x00, 0xA4, 0x04, 0x0C, aid, [0x9000]);
	} else {
		this.card.sendSecMsgApdu(Card.ALL, 0x00, 0xA4, 0x04, 0x0C, aid, [0x9000]);
	}
}



/**
 * Select ePass LDS Application
 */
EAC20.prototype.selectLDS = function() {
	this.selectADF(EAC20.AID_LDS);
}



/**
 * Select eID Application
 */
EAC20.prototype.select_eID = function() {
	this.selectADF(EAC20.AID_eID);
}



/**
 * Select eSign Application
 */
EAC20.prototype.select_eSign = function() {
	this.selectADF(EAC20.AID_eSign);
}



/**
 * Read EF.DG14 and process security infos
 *
 */
EAC20.prototype.readDG14 = function() {
	var cibin = this.readEFwithSFI(14);
	var citlv = new ASN1(cibin);
	this.log(citlv);
	
	this.processSecurityInfos(citlv.get(0), true);
}



/**
 * Read EF.CVCA and process contained CARs
 *
 */
EAC20.prototype.readCVCA = function() {
	var cvcabin = this.readEFwithSFI(EAC20.SFI_CVCA);
	assert(cvcabin.byteAt(0) == 0x42);

	var cvca = new ASN1(cvcabin);
	this.lastCAR = new PublicKeyReference(cvca.value);

	if (cvcabin.byteAt(cvca.size) == 0x42) {
		var cvca = new ASN1(cvcabin.bytes(cvca.size));
		this.previousCAR = new PublicKeyReference(cvca.value);
	}
}



/**
 * Read EF.CardAccess and process security infos
 *
 */
EAC20.prototype.readCardAccess = function() {
	var cibin = this.readEFwithSFI(EAC20.SFI_CardAccess);
	var citlv = new ASN1(cibin);
	this.log(citlv);
	
	this.processSecurityInfos(citlv, false);
}

// Deprecated
EAC20.prototype.readCardInfo = EAC20.prototype.readCardAccess;



/**
 * Read EF.CardSecurity and process security infos
 */
EAC20.prototype.readCardSecurity = function() {
	var csbin = this.readEFwithSFI(EAC20.SFI_CardSecurity);
	var cstlv = new ASN1(csbin);
	this.log("EF.CardSecurity:");
	this.log(cstlv);

	var cms = new CMSSignedData(csbin);

	var certs = cms.getSignedDataCertificates();

	this.log("EF.CardSecurity Certificates:");
	for (var i = 0; i < certs.length; i++) {
		this.log(certs[i]);
	}

	this.log("DocSigner Signature is " + (cms.isSignerInfoSignatureValid(0) ? "valid" : "not valid"));

	var data = cms.getSignedContent();

	this.log(data);

	var cstlv = new ASN1(data);

	this.log(cstlv);
	
	this.processSecurityInfos(cstlv, true);
}



/**
 * Read EF.ChipSecurity and process security infos
 */
EAC20.prototype.readChipSecurity = function() {
	var csbin = this.readEFwithSFI(EAC20.SFI_ChipSecurity);
	var cstlv = new ASN1(csbin);
	this.log("EF.ChipSecurity:");
	this.log(cstlv);
	
	var cms = new CMSSignedData(csbin);

	var certs = cms.getSignedDataCertificates();

	this.log("EF.ChipSecurity Certificates:");
	for (var i = 0; i < certs.length; i++) {
		this.log(certs[i]);
	}

	this.log("DocSigner Signature is " + (cms.isSignerInfoSignatureValid(0) ? "valid" : "not valid"));

	var data = cms.getSignedContent();

	this.log(data);

	var cstlv = new ASN1(data);

	this.log(cstlv);

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
 * Return the key id of the chip authentication key
 *
 * @return the key id
 * @type 
 */
EAC20.prototype.getCAKeyId = function() {
	for (var i in this.CAInfos) {		// Locate first entry in list
		if (this.CAInfos[i].keyId) {
			return this.CAInfos[i].keyId;
		}
		return 0;
	}
	return 0;
}



/**
 * Return the key id of the restricted identification key
 *
 * @param {boolean} authOnly return the RI key available after authentication only (to calculate the pseudonym)
 * @return the key id
 * @type 
 */
EAC20.prototype.getRIKeyId = function(authOnly) {
	for each (var rii in this.RIInfos) {
		if (!authOnly == !rii.authorizedOnly) {
			return rii.keyId;
		}
	}
	return 0;
}



/**
 * Calculate the hash over document number, date of birth and date of expiration from 2 or 3 line MRZ
 *
 * <pre>
 * 2 line MRZ of Silver Data Set
 *   P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<
 *   L898902C<3UTO6908061F9406236ZE184226B<<<<<14
 *   '-DocNo--'   '-DoB-' '-DoE-'
 *
 * 3 line MRZ of Silver Data Set
 *   I<UTOL898902C<3<<<<<<<<<<<<<<<
 *        '-DocNo--'
 *   6908061F9406236UTO<<<<<<<<<<<1
 *   '-DoB-' '-DoE-'
 *   ERIKSON<<ANNA<MARIA<<<<<<<<<<<
 * </pre>
 *
 * @param {String} mrz 2 line or 3 line machine readable zone
 * @type ByteString
 * @return the SHA-1 hash over the concatenation of document number, date of birth and date of expiration
 */
EAC20.prototype.hashMRZ = function(mrz) {
	// Convert to byte string
	var strbin = new ByteString(mrz, ASCII);

	if (strbin.length == 88) {			// 2 line MRZ
		// Extract Document Number, Date of Birth and Date of Expiration
		var hash_input = strbin.bytes(44, 10);
		hash_input = hash_input.concat(strbin.bytes(57, 7));
		hash_input = hash_input.concat(strbin.bytes(65, 7));
	} else if (strbin.length == 90) {		// 3 line MRZ
		// Extract Document Number, Date of Birth and Date of Expiration
		var hash_input = strbin.bytes(5, 10);
		hash_input = hash_input.concat(strbin.bytes(30, 7));
		hash_input = hash_input.concat(strbin.bytes(38, 7));
	} else {
		throw new GPError("EAC20", GPError.INVALID_DATA, strbin.length, "MRZ must be either 88 or 90 character long");
	}

	this.log("Hash Input : " + hash_input.toString(ASCII));
	var mrz_hash = this.crypto.digest(Crypto.SHA_1, hash_input);
	this.log("MRZ Hash : " + mrz_hash);
	return mrz_hash;
}



/**
 * Calculate the Basic Access Control (BAC) key from the MRZ
 *
 * @param {String} mrz 2 line or 3 line machine readable zone
 * @param {Number} keyno Number of key to calculate (1 for Kenc and 2 for Kmac)
 * @type Key
 * @returns the key object
 */
EAC20.prototype.calculateBACKey = function(mrz, keyno) {
	var mrz_hash = this.hashMRZ(mrz);

	// Extract first 16 byte and append 00000001 or 00000002
	var bb = new ByteBuffer(mrz_hash.bytes(0, 16));
	bb.append(new ByteString("000000", HEX));
	bb.append(keyno);

	// Hash again to calculate key value
	var keyval = this.crypto.digest(Crypto.SHA_1, bb.toByteString());
	keyval = keyval.bytes(0, 16);
	this.log("Value of Key : " + keyval);
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
	if (mrz.length == 90) {
		var idpicc = mrz.substr(5, 10);
	} else if (mrz.length == 88) {
		var idpicc = mrz.substr(44, 10);
	} else {
		throw new GPError("EAC20", GPError.INVALID_DATA, 0, "MRZ must be either 88 or 90 character long");
	}

	this.setIDPICC(new ByteString(idpicc, ASCII));

	var kenc = this.calculateBACKey(mrz, 1);
	var kmac = this.calculateBACKey(mrz, 2);

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
		this.log("Mutual authenticate failed with " + this.card.SW.toString(16) + " \"" + this.card.SWMSG + "\". MRZ correct ?");
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

	this.sm = new IsoSecureChannel(this.crypto);
	this.sm.setEncKey(kenc);
	this.sm.setMacKey(kmac);
	this.sm.setSendSequenceCounter(ssc);

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

	this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO, 0x00, 0x22, 0xC1, 0xA4, crt.toByteString(), [0x9000, 0x63C2, 0x63C1 ]);

	// General Authenticate
	var dado = new ASN1(0x7C);

	dadobin = this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO|Card.RENC, 0x10, 0x86, 0x00, 0x00, dado.getBytes(), 0, [0x9000]);

	var dado = new ASN1(dadobin);
	assert(dado.tag == 0x7C);
	assert(dado.elements == 1);
	var encryptedNonceDO = dado.get(0);
	assert(encryptedNonceDO.tag == 0x80);
	var encryptedNonce = encryptedNonceDO.value;

	this.log("Encrypted nonce: " + encryptedNonce);

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
	this.log("ID_PICC : " + this.idPICC);
	
	pace.performKeyAgreement(ephemeralPublicKeyICC.value);


	var authToken = pace.calculateAuthenticationToken();

	var dado = new ASN1(0x7C, new ASN1(0x85, authToken));

	dadobin = this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO|Card.RENC, 0x00, 0x86, 0x00, 0x00, dado.getBytes(), 0, [0x9000, 0x63C2, 0x63C1, 0x63C0, 0x6283 ]);

	if ((this.card.SW & 0xFFF0) == 0x63C0) {
		throw new GPError("EAC20", GPError.DEVICE_ERROR, this.card.SW, "Authentication failed: " + (this.card.SW & 0xF) + " tries left");
	}

	if (this.card.SW == 0x6300) {
		throw new GPError("EAC20", GPError.DEVICE_ERROR, this.card.SW, "Authentication failed");
	}

	var dado = new ASN1(dadobin);
	this.log(dado);
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
		this.log("Authentication token valid");

		var symalgo = pace.getSymmetricAlgorithm();
		
		if (symalgo == Key.AES) {
			sm = new IsoSecureChannel(this.crypto, IsoSecureChannel.SSC_SYNC_ENC_POLICY);
			sm.setEncKey(pace.kenc);
			sm.setMacKey(pace.kmac);
			sm.setMACSendSequenceCounter(new ByteString("00000000000000000000000000000000", HEX));
		} else {
			sm = new IsoSecureChannel(this.crypto);
			sm.setEncKey(pace.kenc);
			sm.setMacKey(pace.kmac);
			sm.setMACSendSequenceCounter(new ByteString("0000000000000000", HEX));
		}
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
		
		this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO, 0x00, 0x22, 0x81, 0xB6, pukref, [0x9000]);
		
		// Extract value of 7F21
		var tl = new TLVList(cvc.getBytes(), TLV.EMV);
		var t = tl.index(0);
		var v = t.getValue();
		
		this.log("Certificate: ");
		this.log(new ASN1(v));
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
 * @param {ByteString} auxdata auxiliary data (tag '67') to be included in terminal authentication
 * @param {Crypto} crypto optional alternative crypto provider (e.g. for key in SmartCard-HSM)
 */
EAC20.prototype.performTerminalAuthentication = function(termkey, auxdata, crypto) {
	var signatureInput = this.performTerminalAuthenticationSetup(auxdata);
	
	if (crypto == undefined) {
		var crypto = this.crypto;
	}
	var signature = crypto.sign(termkey, Crypto.ECDSA_SHA256, signatureInput);

	var keysize = termkey.getSize();
	if (keysize < 0) {
		keysize = termkey.getComponent(Key.ECC_P).length;
	} else {
		keysize >>= 3;
	}

	signature = ECCUtils.unwrapSignature(signature, keysize);
	this.log("Signature (Encoded):");
	this.log(signature);

	this.performTerminalAuthenticationFinal(signature);
}



/**
 * Prepare terminal authentication by setting the required security environment
 *
 * @param {ByteString} auxdata auxiliary data (tag '67') to be included in terminal authentication
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
	this.log("Manage SE data:");
	this.log(msedata);
	this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO, 0x00, 0x22, 0x81, 0xA4, msedata, [0x9000]);
	
	var challenge = this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO|Card.RENC, 0x00, 0x84, 0x00, 0x00, 8, [0x9000]);
	
	var bb = new ByteBuffer();
	bb.append(this.idPICC);
	bb.append(challenge);
	bb.append(idIFD);
	if (auxdata) {
		bb.append(auxdata);
	}
	var signatureInput = bb.toByteString();
	this.log("Signature Input:");
	this.log(signatureInput);
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
EAC20.prototype.performChipAuthenticationV1 = function(keyid) {
	this.log("performChipAuthenticationV1() called");

	if (typeof(keyid) == "undefined") {
		keyid = 0;
	}

	var cainfo = this.CAInfos[keyid];
	if (typeof(cainfo) == "undefined") {
		throw new GPError("EAC20", GPError.INVALID_DATA, 0, "Unknown keyId " + keyId + " for ChipAuthenticationInfo");
	}

	var capuk = this.CAPublicKeys[keyid];
	if (typeof(capuk) == "undefined") {
		throw new GPError("EAC20", GPError.INVALID_DATA, 0, "Unknown keyId " + keyId + " for ChipAuthenticationPublicKeyInfo");
	}

	var domainParameter = capuk.domainParameter;

	this.ca = new ChipAuthentication(this.crypto, cainfo.protocol, domainParameter);

	this.ca.generateEphemeralCAKeyPair();

	var bb = new ByteBuffer();
	bb.append(new ASN1(0x91, this.ca.getEphemeralPublicKey()).getBytes());

	if (typeof(cainfo.keyId) != "undefined") {
		bb.append(new ByteString("8401", HEX));
		bb.append(cainfo.keyId);
	}

	var msedata = bb.toByteString();
	this.log("Manage SE data:");
	this.log(msedata);
	this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO, 0x00, 0x22, 0x41, 0xA6, msedata, [0x9000]);

	this.ca.performKeyAgreement(capuk.publicKey);

	this.log("Create DES based secure channel");
	var sm = new IsoSecureChannel(this.crypto);
	sm.setEncKey(this.ca.kenc);
	sm.setMacKey(this.ca.kmac);
	sm.setSendSequenceCounter(new ByteString("0000000000000000", HEX));

	this.card.setCredential(sm);
	this.sm = sm;
}



/**
 * Prepare chip authentication by generating the ephemeral key pair
 *
 * @param {Number} keyId the key identifier to be used for chip authentication
 */
EAC20.prototype.prepareChipAuthentication = function(keyId) {
	this.log("prepareChipAuthentication() called");

	this.cakeyId = keyId;

	var cainfo = this.CAInfos[keyId];
	if (typeof(cainfo) == "undefined") {
		throw new GPError("EAC20", GPError.INVALID_DATA, 0, "Unknown keyId " + keyId + " for ChipAuthenticationInfo");
	}

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
	this.log("performChipAuthenticationV2() called");

	var cainfo = this.CAInfos[this.cakeyId];
	if (typeof(cainfo) == "undefined") {
		throw new GPError("EAC20", GPError.INVALID_DATA, 0, "Unknown keyId " + this.cakeyId + " for ChipAuthenticationInfo");
	}

	if (this.ca.algo != cainfo.protocol) {
		this.log("Special handling for ChipAuthenticationInfo in EF.CardSecurity overwriting ChipAuthenticationInfo in EF.CardAccess");
		this.log("Protocol in EF.CardAccess: " + this.ca.algo);
		this.log("Protocol is EF.CardSecurity: " + cainfo.protocol);
		this.ca.algo = cainfo.protocol;
	}
	
	var capuk = this.CAPublicKeys[this.cakeyId];
	if (typeof(capuk) == "undefined") {
		throw new GPError("EAC20", GPError.INVALID_DATA, 0, "Unknown keyId " + this.cakeyId + " for ChipAuthenticationPublicKeyInfo");
	}

	var bb = new ByteBuffer();
	bb.append(new ASN1(0x80, cainfo.protocol).getBytes());
	
	if (typeof(cainfo.keyId) != "undefined") {
		bb.append(new ByteString("8401", HEX));
		bb.append(cainfo.keyId);
	}
	
	var msedata = bb.toByteString();
	this.log("Manage SE data:");
	this.log(msedata);
	this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO, 0x00, 0x22, 0x41, 0xA4, msedata, [0x9000]);
	
	var ephemeralPublicKeyIfd = this.ca.getEphemeralPublicKey();

	var dado = new ASN1(0x7C, new ASN1(0x80, ephemeralPublicKeyIfd));

	var dadobin = this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO|Card.RENC, 0x00, 0x86, 0x00, 0x00, dado.getBytes(), 0, [0x9000]);
	
	this.log(dadobin);

	var dado = new ASN1(dadobin);
	assert(dado.tag == 0x7C);
	assert(dado.elements == 2);
	var nonceDO = dado.get(0);
	assert(nonceDO.tag == 0x81);
	var nonce = nonceDO.value;

	var authTokenDO = dado.get(1);
	assert(authTokenDO.tag == 0x82);
	var authToken = authTokenDO.value;

	this.ca.performKeyAgreement(capuk.publicKey, nonce);

	var result = this.ca.verifyAuthenticationToken(authToken);

	if (result) {
		this.log("Authentication token valid");

		if (this.ca.algo.equals(ChipAuthentication.id_CA_ECDH_3DES_CBC_CBC)) {
			this.log("Create DES based secure channel");
			var sm = new IsoSecureChannel(this.crypto);
			sm.setEncKey(this.ca.kenc);
			sm.setMacKey(this.ca.kmac);
			sm.setMACSendSequenceCounter(new ByteString("0000000000000000", HEX));
		} else {
			this.log("Create AES based secure channel");
			var sm = new IsoSecureChannel(this.crypto, IsoSecureChannel.SSC_SYNC_ENC_POLICY);
			sm.setEncKey(this.ca.kenc);
			sm.setMacKey(this.ca.kmac);
			sm.setMACSendSequenceCounter(new ByteString("00000000000000000000000000000000", HEX));
		}
		this.card.setCredential(sm);
		this.sm = sm;
	} else {
		this.log("Authentication token invalid");
	}
	
	return result;
}



/**
 * Verify authenticated auxiliary data
 *
 * @param {ByteString} oid the object identifier for the auxiliary data provided during terminal authentication
 * @return true, if auxiliary data was verified
 * @type boolean
 */
EAC20.prototype.verifyAuxiliaryData = function(oid) {
	var o = new ASN1(ASN1.OBJECT_IDENTIFIER, oid);
	this.card.sendSecMsgApdu(Card.ALL, 0x80, 0x20, 0x80, 0x00, o.getBytes(), [0x9000,0x6300]);
	return this.card.SW == 0x9000;
}



/**
 * Perform chip authentication and establish a secure channel
 *
 * @param {Number} keyid the key identifier (only required for ChipAuthentication in version 1)
 * @return true, if chip authentication was successfull
 * @type boolean
 */
EAC20.prototype.performChipAuthentication = function(keyid) {
	if (typeof(this.cakeyId) != "undefined") {
		return this.performChipAuthenticationV2();
	} else {
		return this.performChipAuthenticationV1(keyid);
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
	this.log("Manage SE data:");
	this.log(msedata);
	this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO, 0x00, 0x22, 0x41, 0xA4, msedata, [0x9000]);
	
	// ToDo change to sectorPublicKey.value
	var dado = new ASN1(0x7C, new ASN1(0xA0, sectorPublicKey.bytes(5)));

	this.log("GA Input: " + dado.getBytes());
	
	var dadobin = this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO|Card.RENC, 0x00, 0x86, 0x00, 0x00, dado.getBytes(), 65535, [0x9000]);
	
	this.log(dadobin);

	var dado = new ASN1(dadobin);
	assert(dado.tag == 0x7C);
	assert(dado.elements == 1);
	var nonceDO = dado.get(0);
	assert((nonceDO.tag == 0x81) || (nonceDO.tag == 0x83));
	var sectorId = nonceDO.value;

	this.log("Sector specific identifier: " + sectorId);
	return sectorId;
}
