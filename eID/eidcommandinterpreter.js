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
 * @fileoverview Implementation of an eID specific command interpreter
 */

load("../cardsim/commandinterpreter.js");
load("../icao/pace.js");
load("tools/eccutils.js");


/**
 * Create a command interpreter
 *
 * @class Class implementing a command interpreter that handles ISO 7816-4 command APDUs
 * @constructor
 * @param {FileSelector} fileSelector the file selector object
 */
function eIDCommandInterpreter(fileSelector) {
	CommandInterpreter.call(this, fileSelector);

	this.pacedp = new Key();
	this.pacedp.setComponent(Key.ECC_CURVE_OID, new ByteString("1.3.36.3.3.2.8.1.1.7", OID));
	this.challenge = null;
	this.crypto = new Crypto();
	this.trustedDVCA = null;
	this.trustedTerminal = null;
	this.effectiveRights = null;
	this.lastINS = 0;
}


// Inherit from CommandInterpreter
eIDCommandInterpreter.prototype = new CommandInterpreter();
eIDCommandInterpreter.constructor = eIDCommandInterpreter;



/**
 * Determine if the terminal has been authenticated
 *
 * @type boolean
 * @return true if authenticated
 */
eIDCommandInterpreter.prototype.isAuthenticatedTerminal = function() {
	return (this.effectiveRights != null);
}



/**
 * Return terminal role from CHAT
 * @type ByteString
 * @return the object identifier value
 */
eIDCommandInterpreter.prototype.getTerminalRole = function() {
	if (this.isAuthenticatedTerminal()) {
		return this.trustedTerminal.getCHAT().get(0).value;
	}
}



/**
 * Determine the current date
 *
 * @type Date
 * @return the current Date
 */
eIDCommandInterpreter.prototype.getDate = function() {
	var dateobj = this.fileSelector.getMeta("currentDate");
//	print("getDate() = " + dateobj.currentDate);
	return dateobj.currentDate;
}



/**
 * Set the current date
 *
 * @param {Date} date the new date
 */
eIDCommandInterpreter.prototype.setDate = function(date) {
	var dateobj = this.fileSelector.getMeta("currentDate");
//	print("setDate() = " + date);
	dateobj.currentDate = date;
}



/**
 * Update EF.CVCA to indicate new trust anchor for id-IS
 *
 * @param {Date} date the new date
 */
eIDCommandInterpreter.prototype.updateEFCVCA = function(content) {
	var ef = this.fileSelector.getMeta("efCVCA");
	ef.content = content;
//	print(ef.content);
}



/**
 * Process GENERAL AUTHENTICATE command
 *
 * @param {APDU} the apdu
 */
eIDCommandInterpreter.prototype.generalAuthenticate = function(apdu) {
	var a = new ASN1(apdu.getCData());

	if (a.tag != 0x7C)
		throw new GPError("EACSIM", GPError.INVALID_DATA, 0, "Body must contain data element 0x7C");

	if (a.elements > 0) {
		var ddtag = a.get(0).tag;
		if (ddtag == 0x80) {
			this.performChipAuthenticationV2(apdu);
			return;
		}
		if ((ddtag == 0xA0) || (ddtag == 0xA2)) {
			this.performRestrictedIdentification(apdu);
			return;
		}
	}

	this.performPACE(apdu);
}



/**
 * Process GENERAL AUTHENTICATE command to perform PACE
 *
 * @param {APDU} the apdu
 */
eIDCommandInterpreter.prototype.performPACE = function(apdu) {

	var a = new ASN1(apdu.getCData());
	var response = new ASN1(0x7C);

	if (a.elements == 0) {		// 1st General Authenticate
		if (!apdu.isChained()) {
			throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Command must be chained");
		}
		
		var se = this.fileSelector.getSecurityEnvironment().VEXK;

		if (!se.t.AT) {
			throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Security environment not set");
		}

//		print(se);

		var protocol = se.t.AT.find(0x80);
		if (!protocol) {
			throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "No protocol defined in security environment");
		}
		var protocol = protocol.value;
//		print("Protocol: " + protocol);

		var keyid = se.t.AT.find(0x83);
		if (!keyid) {
			throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "No key id defined in security environment");
		}
		var keyid = keyid.value.toUnsigned();
//		print("KeyID: " + keyid);

		var chat = se.t.AT.find(0x7F4C);
		this.chat = chat;

		this.paceao = this.fileSelector.getObject(AuthenticationObject.TYPE_PACE, keyid);
		if (!this.paceao) {
			throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "PACE password not found");
		}

		if (this.paceao.isBlocked()) {
			throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_AUTHMETHLOCKED, "PACE password blocked");
		}

		if (this.paceao.isSuspended()) {
			if (!this.fileSelector.isAuthenticated(true, this.paceao.unsuspendAuthenticationObject)) {
				throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "PACE password suspended");
			}
		}

		this.paceao.decreaseRetryCounter();

		var paceInfo = this.fileSelector.getMeta("paceInfo");
		assert(paceInfo, "paceInfo must be defined in meta data");

		this.pace = new PACE(this.crypto, protocol, this.pacedp, paceInfo.version);
		this.pace.setPassword(this.paceao.value);
		var encnonce = this.pace.getEncryptedNonce();
		response.add(new ASN1(0x80, encnonce));
	} else {
		if (!this.pace)
			throw new GPError("EACSIM", GPError.INVALID_MECH, APDU.SW_CONDOFUSENOTSAT, "PACE must have been initialized");

		if (a.elements != 1)
			throw new GPError("EACSIM", GPError.INVALID_DATA, APDU.SW_INVDATA, "Dynamic Authentication Data may only contain 1 element");

		a = a.get(0);

		switch(a.tag) {
		case 0x81:
			if (!apdu.isChained())
				throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Command must be chained");

			if ((this.lastINS != APDU.INS_GENERAL_AUTHENTICATE) || !this.pace.hasNonce())
				throw new GPError("EACSIM", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Invalid sequence. First GA missing");
			
			if (this.pace.hasMapping())
				throw new GPError("EACSIM", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Invalid sequence. Steps was already performed");

			if (a.value.byteAt(0) != 0x04) 
				throw new GPError("EACSIM", GPError.INVALID_DATA, APDU.SW_INVDATA, "Public key does not start with '04'");

			var mappingData = this.pace.getMappingData();
			response.add(new ASN1(0x82, mappingData));

			this.pace.performMapping(a.value);
			break;
		case 0x83:
			if (!apdu.isChained())
				throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Command must be chained");
			
			if ((this.lastINS != APDU.INS_GENERAL_AUTHENTICATE) || (!this.pace.hasMapping()))
				throw new GPError("EACSIM", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Invalid sequence. Second GA missing");
			
			if (a.value.byteAt(0) != 0x04) 
				throw new GPError("EACSIM", GPError.INVALID_DATA, APDU.SW_INVDATA, "Public key does not start with '04'");
			
			var ephKey = this.pace.getEphemeralPublicKey();
			response.add(new ASN1(0x84, ephKey));

			// Store idPICC for later terminal authentication
			this.idPICC = ephKey.bytes(1, (ephKey.length - 1) >> 1);

			this.pace.performKeyAgreement(a.value);
			break;
		case 0x85:
			if (apdu.isChained())
				throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_LASTCMDEXPECTED, "Last PACE command must not be chained");
			
			if (this.lastINS != APDU.INS_GENERAL_AUTHENTICATE)
				throw new GPError("EACSIM", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Invalid sequence. Second GA missing");

			if (!this.pace.verifyAuthenticationToken(a.value)) {
				var sw = APDU.SW_WARNINGNVCHG;
				if (this.paceao.initialretrycounter) {
					sw |= 0xC0 + this.paceao.retrycounter;
				}
				throw new GPError("EACSIM", GPError.INVALID_DATA, sw, "Verification of authentication token failed");
			}

			this.paceao.restoreRetryCounter();
			this.fileSelector.addAuthenticationState(true, this.paceao);
//			print(this.fileSelector);
//			print(this.fileSelector.isAuthenticated(true, this.paceao));

			var authToken = this.pace.calculateAuthenticationToken();

			response.add(new ASN1(0x86, authToken));
			if (this.chat) {
				var pkiid = this.chat.get(0).value.right(1).toUnsigned();
				var anchor = this.fileSelector.getObject(TrustAnchor.TYPE, pkiid);
				if (!anchor) {
					throw new GPError("EACSIM", GPError.INVALID_DATA, 0, "Invalid PKI in chat");
				}
				anchor.addCARforPACE(response);
			}

			var symalgo = this.pace.getSymmetricAlgorithm();

			if (symalgo == Key.AES) {
				var sm = new SecureChannel(this.crypto);
				sm.setSendSequenceCounterPolicy(IsoSecureChannel.SSC_SYNC_ENC_POLICY);
				sm.setMacKey(this.pace.kmac);
				sm.setEncKey(this.pace.kenc);
				sm.setMACSendSequenceCounter(new ByteString("00000000000000000000000000000000", HEX));
			} else {
				var sm = new SecureChannel(this.crypto);
				sm.setMacKey(this.pace.kmac);
				sm.setEncKey(this.pace.kenc);
				sm.setMACSendSequenceCounter(new ByteString("0000000000000000", HEX));
			}
			this.setSecureChannel(sm);

			break;
		default:
			throw new GPError("EACSIM", GPError.INVALID_DATA, 0, "Unsupported Dynamic Authentication Data");
		}
	}

	apdu.setRData(response.getBytes());
	apdu.setSW(APDU.SW_OK);
}



/**
 * Intercept MANAGE SE for PACE to determine status of PIN
 *
 * @param {APDU} the apdu
 */
eIDCommandInterpreter.prototype.determinePINStatus = function(apdu) {
	var tlv = new ASN1(apdu.getP2(), apdu.getCData());
	tlv = new ASN1(tlv.getBytes());		// Dirty trick to deserialize as TLV tree
	var keyref = tlv.find(0x83);
	if (!keyref) {
		return;
	}
	
	var paceao = this.fileSelector.getObject(AuthenticationObject.TYPE_PACE, keyref.value.toUnsigned());
	if (!paceao) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "PACE password not found");
	}
	if (!paceao.isActive) {
		apdu.setSW(APDU.SW_INVFILE);
	} else {
		if (paceao.initialretrycounter) {
			if (paceao.retrycounter != paceao.initialretrycounter) {
				apdu.setSW(APDU.SW_WARNINGCOUNT + paceao.retrycounter);
			}
		}
	}
}



/**
 * Process GENERAL AUTHENTICATE command to perform chip authentication in version 1
 *
 * @param {APDU} the apdu
 */
eIDCommandInterpreter.prototype.performChipAuthenticationV1 = function(apdu) {

	var a = new ASN1(0x30, apdu.getCData());
	a = new ASN1(a.getBytes());

	if ((a.elements == 0) || (a.elements > 2)) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Command data must contain 1..2 TLV elements");
	}

	if (a.get(0).tag != 0x91) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Public key data elements must have tag '91'");
	}

	var chipAuthenticationInfo = this.fileSelector.getMeta("chipAuthenticationInfo");
	var chipAuthenticationPublicKey = this.fileSelector.getMeta("chipAuthenticationPublicKey");
	var chipAuthenticationPrivateKey = this.fileSelector.getMeta("chipAuthenticationPrivateKey");

	assert(chipAuthenticationInfo);
	assert(chipAuthenticationPublicKey);
	assert(chipAuthenticationPrivateKey);

	// ToDo: Select key based on MSE SET
	var ca = new ChipAuthentication(this.crypto, chipAuthenticationInfo.protocol, chipAuthenticationPublicKey);

	ca.setKeyPair(chipAuthenticationPrivateKey, chipAuthenticationPublicKey);

	var puk = a.get(0).value;
	ca.performKeyAgreement(puk);

	this.idIFD = puk.bytes(1).left(puk.length >> 1);

	var sm = new SecureChannel(this.crypto);
	sm.setMacKey(ca.kmac);
	sm.setEncKey(ca.kenc);
	sm.setMACSendSequenceCounter(new ByteString("0000000000000000", HEX));
	this.setSecureChannel(sm);

	apdu.setSW(APDU.SW_OK);
}



/**
 * Process GENERAL AUTHENTICATE command to perform chip authentication in version 2
 *
 * @param {APDU} the apdu
 */
eIDCommandInterpreter.prototype.performChipAuthenticationV2 = function(apdu) {

	if (apdu.isChained()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CHAINNOTSUPPORTED, "Chaining not supported in GENERAL AUTHENTICATE for chip authentication");
	}

	var a = new ASN1(apdu.getCData());
	var response = new ASN1(0x7C);

	var chipAuthenticationInfo = this.fileSelector.getMeta("groupChipAuthenticationInfo");
	var chipAuthenticationPublicKey = this.fileSelector.getMeta("groupChipAuthenticationPublicKey");
	var chipAuthenticationPrivateKey = this.fileSelector.getMeta("groupChipAuthenticationPrivateKey");

	assert(chipAuthenticationInfo);
	assert(chipAuthenticationPublicKey);
	assert(chipAuthenticationPrivateKey);

	var uniqueChipAuthenticationInfo = this.fileSelector.getMeta("uniqueChipAuthenticationInfo");
	var uniqueChipAuthenticationPublicKey = this.fileSelector.getMeta("uniqueChipAuthenticationPublicKey");
	var uniqueChipAuthenticationPrivateKey = this.fileSelector.getMeta("uniqueChipAuthenticationPrivateKey");

	var se = this.fileSelector.getSecurityEnvironment().CDIK;

	if (!se.t.AT) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "No security environment found");
	}

	var keyref = se.t.AT.find(0x84);
	if (keyref) {
		var uniqueChipAuthenticationInfo = this.fileSelector.getMeta("uniqueChipAuthenticationInfo");
		if (uniqueChipAuthenticationInfo && (uniqueChipAuthenticationInfo.keyId == keyref.value.toUnsigned())) {
			var ac = this.fileSelector.getMeta("accessController");

			if (ac && !ac.checkRight(this, apdu, 3)) {
				throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_SECSTATNOTSAT, "No privileged terminal right to access unique chip authentication key");
			}

			chipAuthenticationInfo = uniqueChipAuthenticationInfo;
			chipAuthenticationPublicKey = this.fileSelector.getMeta("uniqueChipAuthenticationPublicKey");
			chipAuthenticationPrivateKey = this.fileSelector.getMeta("uniqueChipAuthenticationPrivateKey");
		} else {
			if (chipAuthenticationInfo.keyId && (keyref.value.toUnsigned() != chipAuthenticationInfo.keyId)) {
				throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "Key id " + keyref.value.toUnsigned() + " does not match a chip authentication key");
			}
		}
	}

	// Extract idIFD and make sure it's the same used in TA
	var idIFD = a.get(0).value.bytes(1);		// Skip '04' and extract public key
	idIFD = idIFD.left(idIFD.length >> 1);

	if (!idIFD.equals(this.idIFD)) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Terminal public key does not match key signed in terminal authentication");
	}

	var ca = new ChipAuthentication(this.crypto, chipAuthenticationInfo.protocol, chipAuthenticationPublicKey);

	ca.setKeyPair(chipAuthenticationPrivateKey, chipAuthenticationPublicKey);

	var nonce = this.crypto.generateRandom(8);

	ca.performKeyAgreement(a.get(0).value, nonce);
	var token = ca.calculateAuthenticationToken();

	response.add(new ASN1(0x81, nonce));
	response.add(new ASN1(0x82, token));

	apdu.setRData(response.getBytes());
	
	if (ca.algo.equals(ChipAuthentication.id_CA_ECDH_3DES_CBC_CBC)) {
//		print("DES");
		var sm = new SecureChannel(this.crypto);
		sm.setMacKey(ca.kmac);
		sm.setEncKey(ca.kenc);
		sm.setMACSendSequenceCounter(new ByteString("0000000000000000", HEX));
	} else {
//		print("AES");
		var sm = new SecureChannel(this.crypto);
		sm.setSendSequenceCounterPolicy(IsoSecureChannel.SSC_SYNC_ENC_POLICY);
		sm.setMacKey(ca.kmac);
		sm.setEncKey(ca.kenc);
		sm.setMACSendSequenceCounter(new ByteString("00000000000000000000000000000000", HEX));
	}
	this.setSecureChannel(sm);

	apdu.setSW(APDU.SW_OK);
}



/**
 * Locate public key either in trust anchor, trusted DVCA or trusted terminal
 *
 * @param {PublicKeyReference} keyid the public key reference to look for
 * @type object
 * @return object with properties level (issuer is 0-CVCA, 1-DVCA or 2-Terminal) and anchor (Trust Anchor)
 */
eIDCommandInterpreter.prototype.locatePublicKey = function(keyid) {
	var idlist = this.fileSelector.enumerateObjects(TrustAnchor.TYPE);
//	print(idlist);

	for each (var i in idlist) {
		var anchor = this.fileSelector.getObject(TrustAnchor.TYPE, i);
//		print(anchor.root.getCHR().toString());
		if (anchor.isIssuer(keyid)) {
			return { level: 0, anchor: anchor };
		}
	}

	if (this.trustedDVCA && (this.trustedDVCA.getCHR().equals(keyid))) {
		var r = this.locatePublicKey(this.trustedDVCA.getCAR());
		r.level = 1;
		return r;
	}

	if (this.trustedTerminal && (this.trustedTerminal.getCHR().equals(keyid))) {
		var r = this.locatePublicKey(this.trustedDVCA.getCAR());
		r.level = 2;
		return r;
	}
	return null;
}



/**
 * Process PSO VERIFY CERTIFICATE command
 *
 * @param {APDU} the apdu
 */
eIDCommandInterpreter.prototype.verifyCertificate = function(apdu) {

	if (apdu.isChained()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CHAINNOTSUPPORTED, "Chaining not supported in PSO VERIFY CERTIFICATE");
	}
	
	if (!apdu.hasCData()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Command data expected in PSO VERIFY CERTIFICATE");
	}
	
	if ((apdu.getP1() != 0x00) || (apdu.getP2() != 0xBE)) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INCP1P2, "Invalid P1 or P2");
	}

	// Reconstruct CVC
	var a = new ASN1(0x7F21, apdu.getCData());
	try	{
		a = new ASN1(a.getBytes());
	}
	catch(e) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Invalid certificate format");
	}

	// Do some basic format checking
	if ((a.elements != 2) || (a.get(0).tag != 0x7F4e) || (a.get(1).tag != 0x5F37)) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Invalid certificate format");
	}

	var cvc = new CVC(a);

//	print(cvc);

	// Determine public key for checking CVC signature
	var se = this.fileSelector.getSecurityEnvironment().VEXK;
//	print(se);

	if (!se.t.DST) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "No public key set in MANAGE SE for verification");
	}

	var keyref = se.t.DST.find(0x83);
	if (!keyref) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "No public key set in MANAGE SE for verification");
	}

	var keyid = new PublicKeyReference(keyref.value);
//	print("KeyID: " + keyid);

	var rc = this.locatePublicKey(keyid);
	if (rc == null) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "Referenced public key " + keyid + " not found");
	}

	var anchor = rc.anchor;
//	print(anchor);
//	print(rc.level);
	
	switch(rc.level) {
		case 0:
			anchor.validateCertificateIssuedByCVCA(this.crypto, cvc, this);

			var chat = cvc.getCHAT();
			var certtype = chat.get(1).value.byteAt(0) & 0xC0;

			if ((certtype == 0x80) || (certtype == 0x40)) {
				this.trustedDVCA = cvc;
			}
			break;
		case 1:
			anchor.validateCertificateIssuedByDVCA(this.crypto, cvc, this.trustedDVCA, this);
			this.trustedTerminal = cvc;
			break;
		default:
			throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Referenced public key " + keyid + " is a terminal key");
	}

	apdu.setSW(APDU.SW_OK);
}



/**
 * Process EXTERNAL AUTHENTICATE command to perform terminal authentication
 *
 * @param {APDU} the apdu
 * @param {SecurityEnvironment} se the security environment for external authentication
 */
eIDCommandInterpreter.prototype.externalAuthenticateForTA = function(apdu, se) {
	if (apdu.isChained()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CHAINNOTSUPPORTED, "Chaining not supported in EXTERNAL AUTHENTICATE");
	}

	if (!apdu.hasCData()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Command data expected in EXTERNAL AUTHENTICATE");
	}

	if ((apdu.getP1() != 0x00) || (apdu.getP2() != 0x00)) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INCP1P2, "Invalid P1 or P2");
	}

	if (!apdu.isSecureMessaging()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Terminal authentication can only be performed with secure messaging");
	}

	if (this.isAuthenticatedTerminal()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Terminal authentication can only be performed once in a session");
	}

	if (!this.challenge) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Must obtain challenge before external authenticate");
	}

	if (this.challenge.length < 8) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Challenge must be larger or equal 8 bytes");
	}

	// Invalidate challenge
	var challenge = this.challenge;
	this.challenge = null;

	if (this.trustedTerminal == null) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "No terminal certificate found");
	}

	if (this.chat) {
		var tchat = this.trustedTerminal.getCHAT();
		if (!tchat.get(0).value.equals(this.chat.get(0).value)) {
			throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "CHAT in terminal certificate does not match CHAT in PACE");
		}
		if (tchat.get(1).value.length != this.chat.get(1).value.length) {
			throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "CHAT in terminal certificate has different length than CHAT in PACE");
		}
	}

	var keyref = se.t.AT.find(0x83);
	if (!keyref) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "No public key set in MANAGE SE for terminal authentication");
	}

	var keyid = new PublicKeyReference(keyref.value);
//	print("KeyID: " + keyid);

	var rc = this.locatePublicKey(keyid);
	if (rc == null) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "Referenced public key " + keyid + " not found");
	}

	if (rc.level != 2) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "Referenced public key is not a terminal key");
	}

	var dp = rc.anchor.getPublicKeyFor(this.trustedDVCA.getCAR());
	var puk = this.trustedTerminal.getPublicKey(dp);

	if (typeof(this.idIFD) == "undefined") {			// CA not already performed ? Then we do EAC 2.x
		var cakey = se.t.AT.find(0x91);
		if (!cakey) {
			throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "No chip authentication ephemeral key found");
		}
		this.idIFD = cakey.value;
	}

	if (typeof(this.idPICC) == "undefined") {
		this.idPICC = this.fileSelector.getMeta("idPICC");
	}

	var bb = new ByteBuffer();
	bb.append(this.idPICC);
	bb.append(challenge);
	bb.append(this.idIFD);

	var auxdata = se.t.AT.find(0x67);

	if (auxdata) {
		bb.append(auxdata.getBytes());
	}
	var signatureInput = bb.toByteString();

	var signature = ECCUtils.wrapSignature(apdu.getCData());
	var mech = CVC.getSignatureMech(this.trustedTerminal.getPublicKeyOID(dp));
	if (!this.crypto.verify(puk, mech, signatureInput, signature)) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_WARNINGNVCHG, "Verification of terminal authentication signature failed");
	}

	// Determine effective rights
	var cvc = rc.anchor.getCertificateFor(this.trustedDVCA.getCAR());
	var er = cvc.getCHAT().get(1).value;

	er = er.and(this.trustedDVCA.getCHAT().get(1).value);
	er = er.and(this.trustedTerminal.getCHAT().get(1).value);

	if (this.chat) {
		er = er.and(this.chat.get(1).value);
	}

//	print("Effective rights : " + er);
	this.effectiveRights = er;

	apdu.setSW(APDU.SW_OK);
}



/**
 * Process GENERAL AUTHENTICATE command to perform restricted identification
 *
 * @param {APDU} the apdu
 */
eIDCommandInterpreter.prototype.performRestrictedIdentification = function(apdu) {
	if (apdu.isChained()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CHAINNOTSUPPORTED, "Chaining not supported in GENERAL AUTHENTICATE for chip authentication");
	}

	if (!apdu.hasLe()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Wrong length - missing Le field");
	}

	if (apdu.isChained()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CHAINNOTSUPPORTED, "Chaining not supported in ");
	}

	var rikeys = this.fileSelector.getMeta("RIKeys");
	assert(rikeys, "No RI keys defined im meta data");

	var se = this.fileSelector.getSecurityEnvironment().CDIK;
//	print(se);

	var keyid = 0;
	if (se.t.AT) {
		var keyref = se.t.AT.find(0x84);
		if (keyref) {
			keyid = keyref.value.toUnsigned();
		}
	}

	if (!rikeys[keyid]) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "Restricted identification key not found");
	}

	var ri = rikeys[keyid];
	GPSystem.trace("Selected key " + keyid + " for restricted identification(authorizedOnly=" + (ri.authorizedOnly ? "true" : "false") + ")");

	var ac = this.fileSelector.getMeta("accessController");

	if (ac && ri.authorizedOnly) {
		if (!ac.checkRight(this, apdu, 2)) {
			throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_SECSTATNOTSAT, "Restricted identification requires right in id-AT");
		}
	}

	var a = new ASN1(apdu.getCData());
	var rido = a.get(0);
	
	var response = new ASN1(0x7C);

	var pk = new ASN1(0x7F49, rido.value);
	pk = new ASN1(pk.getBytes());		// Rebuild tree after replacing tag

//	print(pk);
	var mech = CVC.getHashMech(this.trustedDVCA.getPublicKeyOID());
	var hash = this.crypto.digest(mech, pk.getBytes());
//	print(hash);

	var ext = this.trustedTerminal.getExtension(new ByteString("id-sector", OID));
	if (!ext) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "Terminal certificate does not contain a sector-id");
	}

	if (rido.tag == 0xA0) {
		var stag = 0x80;
		var rtag = 0x81;
	} else if (rido.tag == 0xA2) {
		var stag = 0x81;
		var rtag = 0x83;
	} else {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Dynamic data for restricted identification requires either 'A0' or 'A2' data element");
	}

	var hashdo = ext.find(stag);
	if (!hashdo) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "Sector-id extension does not contain a hash value");
	}

	if (!hashdo.value.equals(hash)) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Sector-id does not match provided public key");
	}

	var sectorPuK = new Key();
	sectorPuK.setType(Key.PUBLIC);
	CVC.decodeECPublicKey(pk, sectorPuK);

	var inp = sectorPuK.getComponent(Key.ECC_QX).concat(sectorPuK.getComponent(Key.ECC_QY));
	var id = this.crypto.digest(mech, this.crypto.decrypt(ri.prk, Crypto.ECDH, inp));

	response.add(new ASN1(rtag, id));

	apdu.setRData(response.getBytes());
	apdu.setSW(APDU.SW_OK);
}



/**
 * Process GET CHALLENGE command
 *
 * @param {APDU} the apdu
 */
eIDCommandInterpreter.prototype.getChallenge = function(apdu) {
	if (!apdu.hasLe()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Wrong length - missing Le field");
	}

	if (apdu.isChained()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CHAINNOTSUPPORTED, "Chaining not supported in GET CHALLENGE");
	}
	
	if (apdu.hasCData()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Command data not expected in GET CHALLENGE");
	}
	
	var l = apdu.getNe();
	this.challenge = this.crypto.generateRandom(l);
	apdu.setRData(this.challenge);
	
	apdu.setSW(APDU.SW_OK);
}



/**
 * Performs an EXTERNAL AUTHENTICATE command for BAC
 *
 * @param {APDU} the apdu
 */
eIDCommandInterpreter.prototype.externalAuthenticateForBAC = function(apdu) {
	if (!apdu.hasLe()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Wrong length - missing Le field");
	}

	if (apdu.isChained()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CHAINNOTSUPPORTED, "Chaining not supported in EXTERNAL AUTHENTICATE");
	}
	
	if (!apdu.hasCData()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Command requires C-data");
	}

	if ((apdu.getP1() != 0x00) || (apdu.getP2() != 0x00)) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INCP1P2, "Invalid P1 or P2");
	}

	if (!this.challenge) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Must obtain challenge before external authenticate");
	}

	if (this.challenge.length < 8) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Challenge must be larger or equal 8 bytes");
	}

	var challenge = this.challenge;
	this.challenge = null;

	var cryptogram = apdu.getCData();

	if (cryptogram.length != 40) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Cryptogram must be 40 bytes long");
	}

	var k_enc_bac = this.fileSelector.getMeta("KENC");
	var k_mac_bac = this.fileSelector.getMeta("KMAC");

	if (!k_enc_bac || !k_mac_bac) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_GENERALERROR, "No K_ENC or K_MAC defined for DF");
	}

	var mac = cryptogram.right(8);
	cryptogram = cryptogram.left(32);

	if (!this.crypto.verify(k_mac_bac, Crypto.DES_MAC_EMV, cryptogram.pad(Crypto.ISO9797_METHOD_2), mac)) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_WARNINGNVCHG, "Authentication failed");
	}

	var plain = this.crypto.decrypt(k_enc_bac, Crypto.DES_CBC, cryptogram, new ByteString("0000000000000000", HEX));

	var rndifd = plain.bytes(0, 8);
	var rndicc = plain.bytes(8, 8);
	var kifd = plain.bytes(16, 16);

	if (!rndicc.equals(challenge)) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_WARNINGNVCHG, "RNDicc in cryptogram does not match last response in GET CHALLENGE");
	}

	var kicc = this.crypto.generateRandom(16);
	var plain = rndicc.concat(rndifd).concat(kicc);

	var cryptogram = this.crypto.encrypt(k_enc_bac, Crypto.DES_CBC, plain, new ByteString("0000000000000000", HEX));
	var mac = this.crypto.sign(k_mac_bac, Crypto.DES_MAC_EMV, cryptogram.pad(Crypto.ISO9797_METHOD_2));

	apdu.setRData(cryptogram.concat(mac));

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

	var sm = new SecureChannel(this.crypto);
	sm.setMacKey(kmac);
	sm.setEncKey(kenc);
	sm.setMACSendSequenceCounter(ssc);
	this.setSecureChannel(sm);

	apdu.setSW(APDU.SW_OK);
}



/**
 * Process VERIFY(AD)
 *
 * @param {APDU} the apdu
 */
eIDCommandInterpreter.prototype.verifyAuxiliaryData = function(apdu) {
	if (apdu.isChained()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CHAINNOTSUPPORTED, "Chaining not supported in VERIFY(AUX)");
	}

	if (!apdu.hasCData()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Command requires C-data");
	}

	if ((apdu.getP1() != 0x80) || (apdu.getP2() != 0x00)) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INCP1P2, "Invalid P1 or P2");
	}

	var oid = apdu.getCData();
	if ((oid.byteAt(0) != 0x06) || (oid.byteAt(1) != oid.length - 2)) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Malformed object identifier in C-Data");
	}
	oid = oid.bytes(2);

	if (!oid.equals(new ByteString("id-DateOfExpiry", OID)) && 
		!oid.equals(new ByteString("id-CommunityID", OID)) &&
		!oid.equals(new ByteString("id-DateOfBirth", OID))) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Unknown object identifier in C-Data");
	}

	var se = this.fileSelector.getSecurityEnvironment().VEXK;

	if (!se.t.AT) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "No security environment found");
	}

	var ad = se.t.AT.find(0x67);
	if (!ad) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "No auxiliary data found in security environment");
	}
	
	var refdata;
	for (var i = 0; i < ad.elements; i++) {
		var ade = ad.get(i);
		if (ade.tag == 0x73) {
			if ((ade.elements != 2) || (ade.get(0).tag != ASN1.OBJECT_IDENTIFIER) || (ade.get(1).tag != 0x53)) {
				throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "Malformed auxiliary data found in security environment");
			}
			if (ade.get(0).value.equals(oid)) {
				var refdata = ade.get(1).value;
				break;
			}
		}
	}

//	print("RefData: " + refdata.toString(ASCII));

	var ac = this.fileSelector.getMeta("accessController");
	
	if (oid.equals(new ByteString("id-CommunityID", OID))) {
		if (ac && !ac.checkRight(this, apdu, 1)) {
			throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_SECSTATNOTSAT, "Community ID Verification not allowed");
		}
		var id = this.fileSelector.getMeta("CommunityID");
		assert(id, "Community ID not defined as part of meta data");
		id = new ByteString(id, ASCII);
		if (id.startsWith(refdata) == refdata.length) {
			apdu.setSW(APDU.SW_OK);
		} else {
			apdu.setSW(APDU.SW_WARNINGNVCHG);
		}
	} else if (oid.equals(new ByteString("id-DateOfExpiry", OID))) {
		var doe = this.fileSelector.getMeta("DateOfExpiry");
		assert(doe, "Data of expiry not defined as part of meta data");
		if (refdata.toString(ASCII) <= doe) {
			apdu.setSW(APDU.SW_OK);
		} else {
			apdu.setSW(APDU.SW_WARNINGNVCHG);
		}
	} else {
		if (ac && !ac.checkRight(this, apdu, 0)) {
			throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_SECSTATNOTSAT, "Age Verification not allowed");
		}
		var dob = this.fileSelector.getMeta("DateOfBirth");
		assert(dob, "Data of birth not defined as part of meta data");
		if (refdata.toString(ASCII) >= dob) {
			apdu.setSW(APDU.SW_OK);
		} else {
			apdu.setSW(APDU.SW_WARNINGNVCHG);
		}
	}
}



/**
 * Performs an EXTERNAL AUTHENTICATE command
 *
 * @param {APDU} the apdu
 */
eIDCommandInterpreter.prototype.externalAuthenticate = function(apdu) {
	var se = this.fileSelector.getSecurityEnvironment().VEXK;

	if (se.t.AT) {
		this.externalAuthenticateForTA(apdu, se);
	} else {
		this.externalAuthenticateForBAC(apdu);
	}
}



/**
 * Performs an ACTIVATE/DEACTIVATE command
 *
 * @param {APDU} the apdu
 */
eIDCommandInterpreter.prototype.manageActiveState = function(apdu) {
	if (apdu.isChained()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CHAINNOTSUPPORTED, "Chaining not supported in command");
	}
	if (apdu.hasCData()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Command must not have C-data");
	}
	if (apdu.getP1() != 0x10) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INCP1P2, "Invalid P1 or P2");
	}

	var pacekeys = this.fileSelector.getMeta(AuthenticationObject.TYPE_PACE);
	assert(pacekeys, "No PACE authentication objects defined");

	var paceao = pacekeys[apdu.getP2()];
	if (!paceao) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "PACE password not found");
	}

	var ac = this.fileSelector.getMeta("accessController");
	if (!(ac && ac.checkRight(this, apdu, 5))) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_SECSTATNOTSAT, "Activate requires right 5 in id-AT");
	}

	if (apdu.getINS() == APDU.INS_ACTIVATE) {
		paceao.activate();
	} else {
		paceao.deactivate();
	}

	apdu.setSW(APDU.SW_OK);
}



/**
 * Performs a RESET RETRY COUNTER command for PACE keys
 *
 * @param {APDU} the apdu
 */
eIDCommandInterpreter.prototype.resetRetryCounterPACE = function(apdu) {
	if (apdu.isChained()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CHAINNOTSUPPORTED, "Chaining not supported in command");
	}
	var p1 = apdu.getP1();

	if (p1 == 0x02) {
		if (!apdu.hasCData()) {
			throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Command must have C-data");
		}
	} else if (p1 == 0x03) {
		if (apdu.hasCData()) {
			throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Command must not have C-data");
		}
	} else {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INCP1P2, "Invalid P1 or P2");
	}

	var pacekeys = this.fileSelector.getMeta(AuthenticationObject.TYPE_PACE);
	assert(pacekeys, "No PACE authentication objects defined");

	var paceao = pacekeys[apdu.getP2()];
	if (!paceao) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "PACE password not found");
	}

	if (!apdu.isSecureMessaging()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_SECSTATNOTSAT, "Secure messaging required for reset retry counter");
	}

	var ac = this.fileSelector.getMeta("accessController");

	if (!(	this.fileSelector.isAuthenticated(true, paceao) ||
			((typeof(paceao.unblockAuthenticationObject) != "undefined") && this.fileSelector.isAuthenticated(true, paceao.unblockAuthenticationObject)) ||
			(ac && ac.checkRight(this, apdu, 5))   )) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_SECSTATNOTSAT, "Security condition for reset retry counter not satisfied");
	}
	paceao.resetRetryCounter(apdu.getCData());

	apdu.setSW(APDU.SW_OK);
}



/**
 * Performs a TERMINATE(PIN) command
 *
 * @param {APDU} the apdu
 */
eIDCommandInterpreter.prototype.terminatePIN = function(apdu) {
	if (apdu.hasCData()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Command must not have C-data");
	}

	var pinao = this.fileSelector.getObject(AuthenticationObject.TYPE_PIN, apdu.getP2());
	if (!pinao) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "PIN with reference " + apdu.getP2() + " not found");
	}

	pinao.terminate();
	apdu.setSW(APDU.SW_OK);
}



/**
 * Performs a TERMINATE(Key) command
 *
 * @param {APDU} the apdu
 */
eIDCommandInterpreter.prototype.terminateKey = function(apdu) {
	if (!apdu.hasCData()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Command must have C-data");
	}
	var crt = new ASN1(apdu.getCData());

	if (crt.tag != 0xB6) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Digital Signature Template (DST 'B6') not found");
	}

	var ref = crt.find(0x84);
	if (!ref) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Private key reference object '84' not found");
	}
	var id = ref.value.toUnsigned();

	var key = this.fileSelector.getObject(SignatureKey.TYPE_KEY, id);
	if (!key) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "Key with reference " + id + " not found");
	}

	if (!key.useAuthenticationObject.isTerminated) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_REFDATANOTUSABLE, "Authentication object is not terminated");
	}
	
	key.terminate();
	apdu.setSW(APDU.SW_OK);
}



/**
 * Performs a TERMINATE command
 *
 * @param {APDU} the apdu
 */
eIDCommandInterpreter.prototype.terminate = function(apdu) {
	if (apdu.isChained()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CHAINNOTSUPPORTED, "Chaining not supported in command");
	}

	switch(apdu.getP1()) {
	case 0x10:
		this.terminatePIN(apdu);
		break;
	case 0x21:
		this.terminateKey(apdu);
		break;
	default:
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INCP1P2, "Invalid P1 or P2");
	}

	apdu.setSW(APDU.SW_OK);
}



/**
 * Performs a TERMINATE(Key) command
 *
 * @param {APDU} the apdu
 */
eIDCommandInterpreter.prototype.generateAsymmetricKeyPair = function(apdu) {
	if (!apdu.hasCData()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Command must have C-data");
	}
	if ((apdu.getP1() != 0x82) || (apdu.getP2() != 0x00)) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INCP1P2, "Invalid P1 or P2");
	}
	var a = new ASN1(0x30, apdu.getCData());
	a = new ASN1(a.getBytes());
//	print(a);

	var crt = a.get(0);
	if (crt.tag != 0xB6) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Digital Signature Template (DST 'B6') not found");
	}

	var ref = crt.find(0x84);
	if (!ref) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Private key reference object '84' not found");
	}
	var id = ref.value.toUnsigned();

	var keyobj = this.fileSelector.getObject(SignatureKey.TYPE_KEY, id);
	if (!keyobj) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "Key with reference " + id + " not found");
	}

	var dpt = a.get(1);
	if (dpt.tag != 0x7F49) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Private key reference object '84' not found");
	}

	if (dpt.elements != 7) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Public key must contain 7 elements");
	}

	var puk = new Key();
	puk.setType(Key.PUBLIC);
	puk.setComponent(Key.ECC_P, dpt.find(0x81).value);
	puk.setComponent(Key.ECC_A, dpt.find(0x82).value);
	puk.setComponent(Key.ECC_B, dpt.find(0x83).value);
	var g = dpt.find(0x84).value.bytes(1);
	puk.setComponent(Key.ECC_GX, g.left(g.length >> 1));
	puk.setComponent(Key.ECC_GY, g.right(g.length >> 1));
	puk.setComponent(Key.ECC_N, dpt.find(0x85).value);
	puk.setComponent(Key.ECC_H, dpt.find(0x87).value);

	keyobj.privateKey = new Key();
	keyobj.privateKey.setType(Key.PRIVATE);
	keyobj.isTerminated = false;
	
	this.crypto.generateKeyPair(Crypto.EC, puk, keyobj.privateKey);

	var encpuk = PACE.encodePublicKey("ecdsa-plain-signatures", puk, true);
	apdu.setRData(encpuk.getBytes());

	apdu.setSW(APDU.SW_OK);
}



/**
 * Performs a COMPUTE DIGITAL SIGNATURE command
 *
 * @param {APDU} the apdu
 */
eIDCommandInterpreter.prototype.computeDigitalSignature = function(apdu) {
	if (!apdu.hasCData()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Command must have C-data");
	}
	if (apdu.getP2() != 0x9A) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INCP1P2, "Invalid P1 or P2");
	}

	var se = this.fileSelector.getSecurityEnvironment().CDIK;
//	print(se);

	var keyid = 0x81;
	if (se.t.DST) {
		var keyref = se.t.DST.find(0x84);
		if (keyref) {
			keyid = keyref.value.toUnsigned();
		}
	}

//	print("KeyID: " + keyid);

	var keyobj = this.fileSelector.getObject(SignatureKey.TYPE_KEY, keyid);
	if (!keyobj) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "Key with reference " + keyid + " not found");
	}

	if (keyobj.isTerminated) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_REFDATANOTUSABLE, "Key is terminated");
	}
	
	var signature = this.crypto.sign(keyobj.privateKey, Crypto.ECDSA, apdu.getCData());

	apdu.setRData(ECCUtils.unwrapSignature(signature), keyobj.privateKey.getComponent(Key.ECC_P).length);
	apdu.setSW(APDU.SW_OK);
}



/**
 * Dispatch to command handler based in INS byte in APDU
 *
 * @param {APDU} apdu the apdu
 * @param {Number} ins the normalized instruction code
 */
eIDCommandInterpreter.prototype.dispatch = function(apdu, ins) {
	if (!apdu.isISO() && (ins != APDU.INS_VERIFY)) {
		apdu.setSW(APDU.SW_INVCLA);
		return;
	}

	switch(ins) {
	case APDU.INS_GENERAL_AUTHENTICATE:
		this.generalAuthenticate(apdu);
		break;
	case APDU.INS_GET_CHALLENGE:
		this.getChallenge(apdu);
		break;
	case APDU.INS_EXTERNAL_AUTHENTICATE:
		this.externalAuthenticate(apdu);
		break;
	case APDU.INS_MANAGE_SE:
		if ((apdu.getP1() == 0x41) && (apdu.getP2() == 0xA6)) {
			this.performChipAuthenticationV1(apdu);
		} else {
			CommandInterpreter.prototype.dispatch.call(this, apdu, ins);
			if ((apdu.getP1() == 0xC1) && (apdu.getP2() == 0xA4)) {
				this.determinePINStatus(apdu);
			}
		}
		break;
	case APDU.INS_VERIFY:
		if ((apdu.getCLA() & 0x80) == 0x80) {
			this.verifyAuxiliaryData(apdu);
		} else {
			CommandInterpreter.prototype.dispatch.call(this, apdu, ins);
		}
		break;
	case APDU.INS_RESET_RETRY_COUNTER:
		if (!(apdu.getP2() & 0x80)) {
			this.resetRetryCounterPACE(apdu);				// PACE eID-PIN
		} else {
			CommandInterpreter.prototype.dispatch.call(this, apdu, ins);		// eSign PIN
		}
		break;
	case APDU.INS_ACTIVATE:
		this.manageActiveState(apdu);
		break;
	case APDU.INS_DEACTIVATE:
		this.manageActiveState(apdu);
		break;
	case APDU.INS_TERMINATE:
		this.terminate(apdu);
		break;
	case APDU.INS_PSO:
		if (apdu.getP2() == APDU.INS_VERIFY_CERTIFICATE) {
			this.verifyCertificate(apdu);
		} else if (apdu.getP1() == APDU.INS_COMPUTE_DIGITAL_SIGN) {
			this.computeDigitalSignature(apdu);
		} else {
			CommandInterpreter.prototype.dispatch.call(this, apdu, ins);
		}
		break;
	case APDU.INS_GENERATE_KEY_PAIR:
		this.generateAsymmetricKeyPair(apdu);
		break;
	default:
		CommandInterpreter.prototype.dispatch.call(this, apdu, ins);
	}

	this.lastINS = ins;
}
