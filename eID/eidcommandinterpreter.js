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
 * @fileoverview Implementation of a eID specific command interpreter
 */

load("../cardsim/commandinterpreter.js");
load("../icao/pace.js");



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
	this.pacepwd = new ByteString("488444", ASCII);
	this.challenge = null;
	this.crypto = new Crypto();
}


// Inherit from CommandInterpreter
eIDCommandInterpreter.prototype = new CommandInterpreter();
eIDCommandInterpreter.constructor = eIDCommandInterpreter;



/**
 * Process GENERAL AUTHENTICATE command
 *
 * @param {APDU} the apdu
 */
eIDCommandInterpreter.prototype.generalAuthenticate = function(apdu) {
	var a = new ASN1(apdu.getCData());

	if (a.tag != 0x7C)
		throw new GPError("EACSIM", GPError.INVALID_DATA, 0, "Body must contain data element 0x7C");

	var response = new ASN1(0x7C);

	if (a.elements == 0) {		// 1st General Authenticate
		// ToDo use info from SE
		this.pace = new PACE(this.crypto, PACE.id_PACE_ECDH_GM_AES_CBC_CMAC_128, this.pacedp);
		this.pace.setPassword(this.pacepwd);
		var encnonce = this.pace.getEncryptedNonce();
		response.add(new ASN1(0x80, encnonce));
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
			response.add(new ASN1(0x82, mappingData));
			
			this.pace.performMapping(a.value);
			break;
		case 0x83:
			if (!this.pace.hasMapping())
				throw new GPError("EACSIM", GPError.INVALID_DATA, 0, "Invalid sequence. Second GA missing");
			
			if (a.value.byteAt(0) != 0x04) 
				throw new GPError("EACSIM", GPError.INVALID_DATA, 0, "Public key does not start with '04'");
			
			var ephKey = this.pace.getEphemeralPublicKey();
			response.add(new ASN1(0x84, ephKey));
			
			this.pace.performKeyAgreement(a.value);
			break;
		case 0x85:
			if (!this.pace.verifyAuthenticationToken(a.value)) {
				throw new GPError("EACSIM", GPError.INVALID_DATA, 0, "Verification of authentication token failed");
			}
			
			var authToken = this.pace.calculateAuthenticationToken();
			
			response.add(new ASN1(0x86, authToken));
			response.add(new ASN1(0x87, new ByteString("UTCVCA00001", ASCII)));
			
			var sm = new SecureChannel(this.crypto);
			sm.setSendSequenceCounterPolicy(IsoSecureChannel.SSC_SYNC_ENC_POLICY);
			sm.setMacKey(this.pace.kmac);
			sm.setEncKey(this.pace.kenc);
			sm.setMACSendSequenceCounter(new ByteString("00000000000000000000000000000000", HEX));
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
 * Process PSO VERIFY CERTIFICATE command
 *
 * @param {APDU} the apdu
 */
eIDCommandInterpreter.prototype.verifyCertificate = function(apdu) {
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
 * Dispatch to command handler based in INS byte in APDU
 *
 * @param {APDU} apdu the apdu
 * @param {Number} ins the normalized instruction code
 */
eIDCommandInterpreter.prototype.dispatch = function(apdu, ins) {
	switch(ins) {
	case APDU.INS_GENERAL_AUTHENTICATE:
		this.generalAuthenticate(apdu);
		break;
	case APDU.INS_GET_CHALLENGE:
		this.getChallenge(apdu);
		break;
	case APDU.INS_PSO:
		var p2 = apdu.getP2();
		switch(p2) {
		case 0xBE:
			this.verifyCertificate(apdu);
			break;
		default:
			CommandInterpreter.prototype.dispatch.call(this, apdu, ins);
		}
		break;
	default:
		CommandInterpreter.prototype.dispatch.call(this, apdu, ins);
	}
}
