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
 * @fileoverview Implementation of an ISO 7816-4 command interpreter
 */



/**
 * Create a command interpreter
 *
 * @class Class implementing a command interpreter that handles ISO 7816-4 command APDUs
 * @constructor
 * @param {FileSelector} fileSelector the file selector object
 */
function CommandInterpreter(fileSelector) {
	this.fileSelector = fileSelector;
}



/**
 * Set secure channel
 *
 * @param {SecureChannel} secureChannel the secure channel to used for unwrapping and wrapping APDUs
 */
CommandInterpreter.prototype.setSecureChannel = function(secureChannel) {
	this.secureChannel = secureChannel;
}



/**
 * Return status of secure channel
 *
 * @type boolean
 * @return true if secure channel is active
 */
CommandInterpreter.prototype.hasSecureChannel = function() {
	return (typeof(this.secureChannel) != "undefined") && (this.secureChannel != null);
}



/**
 * Process a READ BINARY APDU
 *
 * @param {APDU} apdu the command and response APDU
 */
CommandInterpreter.prototype.readBinary = function(apdu) {
	if (!apdu.hasLe()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Wrong length - missing Le field");
	}

	if (apdu.isChained()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CHAINNOTSUPPORTED, "Chaining not supported in READ BINARY");
	}
	
	var dua = new DataUnitAPDU(apdu);
	
	if (dua.hasCData()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "Command data not expected in  READ BINARY");
	}

	var ef;
	var sfi = dua.getSFI();
	var fid = dua.getFID();
	
	if (sfi >= 0) {
		ef = this.fileSelector.selectSFI(sfi);
	} else if (fid != null) {
		ef = this.fileSelector.selectFID(fid, false, false);
	} else {
		ef = this.fileSelector.getCurrentEF();
	
		if (ef == null) {
			throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_COMNOTALLOWNOEF, "No current EF in READ BINARY");
		}
	}
	
	if (!(ef instanceof TransparentEF)) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_COMINCOMPATIBLE, "EF is not a transparent file in READ BINARY");
	}

	var ac = this.fileSelector.getMeta("accessController");
	if (ac && !ac.checkFileReadAccess(this, apdu, ef)) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_SECSTATNOTSAT, "Read access not allowed as determined by " + ac);
	}

	var offset = dua.getOffset();
	var length = apdu.getNe();

	var data = ef.readBinary(apdu, offset, length);

	apdu.setRData(data);
}



/**
 * Process an UPDATE BINARY APDU
 *
 * @param {APDU} apdu the command and response APDU
 */
CommandInterpreter.prototype.updateBinary = function(apdu) {
	if (apdu.isChained()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CHAINNOTSUPPORTED, "Chaining not supported in READ BINARY");
	}
	
	if (!apdu.hasCData()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "No data found in UPDATE BINARY");
	}

	var dua = new DataUnitAPDU(apdu);
	
	if (!dua.hasCData()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_INVDATA, "No data found in UPDATE BINARY");
	}

	var ef;
	var sfi = dua.getSFI();
	var fid = dua.getFID();
	
	if (sfi >= 0) {
		ef = this.fileSelector.selectSFI(sfi);
	} else if (fid != null) {
		ef = this.fileSelector.selectFID(fid, false, false);
	} else {
		ef = this.fileSelector.getCurrentEF();
	
		if (ef == null) {
			throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_COMNOTALLOWNOEF, "No current EF in UPDATE BINARY");
		}
	}
	
	if (!(ef instanceof TransparentEF)) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_COMINCOMPATIBLE, "EF is not a transparent file in UPDATE BINARY");
	}

	var ac = this.fileSelector.getMeta("accessController");
	if (ac && !ac.checkFileWriteAccess(this, apdu, ef)) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_SECSTATNOTSAT, "Write access not allowed as determined by " + ac);
	}

	var offset = dua.getOffset();
	var data = dua.getCData();

	ef.updateBinary(apdu, offset, data);
}



/**
 * Process a READ RECORD APDU
 *
 * @param {APDU} apdu the command and response APDU
 */
CommandInterpreter.prototype.readRecord = function(apdu) {
	if (!apdu.hasLe()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Wrong length - missing Le field");
	}

	if (apdu.isChained()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CHAINNOTSUPPORTED, "Chaining not supported in READ RECORD");
	}

	var recno = apdu.getP1();
	var sfi = apdu.getP2() >> 3;
	var qualifier = apdu.getP2() & 0x7;

	if (sfi > 0) {
		ef = this.fileSelector.selectSFI(sfi);
	} else {
		ef = this.fileSelector.getCurrentEF();

		if (ef == null) {
			throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_COMNOTALLOWNOEF, "No current EF in READ RECORD");
		}
	}

	if (!(ef instanceof LinearEF)) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_COMINCOMPATIBLE, "EF is not a linear file in READ RECORD");
	}

	var ac = this.fileSelector.getMeta("accessController");
	if (ac && !ac.checkFileReadAccess(this, apdu, ef)) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_SECSTATNOTSAT, "Read access not allowed as determined by " + ac);
	}

	var data = ef.readRecord(apdu, recno, qualifier, apdu.getNe());

	apdu.setRData(data);
}



/**
 * Performs a VERIFY command
 *
 * @param {APDU} the apdu
 */
CommandInterpreter.prototype.verify = function(apdu) {
	if (apdu.isChained()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CHAINNOTSUPPORTED, "Chaining not supported in command");
	}
	
	var pinao = this.fileSelector.getObject(AuthenticationObject.TYPE_PIN, apdu.getP2());
	if (!pinao) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "PIN with reference " + apdu.getP2() + " not found");
	}

	if (apdu.hasCData()) {
		pinao.verify(apdu.getCData());
	} else {
		if (!this.fileSelector.isAuthenticated(ao)) {
			pinao.determineStatus();
		}
	}

	apdu.setSW(APDU.SW_OK);
}



/**
 * Performs a CHANGE REFERENCE DATA command
 *
 * @param {APDU} the apdu
 */
CommandInterpreter.prototype.changeReferenceData = function(apdu) {
	if (apdu.isChained()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_CHAINNOTSUPPORTED, "Chaining not supported in command");
	}
	if (!apdu.hasCData()) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Command must have C-data");
	}

	var pinao = this.fileSelector.getObject(AuthenticationObject.TYPE_PIN, apdu.getP2());
	if (!pinao) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "PIN with reference " + apdu.getP2() + " not found");
	}

	pinao.changeReferenceData(apdu.getP1(), apdu.getCData());

	apdu.setSW(APDU.SW_OK);
}



/**
 * Performs a RESET RETRY COUNTER command
 *
 * @param {APDU} the apdu
 */
CommandInterpreter.prototype.resetRetryCounter = function(apdu) {
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

	var pinao = this.fileSelector.getObject(AuthenticationObject.TYPE_PIN, apdu.getP2());
	if (!pinao) {
		throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_RDNOTFOUND, "PIN with reference " + apdu.getP2() + " not found");
	}

	pinao.resetRetryCounter(apdu.getCData());

	apdu.setSW(APDU.SW_OK);
}



/**
 * Process a MANAGE SECURITY ENVIRONMENT APDU
 *
 * @param {APDU} apdu the command and response APDU
 */
CommandInterpreter.prototype.manageSecurityEnvironment = function(apdu) {
	var p1 = apdu.getP1();
	var p2 = apdu.getP2();
	
	var se = this.fileSelector.getSecurityEnvironment();

	if ((p1 & 0x0F) != 1) { 	// SET
		throw new GPError("CommandInterpreter", GPError.INVALID_TYPE, APDU.APDU.SW_FUNCNOTSUPPORTED, "Only MANAGE SE set variant supported");
	}
	
	var tlv = new ASN1(p2, apdu.getCData());

	if (p1 & 0x80) {					// Verification, Encryption, External Authentication and Key Agreement
		var t = new ASN1(tlv.getBytes());		// Dirty trick to deserialize as TLV tree
		se.VEXK.add(t);
	}
	if (p1 & 0x40) {					// Calculation, Decryption, Internal Authentication and Key Agreement
		var t = new ASN1(tlv.getBytes());		// Dirty trick to deserialize as TLV tree
		se.CDIK.add(t);
	}
	if (p1 & 0x20) {					// Secure Messaging Response
		var t = new ASN1(tlv.getBytes());		// Dirty trick to deserialize as TLV tree
		se.SMRES.add(t);
	}
	if (p1 & 0x10) {					// Secure Messaging Command
		var t = new ASN1(tlv.getBytes());		// Dirty trick to deserialize as TLV tree
		se.SMCOM.add(t);
	}
	apdu.setSW(APDU.SW_OK);
}



/**
 * Process a secure messaging command APDU, if secure messaging is active.
 *
 * @param {APDU} apdu the command APDU
 */
CommandInterpreter.prototype.handleSecMsgCommandAPDU = function(apdu) {
	if (apdu.isSecureMessaging()) {
		if (this.hasSecureChannel()) {
			try	{
				apdu.setSecureChannel(this.secureChannel);
				apdu.unwrap();
			}
			catch(e) {
				this.setSecureChannel();	// Reset secure channel
				throw e;
			}
		} else {
			throw new GPError("CommandInterpreter", GPError.INVALID_DATA, APDU.SW_SMNOTSUPPORTED, "No secure messaging channel");
		}
	} else {
		if (this.hasSecureChannel()) {
			this.setSecureChannel();	// Reset secure channel
		}
	}
}



/**
 * Process a secure messaging response APDU, if secure messaging is active
 *
 * @param {APDU} apdu the response APDU
 */
CommandInterpreter.prototype.handleSecMsgResponseAPDU = function(apdu) {
	if (apdu.isSecureMessaging() && this.hasSecureChannel()) {
		apdu.wrap();
	}
}



/**
 * Dispatch to command handler based on instruction code
 *
 * @param {APDU} apdu the command and response APDU
 * @param {Number} ins instruction code
 */
CommandInterpreter.prototype.dispatch = function(apdu, ins) {
	switch(ins) {
		case APDU.INS_SELECT:
			this.fileSelector.processSelectAPDU(apdu);
			break;
		case APDU.INS_READ_BINARY:
			this.readBinary(apdu);
			break;
		case APDU.INS_UPDATE_BINARY:
			this.updateBinary(apdu);
			break;
		case APDU.INS_READ_RECORD:
			this.readRecord(apdu);
			break;
		case APDU.INS_VERIFY:
			this.verify(apdu);
			break;
		case APDU.INS_RESET_RETRY_COUNTER:
			this.resetRetryCounter(apdu);
			break;
		case APDU.INS_CHANGE_REFERENCE_DATA:
			this.changeReferenceData(apdu);
			break;
		case APDU.INS_MANAGE_SE:
			this.manageSecurityEnvironment(apdu);
			break;
		default:
			apdu.setSW(APDU.SW_INVINS);
	}
}



/**
 * Process a command APDU
 *
 * @param {APDU} apdu the command and response APDU
 */
CommandInterpreter.prototype.processAPDU = function(apdu) {
	try	{
		this.handleSecMsgCommandAPDU(apdu);
		
		var cla = apdu.getCLA();
		var ins = apdu.getINS();
		var tlv = (ins & 1) == 1;
		ins &= 0xFE;
		
		this.dispatch(apdu, ins);
	}
	catch(e) {
		GPSystem.trace(e.fileName + "#" + e.lineNumber + ": " + e);
		var sw = APDU.SW_GENERALERROR;
		if ((e instanceof GPError) && (e.reason >= 0x6200)) {
			apdu.setSW(e.reason);
		} else {
			apdu.setSW(APDU.SW_GENERALERROR);
		}
	}
	this.handleSecMsgResponseAPDU(apdu);
}

