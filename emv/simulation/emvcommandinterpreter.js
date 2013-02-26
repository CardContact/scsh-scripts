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
 * @fileoverview Implementation of an EMV command interpreter
 */

load("../../cardsim/commandinterpreter.js");



/**
 * Create a command interpreter
 *
 * @class Class implementing a command interpreter that handles EMV command APDUs
 * @constructor
 * @param {FileSelector} fileSelector the file selector object
 */
function EMVCommandInterpreter(fileSelector) {
	CommandInterpreter.call(this, fileSelector);
}

// Inherit from CommandInterpreter
EMVCommandInterpreter.prototype = new CommandInterpreter();
EMVCommandInterpreter.constructor = EMVCommandInterpreter;



/**
 * Implements GET PROCESSING OPTIONS
 *
 * @param {APDU} apdu the command APDU
 */
EMVCommandInterpreter.prototype.getProcessingOptions = function(apdu) {
	if ((apdu.getP1() != 0x00) || (apdu.getP2() != 0x00)) {
		throw new GPError("EMVCommandInterpreter", GPError.INVALID_DATA, APDU.SW_INCP1P2, "P1 and P2 must be 00 in GET PROCESSING OPTIONS");
	}
	var aip = this.fileSelector.getMeta("ApplicationInterchangeProfile");
	var afl = this.fileSelector.getMeta("ApplicationFileLocator");

	var resp = new ASN1(0x77,
						new ASN1(EMV.AIP, aip),
						new ASN1(EMV.AFL, afl)
					);
	apdu.setRData(resp.getBytes());
	apdu.setSW(APDU.SW_OK);
}



/**
 * Dispatch to command handler based in INS byte in APDU
 *
 * @param {APDU} apdu the apdu
 * @param {Number} ins the normalized instruction code
 */
EMVCommandInterpreter.prototype.dispatch = function(apdu, ins) {
	switch(ins) {
	case EMV.INS_GET_PROCESSING_OPTIONS:
		this.getProcessingOptions(apdu);
		break;
	default:
		CommandInterpreter.prototype.dispatch.call(this, apdu, ins);
	}
}
