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
 * @fileoverview A simple eID card simulation
 */

load("../cardsim/filesystem.js");
load("eidcommandinterpreter.js");
load("../cardsim/securechannel.js");

load("../icao/pace.js");
load("../icao/chipauthentication.js");


var paceInfo = new PACEInfo();
paceInfo.protocol = new ByteString("id-PACE-ECDH-GM-AES-CBC-CMAC-128", OID);
paceInfo.version = 1;

var paceDomainParameterInfo = new PACEDomainParameterInfo();
paceDomainParameterInfo.protocol = new ByteString("id-PACE-ECDH-GM", OID);

var chipAuthenticationInfo = new ChipAuthenticationInfo();
chipAuthenticationInfo.protocol = new ByteString("id-CA-ECDH-AES-CBC-CMAC-128", OID);
chipAuthenticationInfo.version = 2;

var chipAuthenticationDomainParameterInfo = new PACEDomainParameterInfo();
chipAuthenticationDomainParameterInfo.protocol = new ByteString("id-CA-ECDH", OID);


var CardInfo = new ASN1(ASN1.SEQUENCE,
							paceInfo.toTLV(),
							paceDomainParameterInfo.toTLV(),
							chipAuthenticationInfo.toTLV(),
							chipAuthenticationDomainParameterInfo.toTLV()
						);


/**
 * Create a card simulation object
 *
 * @class Class implementing a simple ISO 7816-4 card simulation
 * @constructor
 */
function eIDSimulation() {
	this.aid = new ByteString("E80704007F00070302", HEX);

	this.mf = new DF(FCP.newDF("3F00", null),
						new LinearEF(FCP.newLinearEF("2F00", 0, FCP.LINEARVARIABLE, 20, 10)),
						new TransparentEF(FCP.newTransparentEF("2F02", 1, 100), new ByteString("5A0A00010203040506070809", HEX)),
						new TransparentEF(FCP.newTransparentEF("011C", 0, 100), CardInfo.getBytes()),
						new DF(FCP.newDF("DF01", this.aid),
							new TransparentEF(FCP.newTransparentEF("EF01", 0, 100)),
							new TransparentEF(FCP.newTransparentEF("EF02", 0, 100))
						)
					);

	print(this.mf.dump(""));
	
	this.initialize();
}



/**
 * Initialize card runtime
 */
eIDSimulation.prototype.initialize = function() {
	this.fileSelector = new FileSelector(this.mf);
	this.commandInterpreter = new eIDCommandInterpreter(this.fileSelector);
}



/**
 * Process an inbound APDU
 *
 * @param {ByteString} capdu the command APDU
 * @type ByteString
 * @return the response APDU
 */ 
eIDSimulation.prototype.processAPDU = function(capdu) {
	print("Command APDU : " + capdu);

	var apdu;
	
	try	{
		apdu = new APDU(capdu);
	}
	catch(e) {
		GPSystem.trace(e);
		var sw = APDU.SW_GENERALERROR;
		if (e instanceof GPError) {
			sw = e.reason;
		}
		var bb = new ByteBuffer();
		bb.append(sw >> 8);
		bb.append(sw & 0xFF);
		return bb.toByteString();
	}

	this.commandInterpreter.processAPDU(apdu);
	
	var rapdu = apdu.getResponseAPDU();
	print("Response APDU: " + rapdu);
	return rapdu;
}



/**
 * Respond to reset request
 *
 * @param {Number} type reset type (One of Card.RESET_COLD or Card.RESET.WARM)
 * @type ByteString
 * @return answer to reset
 */
eIDSimulation.prototype.reset = function(type) {
	print("Reset type: " + type);

	this.initialize();

	var atr = new ByteString("3B600000", HEX);
	return atr;
}



/**
 * Create new simulation and register with existing or newly created adapter singleton.
 *
 */
eIDSimulation.newInstance = function() {
	var sim = new eIDSimulation();

	if (typeof(CARDSIM) == "undefined") {
		var adapter = new CardSimulationAdapter("JCOPSimulation", "8050");
		adapter.setSimulationObject(sim);
		adapter.start();
		CARDSIM = adapter;
		print("Simulation running...");
	} else {
		CARDSIM.setSimulationObject(sim);
		print("Simulation replaced...");
	}
}



eIDSimulation.newInstance();
