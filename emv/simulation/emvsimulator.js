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
 * @fileoverview A simple EMV card simulation
 */

load("../../cardsim/filesystem.js");
load("../emv.js");

load("emvcommandinterpreter.js");
load("emvdatamodel.js");


var dataModel = new EMVDataModel();


/**
 * Create a card simulation object
 *
 * @class Class implementing a simple EMV card simulation
 * @constructor
 */
function EMVSimulator() {
	this.mf = new DF(FCP.newDF("3F00", null));

	var aid = new ByteString("A000000000", HEX);
	var fcipt = new ASN1("FCI Proprietary Template", 0xA5,
							new ASN1("SFI of the Directory Elementary File", 0x88, ByteString.valueOf(1))
						);

	var psd = new ASN1(0x70,
							new ASN1(0x61,
								new ASN1(0x4F, aid),
								new ASN1(0x50, new ByteString("EMV Simulator", ASCII))
							)
						);
	var records = [ psd.getBytes() ];
	var paysysddf = new DF(FCP.newDF(null, EMV.PSE1, fcipt.getBytes()),
							new LinearEF(FCP.newLinearEF("EF01", 1, FCP.LINEARVARIABLE, 1, 100), records)
						);

	this.mf.add(paysysddf);

	var fcipt = new ASN1("FCI Proprietary Template", 0xA5,
							new ASN1("Application Label", 0x50, new ByteString("EMV Simulator", ASCII))
						);

	var adf = new DF(FCP.newDF(null, aid, fcipt.getBytes())
						);

	adf.addMeta("ApplicationInterchangeProfile", dataModel.getApplicationInterchangeProfile());
	adf.addMeta("ApplicationFileLocator", dataModel.getApplicationFileLocator());

	// Create file system from data model
	for each (var file in dataModel.getFiles()) {
		var fid = ByteString.valueOf(0xEF00 + file.sfi, 2).toString(HEX);
		adf.add(new LinearEF(FCP.newLinearEF(fid, file.sfi, FCP.LINEARVARIABLE, file.records.length, 256), file.records));
	}

	this.mf.add(adf);

	print(this.mf.dump(""));

	this.initialize();
}



/**
 * Initialize card runtime
 */
EMVSimulator.prototype.initialize = function() {
	this.fileSelector = new FileSelector(this.mf);
	this.commandInterpreter = new EMVCommandInterpreter(this.fileSelector);
}



/**
 * Process an inbound APDU
 *
 * @param {ByteString} capdu the command APDU
 * @type ByteString
 * @return the response APDU
 */ 
EMVSimulator.prototype.processAPDU = function(capdu) {
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
		return ByteString.valueOf(sw, 2);
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
EMVSimulator.prototype.reset = function(type) {
	print("Reset type: " + type);

	this.initialize();

	var atr = new ByteString("3B600000", HEX);
	return atr;
}



/**
 * Create new simulation and register with existing or newly created adapter singleton.
 *
 */
EMVSimulator.newInstance = function() {
	var sim = new EMVSimulator();

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



EMVSimulator.newInstance();
