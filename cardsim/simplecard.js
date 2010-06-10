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
 * @fileoverview A simple card simulation
 */

load("filesystem.js");



function SimpleCardSimulator() {
	this.aid = new ByteString("A0000000010101", HEX);

	this.mf = new DF(FCP.newDF("3F00", null),
						new TransparentEF(FCP.newTransparentEF("2F00", -1, 100)),
						new TransparentEF(FCP.newTransparentEF("2F01", 0x17, 100)),
						new DF(FCP.newDF("DF01", this.aid),
							new TransparentEF(FCP.newTransparentEF("EF01", -1, 100)),
							new TransparentEF(FCP.newTransparentEF("EF02", -1, 100))
						)
					);

	this.fileSelector = new FileSelector(this.mf);

}



SimpleCardSimulator.prototype.processAPDU = function(capdu) {
	print("Received APDU: " + capdu);

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

	try	{
		switch(apdu.getINS()) {
			case APDU.INS_SELECT:
				this.fileSelector.processSelectAPDU(apdu);
				break;
			default:
				apdu.setSW(APDU.SW_INVINS);
		}
	}
	catch(e) {
		GPSystem.trace(e.fileName + "#" + e.lineNumber + ": " + e);
		var sw = APDU.SW_GENERALERROR;
		if (e instanceof GPError) {
			apdu.setSW(e.reason);
		}
	}
	
	return apdu.getResponseAPDU();
}



SimpleCardSimulator.prototype.reset = function(type) {
	print("Reset type: " + type);
	this.fileSelector = new FileSelector(this.mf);
	var atr = new ByteString("3B600000", HEX);
	return atr;
}



var newsim = false;
if (typeof(CARDSIM) == "undefined") {
	CARDSIM = new CardSimulationAdapter("JCOPSimulation", "8050");
	newsim = true;
}

var sim = new SimpleCardSimulator();

CARDSIM.setSimulationObject(sim);

if (newsim) {
	CARDSIM.start();
}

print("Simulation running...");
