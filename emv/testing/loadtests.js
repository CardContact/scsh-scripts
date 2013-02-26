/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2008 CardContact Software & System Consulting
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
 * @fileoverview Script to load all tests for the EMV simulation test suite into the GUI test runner
 */

//
// Script to load test cases
//


load("tools/TestRunner.js");
load("tools/TestGroup.js");
load("tools/TestProcedure.js");

load("../emv.js");
load("../emvView.js");


var param = new Array();

param["card"] = new Card(_scsh3.reader);
param["crypto"] = new Crypto();

param["contactless"] = false;			// Use 1PAY.SYS.DDF01 or 2PAY.SYSDDF01



/**
 * Create new instance of EMV class for tests.
 *
 * <p>This method allows to tailor some global settings for the tests.</p>
 * @param {Card} card the EMV card
 * @param {Crypto} crypto the crypto provider to use
 * @type EMV
 * @return a new instance of the EMV class
 */
function newEMV(card, crypto) {
	var emv = new EMV(card, crypto);
	emv.verbose = true;
	return emv;
}



var testRunner = new TestRunner("EMV Simulation Test Suite");

testRunner.addTestGroupFromXML("tg_application_selection.xml", param);
testRunner.addTestGroupFromXML("tg_initiate_application_processing.xml", param);
testRunner.addTestGroupFromXML("tg_read_application_data.xml", param);

print("Test-Suite loaded...");
