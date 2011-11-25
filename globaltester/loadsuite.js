/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2006 CardContact Software & System Consulting
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
 * @fileoverview Example to load and run test suites from Global Tester
 */


load("lib/GTTestGroup.js");
load("lib/TestRunner.js");


// Define parameter passed in the scope for test case execution. These parameters
// are usually set in the GT parameter dialog (e.g. _mrz
var param = [];
param["_manualReader"] = null;
param["_reader"] = "";
param["_mrz"] = "L898902C<3UTO6908061F9406236ZE184226B<<<<<14";
param["_readBuffer"] = 0;


var suite = GPSystem.mapFilename("", GPSystem.CWD);

if (typeof(_scsh3.lastGTSuite) != "undefined") {
	suite = _scsh3.lastGTSuite;
}

var suite = Dialog.prompt("Please select test suite", suite, null, "*.xml");

if (suite != null) {
	suite = suite.replace("\\", "/", "g");
	_scsh3.setProperty("lastGTSuite", suite);

	var groups = GTTestGroup.loadSuite(suite, param);

	var runner = new TestRunner(suite);
	for (var i in groups) {
		runner.addTestGroup(groups[i]);
	}
}
