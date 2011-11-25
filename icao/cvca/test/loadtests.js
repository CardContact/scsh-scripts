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
 * @fileoverview Script to load all tests for the card simulation test suite into the GUI test runner
 */

//
// Script to load test cases
//


load("tools/TestRunner.js");
load("tools/TestGroup.js");
load("tools/TestProcedure.js");


var crypto = new Crypto();

var param = new Array();

param["url"] = "http://localhost:8080/se/";
param["datadir"] = "c:/data/eacpki";


function resetDataDir() {
	// Rename data directory for fresh test
	var ts = GPSystem.dateTimeByteString().toString(HEX) + crypto.generateRandom(2).toString(HEX);
	var of = new java.io.File(param["datadir"]);
	var nf = new java.io.File(param["datadir"] + "_" + ts);
	of.renameTo(nf);
}



function HTTPTester(baseurl) {
	this.baseurl = baseurl;
}



HTTPTester.prototype.call = function(relativeurl, expectedResult) {
	var url = this.baseurl + relativeurl;
	
	GPSystem.trace("  Trying " + url);
	var c = new URLConnection(url);

	try	{
		var content = c.get();
		GPSystem.trace(content);
	}
	catch(e) {
		GPSystem.trace(c.serverErrorMessage);
		throw new GPError("HTTPTester", GPError.DEVICE_ERROR, 0, "Server error " + c.responseCode);
	}
	
	var html = content.match(/<html>[\s\S]*<\/html>/);
	var x = new XML(html);
	var result = x..div.(@id == "content").p.toString();

	if ((typeof(expectedResult) != "undefined") && (result != expectedResult)) {
		GPSystem.trace(content);
		throw new GPError("HTTPTester", GPError.DEVICE_ERROR, 0, "Error - result (" + result + ") does not match expected result (" + expectedResult + ")");
	}
}


var testRunner = new TestRunner("EAC PKI Test Suite");

testRunner.addTestGroupFromXML("tg_getcacertificates.xml", param);
testRunner.addTestGroupFromXML("tg_getcacertificatesfromspoc.xml", param);
testRunner.addTestGroupFromXML("tg_requestcertificate_dvca.xml", param);
testRunner.addTestGroupFromXML("tg_requestforeigncertificate_dvca.xml", param);

print("Test-Suite loaded...");
