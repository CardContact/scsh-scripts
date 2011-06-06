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
 * @fileoverview Script to load all SPOC tests
 */


load("tools/TestRunner.js");
load("tools/TestGroup.js");
load("tools/TestProcedure.js");

load("../cvc.js");
load("../cvcertstore.js");
load("../cvca/cvcca.js");
load("../lib/paconnection.js");
load("../lib/riconnection.js");
load("../lib/taconnection.js");




/**
 * Prompt for a value from persistent configuration
 * 
 * The new value is stored a configuration item. Backslashes are properly escaped.
 * 
 * @param {String} text the text to display
 * @param {String} id the configuration item
 * @param {String} defvalue the default value
 * @return the selected value
 */
function prompt(text, id, defvalue, list, filter) {
	if (typeof(_scsh3[id]) != "undefined") {
		var value = _scsh3[id];
	} else {
		var value = defvalue;
	}
	var value = Dialog.prompt(text, value, list, filter);
	if (value == null) {
		throw new Error("User abort");
	} else {
		_scsh3.setProperty(id, value.replace(/\\/g, "/"));
	}
	return value;
}



var storePIN = prompt("Enter keystore PIN", "TLSStorePIN", "", null);

var param = new Array();

var baseURL = prompt("Enter base URL for services", "SPOCBaseURL", "", ["https://localhost:8443/se"]);


param["crypto"] = new Crypto();

param["dvcapath"] = null;		// Set by GetCACertificates, if not defined here
param["holderID"] = "UTTEST";
param["cwd"] = GPSystem.mapFilename("", GPSystem.CWD);
param["certstore"] = new CVCertificateStore(param["cwd"] + "/data");

var ks = new KeyStore("SUN", "jks", "clientkeystore.jks", storePIN);

param["keystore"] = ks;
param["keystorepasswd"] = storePIN;
param["privateKeyPIN"] = storePIN;

var ts = new KeyStore("SUN", "jks", "truststore.jks", storePIN);

param["truststore"] = ts;

param["baseURL"] = baseURL;

var c = new URLConnection(baseURL + "/spoc");
c.setTLSKeyStores(ts, ks, storePIN);
param["taURL" ] = c;

var c = new URLConnection(baseURL  + "/spoc");
c.setTLSKeyStores(ts, ks, storePIN);
param["paURL" ] = c;



java.lang.System.setProperty("javax.net.debug", "ssl:handshake");


var testRunner = new TestRunner("SPOC Tests");

testRunner.addTestProcedureFromXML("tp_cvc.xml");
testRunner.addTestGroupFromXML("terminalauth/tg_gc_spoc.xml", param);
testRunner.addTestGroupFromXML("passiveauth/tg_gc_masterlist_spoc.xml", param);
testRunner.addTestGroupFromXML("restrictedID/tg_gc_blacklist_dv.xml", param);

// testRunner.enable("tg_gc_dvca/011RequestInitialCertificateDVCA", false);

print("Test-Suite loaded...");
