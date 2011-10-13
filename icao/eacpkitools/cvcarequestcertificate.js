/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2010 CardContact Software & System Consulting
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
 * @fileoverview Request certificate from CVCA
 */

load("../lib/taconnection.js");
load("../cvcertstore.js");


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
function prompt(text, id, defvalue, filter) {
	if (typeof(_scsh3[id]) != "undefined") {
		var value = _scsh3[id];
	} else {
		var value = defvalue;
	}
	var value = Dialog.prompt(text, value, null, filter);
	if (value == null) {
		throw new Error("User abort");
	} else {
		value = value.replace(/\\/g, "/");
		_scsh3.setProperty(id, value);
	}
	return value;
}



var url = prompt("Enter the URL of the CVCA service endpoint", "cvcaurl", "http://localhost:8080/se/cvca");
var reqfile = prompt("Select request", "reqfilename", "c:/data", "*.cvreq");

var reqbin = CVCertificateStore.loadBinaryFile(reqfile);

var req = new CVC(reqbin);

var cc = new TAConnection(url, true);
cc.verbose = true;

var certlist = cc.getCACertificates();

print(req);
var certs = cc.requestCertificate(req);

var dir = reqfile.substr(0, reqfile.lastIndexOf("/") + 1);

for (var i = 0; i < certs.length; i++) {
	var cvc = certs[i];
	print(cvc);
	var filename = dir + cvc.getCHR().toString() + ".cvcert";
	CVCertificateStore.saveBinaryFile(filename, cvc.getBytes());
}
