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
 * @fileoverview Script to post a CV-Certificate to a DVCA using a SendCertificates service call
 */

load("../dvcaconnection.js");
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
		_scsh3.setProperty(id, value.replace(/\\/g, "/"));
	}
	return value;
}



var url = prompt("Enter the URL of the DVCA service endpoint", "dvcaurl", "http://localhost:8080/se/dvca");
var certfile = prompt("Select certificate", "certfilename", "c:/data", "*.cvcert");

var certbin = CVCertificateStore.loadBinaryFile(certfile);

var cert = new CVC(certbin);

var dc = new DVCAConnection(url);

dc.sendCertificates([cert], "Synchronous", "ok_cert_available");

