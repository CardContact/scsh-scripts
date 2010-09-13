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
 * @fileoverview Script to populate a certificate store from a directory full of certificates
 */


load("cvcertstore.js");



var inputdir = "testcvcs";
var outputdir = "testcvcs/certstore";


function listCertificates(dir) {
	var f = new java.io.File(dir);
	var files = f.list();
	var result = [];
	
	for (var i = 0; i < files.length; i++) {
		var s = new String(files[i]);
		var n = s.match(/\.(cvcert|CVCERT)$/);
		if (n) {
			var bin = CVCertificateStore.loadBinaryFile(dir + "/" + s);
			var cvc = new CVC(bin);
			result.push(cvc);
		}
	}
	return result;
}



var inputdir = GPSystem.mapFilename(inputdir, GPSystem.CWD);
var outputdir = GPSystem.mapFilename(outputdir, GPSystem.CWD);

var crypto = new Crypto();

var store = new CVCertificateStore(outputdir);
var certlist = listCertificates(inputdir);

for (var i = 0; i < certlist.length; i++) {
	print(certlist[i]);
}

var unprocessed = store.insertCertificates2(crypto, certlist, true);

if (unprocessed.length > 0) {
	print("The following certificates could not be processed:");
	for (var i = 0; i < unprocessed.length; i++) {
		print(unprocessed[i]);
	}
}
