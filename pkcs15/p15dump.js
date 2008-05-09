/*
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
 *  Tool to analyse PKCS#15 / ISO 7816-15 structure on a Smart Card
 */

load("tools/p15classes.js");



// -----------------------------------------------------------------
// Main entry

var card = new Card(_scsh3.reader);
var p15 = new PKCS15(card);

p15.readApplicationDirectory();

var aidlist = p15.getAidList();

var i;
for (aid in aidlist) {
	print("Application : " + aid);
	at = aidlist[aid];
	print("Application Template from EF.DIR :");
	print(at);
	print("----------");
	
	if (!at.ddo) {
		if (aid == "A000000063504B43532D3135") {
			print("PKCS#15");
			i = aid;
			var t = new ASN1(new ByteString("7314300804063F0050155031A00804063F0050155032", HEX));
			at.ddo = new PKCS15_CIODDO(t);
		}
	}
	if (at.ddo) {
		if (at.ddo.ciaInfoPath) {
			var cia = p15.getCIAInfo(at.ddo.ciaInfoPath);
			print("CIAInfo : ");
			print(cia);
		}

		p15.readObjectListForApplication(at);

		for (var i = 0; i < at.objlist.length; i++) {
			var o = at.objlist[i];
			print(o.type + " \"" + o.label + "\"");
			print(o);
			print("----------");
		}
	}
}
