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
 * @fileoverview Example to read from a Mifare classic card using a shell script
 */

load("mifare.js");


var card = new Card(_scsh3.reader);

card.reset(Card.RESET_COLD);

var mif = new Mifare(card);

print("UID: " + mif.getUID());

// var keyaid = 0x01;			// Use for ACR and Omnikey readers
var keyaid = 0x60;			// Use for SCS SDI 010 and 011

for (var i = 0; i < 16; i++) {
	var s = mif.newSector(i);
	s.setKeyId(keyaid);

	var ki = s.authenticatePublic(0, Mifare.KEY_A);
	if (ki >= 0) {
		print("Authentication with " + Mifare.PUBLICKEYS[ki].toString(HEX) + " successfull");
		s.read(0);
		s.read(1);
		s.read(2);
		s.read(3);
		print(s.toString());
	} else {
		print("Unknown key A - skipping sector " + i);
	}
}
