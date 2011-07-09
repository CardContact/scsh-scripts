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
 * @fileoverview Reset card to transport configuration
 */

load("mifare.js");


var card = new Card(_scsh3.reader);

card.reset(Card.RESET_COLD);

var mif = new Mifare(card);

print("UID: " + mif.getUID());

if (_scsh3.reader.substr(0, 3) != "SCM") {
	var keyaid = 0x00;			// Use for ACR and Omnikey readers
	var keybid = 0x01;			// Use for ACR and Omnikey readers
} else {
	print("SCM Reader detected.");
	var keyaid = 0x60;			// Use for SCS SDI 010 and 011
	var keybid = 0x61;			// Use for SCS SDI 010 and 011
}

var empty = new ByteString("00000000000000000000000000000000", HEX);

for (var i = 0; i < 16; i++) {
	var s = mif.newSector(i);
	s.setKeyId(keyaid, Mifare.KEY_A);
	s.setKeyId(keybid, Mifare.KEY_B);
	
	var ki = s.authenticatePublic(0, Mifare.KEY_A);

	if (ki < 0) {
		print("Unknown key A - skipping sector " + i);
		continue;
	}
	
	var header = s.read(3);
	print(s.toString());

	var ac = s.getACforBlock(3);
	if (ac == Sector.AC_UPDATE_WITH_KEYB) {
		var ki = s.authenticatePublic(0, Mifare.KEY_B);
		
		if (ki < 0) {
			print("Unknown key B - skipping sector " + i);
			continue;
		}
	}
	
	s.setKeyA(new ByteString("FFFFFFFFFFFF", HEX));
	s.setKeyB(new ByteString("FFFFFFFFFFFF", HEX));
	s.setHeaderDataByte(new ByteString("69", HEX));

	s.setACforBlock(0, Sector.AC_ALWAYS);
	s.setACforBlock(1, Sector.AC_ALWAYS);
	s.setACforBlock(2, Sector.AC_ALWAYS);
	s.setACforBlock(3, Sector.AC_UPDATE_AC_NOKEY_B);
	
	s.update(3);
	
	var key = new ByteString("FFFFFFFFFFFF", HEX);
	mif.loadKey(keyaid, key);
	s.authenticate(0, Mifare.KEY_A);
	
	if (i > 0) {
		s.update(0, empty);
	}
	s.update(1, empty);
	s.update(2, empty);
}
