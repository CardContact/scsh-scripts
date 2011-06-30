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

var keyid = 0x01;

var empty = new ByteString("00000000000000000000000000000000", HEX);

for (var i = 0; i < 16; i++) {
	var s = mif.newSector(i);
	s.setKeyId(keyid);
	
	var key = new ByteString("FFFFFFFFFFFF", HEX);
	mif.loadKey(keyid, key);
	
	if (!s.authenticate(0, Mifare.KEY_A)) {
		var key = new ByteString("A0A1A2A3A4A5", HEX);
		mif.loadKey(keyid, key);
		
		if (!s.authenticate(0, Mifare.KEY_A)) {
			print("Unknown key A - skipping sector " + i);
			continue;
		}
	}
	var header = s.read(3);
	print(s.toString());
	
	var ac = s.getACforBlock(3);
	if (ac == Sector.AC_UPDATE_WITH_KEYB) {
		var key = new ByteString("FFFFFFFFFFFF", HEX);
		mif.loadKey(keyid, key);
		if (!s.authenticate(0, Mifare.KEY_B)) {
			var key = new ByteString("B0B1B2B3B4B5", HEX);
			mif.loadKey(keyid, key);
		
			if (!s.authenticate(0, Mifare.KEY_B)) {
				print("Unknown key B - skipping sector " + i);
				continue;
			}
		}
	}
	
	s.setKeyA(new ByteString("FFFFFFFFFFFF", HEX));
	s.setKeyB(new ByteString("FFFFFFFFFFFF", HEX));
	s.setHeaderDataByte(new ByteString("69", HEX));

	s.setACforBlock(0, Sector.AC_ALWAYS);
	s.setACforBlock(1, Sector.AC_ALWAYS);
	s.setACforBlock(2, Sector.AC_ALWAYS);
	s.setACforBlock(3, Sector.AC_UPDATE_AC_NOKEY_B);
	
	if (i > 0) {
		s.update(0, empty);
	}
	s.update(1, empty);
	s.update(2, empty);
	s.update(3);
}
