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
 * @fileoverview Example to initialize an NDEF application directory on a Mifare 1K card
 */

load("mifare.js");


var card = new Card(_scsh3.reader);

card.reset(Card.RESET_COLD);

var mif = new Mifare(card);

print("UID: " + mif.getUID());

if (_scsh3.reader.substr(0, 3) != "SCM") {
	var keyaid = 0x00;			// Use for ACR and Omnikey readers
} else {
	print("SCM Reader detected.");
	var keyaid = 0x60;			// Use for SCS SDI 010 and 011
}

var key = new ByteString("FFFFFFFFFFFF", HEX);
mif.loadKey(keyaid, key);


var s = mif.newSector(0);
s.setKeyId(keyaid);
s.readAll(Mifare.KEY_A);
print(s.toString());

s.setKeyA(new ByteString("A0A1A2A3A4A5", HEX));
s.setKeyB(new ByteString("B0B1B2B3B4B5", HEX));
s.setHeaderDataByte(new ByteString("C1", HEX));

s.setACforBlock(1, Sector.AC_UPDATEKEYB);
s.setACforBlock(2, Sector.AC_UPDATEKEYB);
s.setACforBlock(3, Sector.AC_UPDATE_WITH_KEYB);

var mad = new ByteString("0103E103E103E103E103E103E103E103E103E103E103E103E103E103E103E1", HEX);
var crc = Mifare.crc8(mad);
var mad = ByteString.valueOf(crc,1).concat(mad);

s.update(1, mad.bytes(0, 16));
s.update(2, mad.bytes(16, 16));
s.update(3);

print(s.toString());

var empty = new ByteString("00000000000000000000000000000000", HEX);
var ndef = new ByteString("030CD1010855016E66632E636F6DFE00", HEX);

//var ndef = new ByteString("0000030CD1010855016E66632E636F6D", HEX);

for (var i = 1; i < 2; i++) {
	var s = mif.newSector(i);
	s.setKeyId(keyaid);
	s.readAll(Mifare.KEY_A);
	//print(s.toString());

	s.setKeyA(new ByteString("D3F7D3F7D3F7", HEX));
	s.setKeyB(new ByteString("B0B1B2B3B4B5", HEX));
	s.setHeaderDataByte(new ByteString("40", HEX)); //muss laut spec auf 0x40 stehen

	s.setACforBlock(0, Sector.AC_UPDATEKEYB);
	s.setACforBlock(1, Sector.AC_UPDATEKEYB);
	s.setACforBlock(2, Sector.AC_UPDATEKEYB);
	s.setACforBlock(3, Sector.AC_UPDATE_WITH_KEYB);

	s.update(0, ndef);
	s.update(1, empty);
	s.update(2, empty);
	s.update(3);
	
	print(s.toString());
}
