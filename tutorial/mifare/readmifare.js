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

var keyid = 0x1A;

var key = new ByteString("FFFFFFFFFFFF", HEX);
mif.loadKey(keyid, key);

var dump = new ByteBuffer();

for (var block = 0; block < 16*4; block++) {
	mif.authenticate(block, Mifare.KEY_A, keyid);
	dump.append(mif.readBlock(block));
}

print(dump.toByteString());

var s = mif.newSector(0);
s.setKeyId(keyid);
s.readAll();
print(s.toString());

s.setKeyA(new ByteString("A0A1A2A3A4A5", HEX));
print(s.toString());
s.setKeyB(new ByteString("B0B1B2B3B4B5", HEX));
print(s.toString());
s.setHeaderDataByte(new ByteString("AA", HEX));
print(s.toString());

var data = new ByteString("Hello World !!!!", ASCII);
s.update(1, data);
 
