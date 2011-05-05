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

var card = new Card(_scsh3.reader);

card.reset(Card.RESET_COLD);

print("UID: " + card.sendApdu(0xFF,0xCA,0x00,0x00,0, [0x9000]));

var keyid = 0x1A;

var key = new ByteString("FFFFFFFFFFFF", HEX);
card.sendApdu(0xFF,0x82,0x20,keyid, key, [0x9000]);

var dump = new ByteBuffer();

for (var block = 0; block < 16*4; block++) {
	var bb = new ByteBuffer();
	bb.append(0x01);							// Version
	bb.append(ByteString.valueOf(block, 2));
	bb.append(0x60);
	bb.append(keyid);
	card.sendApdu(0xFF,0x86,0x00,0x00, bb.toByteString(), [0x9000]);

	// Read sector

	dump.append(card.sendApdu(0xFF,0xB0,block >> 8,block & 0xFF,0,[0x9000]));
}

print(dump.toByteString());
