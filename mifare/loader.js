/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2011 CardContact Software & System Consulting
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
 * @fileoverview Functions for initialization and loading data on a Mifare 1K card
 */

load("mifare.js");

function Loader() {

}

/**
 *	Initialize an application directory
 */
Loader.prototype.initialize = function() {
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

	s.setACforBlock(0, Sector.AC_UPDATEKEYB);
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
}


/**
 *	Loading the data into the card
 */	
Loader.prototype.load = function(data) {
	var empty = new ByteString("00000000000000000000000000000000", HEX);
	var arr = Loader.splitData(data);
	var countSectors = Math.round(arr.length / 3) + (arr.length % 3);
	assert(countSectors <= 15);

	for (var i = 1; i <= countSectors ; i++) {
		print("Write in sector " + i);
		var s = mif.newSector(i);
		s.setKeyId(keyaid);
		s.readAll(Mifare.KEY_A);

		s.setKeyA(new ByteString("D3F7D3F7D3F7", HEX));
		s.setKeyB(new ByteString("B0B1B2B3B4B5", HEX));
		s.setHeaderDataByte(new ByteString("40", HEX)); //muss laut spec auf 0x40 stehen

		s.setACforBlock(0, Sector.AC_UPDATEKEYB);
		s.setACforBlock(1, Sector.AC_UPDATEKEYB);
		s.setACforBlock(2, Sector.AC_UPDATEKEYB);
		s.setACforBlock(3, Sector.AC_UPDATE_WITH_KEYB);

		if (arr.length != 0) {
			s.update(0, arr.pop());
		}
		if (arr.length != 0) {
			s.update(1, arr.pop());
		}
		else {
			s.update(1, empty);
		}
		if (arr.length != 0) {
			s.update(2, arr.pop());
		}
		else {
			s.update(2, empty);
		}
		s.update(3);
		print(s.toString());
	}
}


/**
 *	Encode data in TLV structure and split it in 16 Byte ByteStrings.
 *	@return {Array}
 */
Loader.splitData = function(data) {
	var b = new ByteBuffer();
	//insert tag byte
	b.append(new ByteString("03", HEX));
		
	var length = data.length;
	if (length < 14) {
		b.append(ByteString.valueOf(length));
		b.append(data.bytes(0));
		//padding
		for (var i = b.length; i < 16; i++) {
			b.append(ByteString.valueOf(0));
		}
	}
	else if (length <= 0xFE) {
		b.append(ByteString.valueOf(length));
		b.append(data.bytes(0, 14));
		data = data.bytes(14);
	}
	else {
		b.append(new ByteString("FF", HEX));
		b.append(ByteString.valueOf(length))
		b.append(data.bytes(0, 12));
		data = data.bytes(12);
	}
	
	var arr = new Array(b.toByteString());
	
	
	while (data.length != 0) {
		if (data.length == 16) {
			arr.push(data.bytes(0, 16));
			return arr.reverse();
		}
		else if (data.length > 16) {
			arr.push(data.bytes(0, 16));
			data = data.bytes(16);
		}
		else {
			var tmp = data.bytes(0);
			//padding
			tmp = tmp.concat(new ByteString("FE", HEX));
			var pad = new ByteString("00000000000000000000000000000000", HEX);
			tmp = tmp.concat(pad.bytes(0, 16 - tmp.length));
			arr.push(tmp);
			return arr.reverse();
		}
	}	
	return arr.reverse();
}

