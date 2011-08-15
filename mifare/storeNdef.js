//versuch

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
 * @fileoverview Example to initialize an application directory on a Mifare 1K card
 */

load("mifare.js");

function Loader() {

}

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
	// s.setACforBlock(1, Sector.AC_UPDATEKEYB);
	// s.setACforBlock(2, Sector.AC_UPDATEKEYB);
	// s.setACforBlock(3, Sector.AC_UPDATE_WITH_KEYB);

	var mad = new ByteString("0103E103E103E103E103E103E103E103E103E103E103E103E103E103E103E1", HEX);
	var crc = Mifare.crc8(mad);
	var mad = ByteString.valueOf(crc,1).concat(mad);

	s.update(1, mad.bytes(0, 16));
	s.update(2, mad.bytes(16, 16));
	s.update(3);

	print(s.toString());
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////	
Loader.prototype.load = function(data) {
	var empty = new ByteString("00000000000000000000000000000000", HEX);
	//var ndef = new ByteString("030CD1010855016E66632E636F6DFE00", HEX);

	//var ndef = new ByteString("0000030CD1010855016E66632E636F6D", HEX);
//	424547494E3A56434152440A464E3A4D6178204D75737465726D616E6E0A4F52473A43617264436F6E746163740A54454C3A303537310A454D41494C3B545950453D696E7465726E65743A43617264436F6E746163744043617264436F6E746163742E64650A55524C3A7777772E63617264636F6E746163742E64650A454E443A5643415244
	print("starte splitData");
	var arr = Loader.splitData(data);
	// for (var i = 0; i < arr.length; i++) {
		// print(arr.pop());
	// }
	var countSectors = Math.round(arr.length / 3);
	
	print("countSectors");
	print(countSectors);
	assert(countSectors <= 15);

	for (var i = 1; i <= countSectors ; i++) {
		print("Schreibe in Sector " + i);
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

		if (arr.length != 0) {
			s.update(0, arr.pop());
		}
		if (arr.length != 0) {
			//print(arr.length);
			//print(arr.pop());
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
	print("beginne mit splitting");
	var b = new ByteBuffer();
	//insert tag byte
	b.append(new ByteString("03", HEX));
	
	print("data: " + data);
	
	var length = data.length;
	print("length: " + length);
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
	print(arr[0]);
	
	while (data.length != 0) {
		print("bin in while-schleife");
		if (data.length == 16) {
			print(data.bytes(0, 16));
			arr.push(data.bytes(0, 16));
			//data = data.bytes(17);
			return arr.reverse();
		}
		else if (data.length > 16) {
			print(data.bytes(0, 16));
			arr.push(data.bytes(0, 16));
			data = data.bytes(17);
		}
		else {
			var tmp = data.bytes(0);
			//padding
			tmp = tmp.concat(new ByteString("FE", HEX));
			var pad = new ByteString("00000000000000000000000000000000", HEX);
			tmp = tmp.concat(pad.bytes(0, 16 - tmp.length));
			
			
			// for (var i = tmp.length; i < 16; i++) {
				// print("bin in for-schleife");
				// tmp = tmp.concat(ByteString.valueOf(0));
				// print(tmp);
			// }
			arr.push(tmp);
			print(tmp);
			return arr.reverse();
		}
	}
	
	return arr.reverse();
}

