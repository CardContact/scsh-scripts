/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|
 * |#       #|  Copyright (c) 1999-2017 CardContact System GmbH
 * |'##> <##'|  32429 Minden, Germany (www.cardcontact.de)
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
 *  @fileoverview Script implementing a read strategie as defined by Gematik "Implementierungsleitfaden Basis-Rollout"
 */



/**
 * Class that allows reading a German eGK Generation 1,1+ and 2
 *
 * @constructor
 * @param {Card} card the card handle
 */
function eGKReader(card) {
	this.card = card;
}



eGKReader.MF_AID = new ByteString("D2760001448000", HEX);
eGKReader.HCA_AID = new ByteString("D27600000102", HEX);



/**
 * Select MF
 */
eGKReader.prototype.selectMF = function() {
	print("Select MF");
	this.card.sendApdu(0x00, 0xA4, 0x04, 0x0C, eGKReader.MF_AID, [0x9000]);
}



/**
 * Select HCA
 */
eGKReader.prototype.selectHCA = function() {
	print("Select HCA");
	this.card.sendApdu(0x00, 0xA4, 0x04, 0x0C, eGKReader.HCA_AID, [0x9000]);
}



/**
 * Read transparent EF with short file identifier
 *
 * @param {Number} sfi the short file identifier
 * @type ByteString
 * @return the data read from the EF
 */
eGKReader.prototype.readEFwithSFI = function(sfi) {
	var data = this.card.sendApdu(0x00, 0xB0, 0x80 + sfi, 0x00, 0, [0x9000]);
	return data;
}



/**
 * Determine the maximum APDU size by parsing the content of EF.ATR
 */
eGKReader.prototype.determineMaxAPDU = function() {
	// Read EF.ATR
	var efatr = this.readEFwithSFI(0x1D);

	print("EF.ATR:");
	var a = new ASN1(efatr);
	print(a);

	this.capdulen = a.get(0).value.toUnsigned();
	this.rapdulen = a.get(1).value.toUnsigned();

	print("Maximum C-Data Length: " + this.capdulen);
	print("Maximum R-Data Length: " + this.rapdulen);
}



/**
 * Determine the version numbers from EF.VERSION
 */
eGKReader.prototype.determineVersion = function() {
	// Read EF.VERSION
	var rec1 = this.card.sendApdu(0x00, 0xB2, 0x01, 0x04 + (0x10 << 3), 0, [0x9000]);
	var vstr = rec1.toString(HEX);
	print("Version eGK Specification Part 1: " + vstr.substr(0, 3) + "." + vstr.substr(3, 3) + "." + vstr.substr(6, 4));

	var rec2 = this.card.sendApdu(0x00, 0xB2, 0x02, 0x04, 0, [0x9000]);
	var vstr = rec2.toString(HEX);
	print("Version eGK Specification Part 2: " + vstr.substr(0, 3) + "." + vstr.substr(3, 3) + "." + vstr.substr(6, 4));

	var rec3 = this.card.sendApdu(0x00, 0xB2, 0x03, 0x04, 0, [0x9000]);
	var vstr = rec3.toString(HEX);
	print("Version Data Structure          : " + vstr.substr(0, 3) + "." + vstr.substr(3, 3) + "." + vstr.substr(6, 4));
}



/**
 * Determine the status of data contained in EF.VD
 */
eGKReader.prototype.determineStatus = function() {
	// Read EF.StatusVD
	var efStatusVD = this.readEFwithSFI(0x0C);
	print("Transaction pending             : " + (efStatusVD.byteAt(0) == 0x30 ? "No" : "Yes"));
	print("Last Update                     : " + efStatusVD.bytes(1, 14).toString(ASCII));

	var vstr = efStatusVD.bytes(15, 5).toString(HEX);
	print("Schema Version                  : " + vstr.substr(0, 3) + "." + vstr.substr(3, 3) + "." + vstr.substr(6, 4));
}



/**
 * Unzip content read from card
 *
 * @param {ByteString} zipbs zipped ByteString
 * @type ByteString
 * @return unzipped content
 */
eGKReader.prototype.unzip = function(zipbs) {
	var bais = new java.io.ByteArrayInputStream(zipbs);
	var zip = new java.util.zip.GZIPInputStream(bais);

	var fc = java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, 10000);
	var len = zip.read(fc, 0, 10000);

	//	print("Read from zip = " + len);
	//	print(fc);
	var bb = new ByteBuffer(fc);
	var bs = bb.toByteString().left(len);
	print(bs.toString(ASCII));
	return bs;
}



/**
 * Read a range in the already selected EF
 *
 * @param {Number} ofs the offset to read from
 * @param {Number} length the number of bytes to read
 * @type ByteString
 * @return the data read from the range
 */
eGKReader.prototype.readRange = function(ofs, length) {
	var maxrdata = this.rapdulen - 2;

	var response = new ByteBuffer();

	while (length > 0) {
		var maxlen = length > maxrdata ? maxrdata : length;
		var data = this.card.sendApdu(0x00, 0xB0, ofs >> 8, ofs & 0xFF, maxlen, [0x9000]);

		response.append(data);
		ofs += data.length;
		length -= data.length;
	}
	return response.toByteString();
}



/**
 * Read EF.PD
 */
eGKReader.prototype.readPD = function() {
	// Read length
	var data = this.card.sendApdu(0x00, 0xB0, 0x81, 0x00, 2, [0x9000]);
	var length = data.toUnsigned();
	print("Length of data in EF.PD : " + length);

	var data = this.readRange(2, length);
	print("EF.PD XML Data:");
	var xmlstr = this.unzip(data);
}



/**
 * Read EF.VD
 */
eGKReader.prototype.readVD = function() {
	// Read length
	var data = this.card.sendApdu(0x00, 0xB0, 0x82, 0x00, 8, [0x9000]);

	var osvd = data.bytes(0, 2).toUnsigned();
	var oevd = data.bytes(2, 2).toUnsigned();
	var osgvd = data.bytes(4, 2).toUnsigned();
	var oegvd = data.bytes(6, 2).toUnsigned();

	print("Offset Start VD  : " + osvd);
	print("Offset End VD    : " + oevd);
	print("Offset Start GVD : " + osgvd);
	print("Offset End GVD   : " + oegvd);

	if (osvd != 0xFFFF) {
		var data = this.readRange(osvd, oevd - osvd + 1);
		print("VD XML Data:");
		var xmlstr = this.unzip(data);
	}
	if (osgvd != 0xFFFF) {
		var data = this.readRange(osgvd, oegvd - osgvd + 1);
		print("GVD XML Data:");
		var xmlstr = this.unzip(data);
	}
}



var card = new Card(_scsh3.reader);

card.reset(Card.RESET_COLD);

var egk = new eGKReader(card);

egk.selectMF();
egk.determineMaxAPDU();

// Read EF.GDO
var efgdo = egk.readEFwithSFI(0x02);

print("EF.GDO:");
print(new ASN1(efgdo));

egk.determineVersion();
egk.selectHCA();
egk.determineStatus();
egk.readPD();
egk.readVD();

