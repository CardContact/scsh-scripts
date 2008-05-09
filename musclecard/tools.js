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
 *  MuscleCard libary functions
 */


var mcaid = new ByteString("A00000000101", HEX);

var mckeytypes = ["UNKNOWN",
		  "RSA_PUBLIC",
		  "RSA_PRIVATE",
		  "RSA_PRIVATE_CRT",
		  "DSA_PUBLIC",
		  "DSA_PRIVATE",
		  "DES",
		  "TRIPLE_DES",
		  "TRIPLE_DES_3KEY"];

function printStatus(resp) {
	print("Response to MSCGetStatus command APDU: " + resp);
	print("Card Edge Major Version        : " + resp.byteAt(0));
	print("Card Edge Minor Version        : " + resp.byteAt(1));
	print("Software Major Version         : " + resp.byteAt(2));
	print("Software Minor Version         : " + resp.byteAt(3));
	print("Total Object memory            : " + resp.bytes(4, 4).toUnsigned());
	print("Free Object Memory             : " + resp.bytes(8, 4).toUnsigned());
	print("Number of used PINs            : " + resp.byteAt(12));
	print("Number of used Keys            : " + resp.byteAt(13));
	print("Currently Logged in Identities : " + accessMaskToString(resp.bytes(14, 2).toUnsigned(), "none", "all", ","));
}



//
// Return string for bitmap position
//
function accessPermissionToString(ap) {
	if (ap < 8) {
		return "PIN" + ap;
	} else if (ap < 14) {
		return "KEY" + (ap - 8);
	}
	return "RES" + (ap - 14);
}



//
// Convert bitmask to string
//
function accessMaskToString(am, allzero, allone, delim) {
	if (am == 0)
		return allzero;
	if (am == 0xFFFF)
		return allone;
	
	var first = true;
	var str;
	
	for (var i = 0; i < 16; i++) {
		if (am & 1) {
			if (first) {
				str = accessPermissionToString(i);
				first = false;
			} else {
				str += delim + accessPermissionToString(i);
			}
		}
		am >>= 1;
	}
	return str;
}



//
// Return human readable interpretation of access condition
//
function accessConditionToString(ac) {
	return accessMaskToString(ac, "Always", "Never", " and ");
}



//
// Helper function to append a four byte integer in MSB/LSB format to a byte buffer
//
function longToBytes(b, v) {
	b.append((v >> 24) & 0xFF);
	b.append((v >> 16) & 0xFF);
	b.append((v >>  8) & 0xFF);
	b.append((v >>  0) & 0xFF);
}



//
// Read data from MuscleCard object
//
function readObject(card, objid, offset, length) {

	var respbb = new ByteBuffer();
	
	while (length > 0) {
		var nlen = length > 255 ? 255 : length;
		
		var bb = new ByteBuffer();
		longToBytes(bb, objid);
		longToBytes(bb, offset);
		bb.append(nlen);
		
		var resp = card.sendApdu(0xB0, 0x56, 0x00, 0x00, bb.toByteString(), [0x9000]);
		respbb.append(resp);
		length -= nlen;
		offset += nlen;
	}
	return respbb.toByteString();
}



//
// Read key blob for a previously exported key
//
// Return an object with contains the key components as
// 0-based array entries and the property "header" set to
// the value of the key header
//
function readKeyBlob(card) {
	
	var result = new Object();
	
	// Read header
	result.header = readObject(card, 0xFFFFFFFF, 0, 4);

	var complist = [2,	// RSA_PUBLIC
			2,	// RSA_PRIVATE
			5,	// RSA_PRIVATE_CRT
			4,	// DSA_PUBLIC
			4,	// DSA_PRIVATE
			1,	// DES
			1,	// TRIPLE_DES
			1];	// TRIPLE_DES_3KEY

	var ofs = 4;
	var comps = complist[result.header.byteAt(1) - 1];
	for (var i = 0; i < comps; i++) {
		var lenb = readObject(card, 0xFFFFFFFF, ofs, 2);
		var len = lenb.toUnsigned();
		ofs += 2;
		result[i] = readObject(card, 0xFFFFFFFF, ofs, len);
		ofs += len;
	}
	return result;
}
