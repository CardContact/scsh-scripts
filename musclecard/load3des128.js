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
 *  Load a 112 bit double length, triple DES key
 */

load("tools.js");

var testkey = new Key("profiles/kp_double_des.xml");


var card = new Card(_scsh3.reader);
card.reset(Card.RESET_COLD);


// Select Applet
card.sendApdu(0x00, 0xA4, 0x04, 0x00, mcaid, [0x9000]);

// 3DES double length key blob
var keyblob = new ByteString("00"	// BLOB_ENC_PLAIN
			   + "07"	// Tripple DES, double length key
			   + "0080"	// 128 Bit length
			   + "0010"	// 16 Byte component
			   , HEX);
			   
keyblob = keyblob.concat(testkey.getComponent(Key.DES));

// MSCCreateObject
card.sendApdu(0xB0, 0x5A, 0x00, 0x00, new ByteString("FFFFFFFE00000016000000000000", HEX), [0x9000]);

// MSCWriteObject
// data = 4b Objid | 4b Offs | 1b Length | value
var data = new ByteBuffer("FFFFFFFE00000000", HEX);
data.append(keyblob.length);
data.append(keyblob);

card.sendApdu(0xB0, 0x54, 0x00, 0x00, data.toByteString(), [0x9000]);

// MSCImportKey
card.sendApdu(0xB0, 0x32, 0x04, 0x00, new ByteString("000000000000", HEX), [0x9000]);
