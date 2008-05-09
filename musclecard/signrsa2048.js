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
 *  Sign with a 2048 bit RSA key
 *  Key must have been generated with genrsa2048.js
 */

load("tools.js");

var card = new Card(_scsh3.reader);
card.reset(Card.RESET_COLD);


// Select Applet
card.sendApdu(0x00, 0xA4, 0x04, 0x00, mcaid, [0x9000]);

print("Reading public key...");
// MSCExportKey
card.sendApdu(0xB0, 0x34, 0x03, 0x00, new ByteString("00", HEX), [0x9000]);

var kb = readKeyBlob(card);

print(kb.header);
print("Modulus : " + kb[0]);
print("Exponent: " + kb[1]);

var puk = new Key();
puk.setType(Key.PUBLIC);
puk.setComponent(Key.MODULUS, kb[0]);
puk.setComponent(Key.EXPONENT, kb[1]);

// MSCVerifyPIN
card.sendApdu(0xB0, 0x42, 0x00, 0x00, new ByteString("12345678", ASCII), [0x9000]);

print("Signing data...");
//var msg = new ByteString("Hello World", ASCII);
var msg = new ByteString("01020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708", HEX);

// MSCComputeCrypt / Cipher Init / data = cipher mode | cipher direction | data location | chunk size (2) | chunk
// Warning: cipher mode definition in mcardprot-1.2.1.pdf is wrong for RSA_NO_PAD(=0) and RSA_PAD_PKCS1(=1)
card.sendApdu(0xB0, 0x36, 0x02, 0x01, new ByteString("0003010000", HEX), [0x9000]);

var data = new ByteBuffer();
data.append(msg.length >> 8);
data.append(msg.length && 0xFF);
data.append(msg);

// MSCCreateObject
card.sendApdu(0xB0, 0x5A, 0x00, 0x00, new ByteString("FFFFFFFE00000102000000000000", HEX), [0x9000]);

// MSCWriteObject
var body = (new ByteString("FFFFFFFE0000000082", HEX)).concat(data.toByteString().bytes(0x00, 0x82));
var resp = card.sendApdu(0xB0, 0x54, 0x00, 0x00, body, [0x9000]);
var body = (new ByteString("FFFFFFFE0000008280", HEX)).concat(data.toByteString().bytes(0x82, 0x80));
var resp = card.sendApdu(0xB0, 0x54, 0x00, 0x00, body, [0x9000]);


// MSCComputeCrypt / Cipher Final / data = data location
card.sendApdu(0xB0, 0x36, 0x02, 0x03, new ByteString("02", HEX), [0x9000]);

var resp = card.sendApdu(0xB0, 0x56, 0x00, 0x00, new ByteString("FFFFFFFF00000000FF", HEX), [0x9000]);
resp = resp.concat(card.sendApdu(0xB0, 0x56, 0x00, 0x00, new ByteString("FFFFFFFF000000FF03", HEX), [0x9000]));
var cryptogram = resp.bytes(2);
print(cryptogram);

var crypto = new Crypto();

var plain = crypto.decrypt(puk, Crypto.RSA, cryptogram);
print(plain);

assert(plain.equals(msg));
