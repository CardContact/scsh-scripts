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
 *  Sign with a 1024 bit RSA key
 *  Key must have been generated with genrsa1024.js
 */

load("tools.js");

var card = new Card(_scsh3.reader);
card.reset(Card.RESET_COLD);


// Select Applet
card.sendApdu(0x00, 0xA4, 0x04, 0x00, mcaid, [0x9000]);

print("Reading public key...");
// MSCExportKey
card.sendApdu(0xB0, 0x34, 0x01, 0x00, new ByteString("00", HEX), [0x9000]);

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
// var msg = new ByteString("Hello World", ASCII);
var msg = new ByteString("0102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708", HEX);

// MSCComputeCrypt / Cipher Init / data = cipher mode | cipher direction | data location | chunk size (2) | chunk
// Warning: cipher mode definition in mcardprot-1.2.1.pdf is wrong for RSA_NO_PAD(=0) and RSA_PAD_PKCS1(=1)

card.sendApdu(0xB0, 0x36, 0x00, 0x01, new ByteString("0003010000", HEX), [0x9000]);

// MSCComputeCrypt / Cipher Final / data = data location | chunk size (2) | chunk
var data = new ByteBuffer();
data.append(1);		// DL_APDU
data.append(0);
data.append(msg.length);
data.append(msg);

var resp = card.sendApdu(0xB0, 0x36, 0x00, 0x03, data.toByteString(), [0x9000]);
var cryptogram = resp.bytes(2);
print(cryptogram);

var crypto = new Crypto();

var plain = crypto.decrypt(puk, Crypto.RSA, cryptogram);
print(plain);

assert(plain.equals(msg));
