/*
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
 * Simple test suite for APDU test applet
*/
 
var aid = new ByteString("E82B0601040181C31F0202", HEX);

var crypto = new Crypto();

var card = new Card(_scsh3.reader);
card.reset(Card.RESET_COLD);

// Select application
var rsp = card.sendApdu(0x00, 0xA4, 0x04, 0x04, aid, 0x00, [0x9000]);
print(new ASN1(rsp));

// Case 1 - Exceptions
card.sendApdu(0x00, 0xF1, 0x01, 0x00, [0x6A86]);
card.sendApdu(0x00, 0xF1, 0x00, 0x01, [0x6A86]);
card.sendApdu(0x00, 0xF1, 0x00, 0x00, new ByteString("FOO", ASCII), [0x6700]);
card.sendApdu(0x00, 0xF1, 0x00, 0x00, 0x00, [0x6700]);

// Case 1
card.sendApdu(0x00, 0xF1, 0x00, 0x00, [0x9000]);
var infoBlock = card.sendApdu(0x00, 0xF0, 0x00, 0x00, 0x00, [0x9000]);
print(infoBlock);

// Case 2 - Exceptions
var rsp = card.sendApdu(0x00, 0xF2, 0x00, 0xFA, new ByteString("FOO", ASCII), 0x00, [0x6700]);
var rsp = card.sendApdu(0x00, 0xF2, 0x00, 0x00, 0x00, [0x9000]);
var rsp = card.sendApdu(0x00, 0xF2, 0x00, 0x00, 0x20, [0x6282]);
assert(rsp.length == 0);
var rsp = card.sendApdu(0x00, 0xF2, 0x00, 0x10, 0x20, [0x6282]);
assert(rsp.length == 0x10);

// Case 2 short - request 250 bytes
var rsp = card.sendApdu(0x00, 0xF2, 0x00, 0xFA, 0x00, [0x9000]);
assert(rsp.length == 250);
var infoBlock = card.sendApdu(0x00, 0xF0, 0x00, 0x00, 0x00, [0x9000]);
print(infoBlock);

// Case 2 extended - request 4096 bytes
var rsp = card.sendApdu(0x00, 0xF2, 0x10, 0x00, 65536, [0x9000]);
assert(rsp.length == 4096);
var infoBlock = card.sendApdu(0x00, 0xF0, 0x00, 0x00, 0x00, [0x9000]);
print(infoBlock);

// Case 3 - exceptions
var data = crypto.generateRandom(255);
card.sendApdu(0x00, 0xF3, 0x01, 0x00, data, [0x6A86]);
card.sendApdu(0x00, 0xF3, 0x00, 0x01, data, [0x6A86]);
card.sendApdu(0x00, 0xF3, 0x00, 0x00, 0x00, [0x6700]);

// Case 3 short - send 255 bytes
var data = crypto.generateRandom(255);
card.sendApdu(0x00, 0xF3, 0x00, 0x00, data, [0x9000]);
var infoBlock = card.sendApdu(0x00, 0xF0, 0x00, 0x00, 0x00, [0x9000]);
print(infoBlock);

// Case 3 extended - send 4096 bytes
var data = crypto.generateRandom(4096);
card.sendApdu(0x00, 0xF3, 0x00, 0x00, data, [0x9000]);
var infoBlock = card.sendApdu(0x00, 0xF0, 0x00, 0x00, 0x00, [0x9000]);
print(infoBlock);

// Case 4 - Exceptions
var data = crypto.generateRandom(255);
var rsp = card.sendApdu(0x00, 0xF4, 0x00, 0xFA, data, [0x6700]);
var data = crypto.generateRandom(255);
var rsp = card.sendApdu(0x00, 0xF4, 0x00, 0xFA, 0x00, [0x6700]);
var data = crypto.generateRandom(255);
var rsp = card.sendApdu(0x00, 0xF4, 0x00, 0x00, data, 0x20, [0x6282]);

// Case 4 short - send 255 bytes, request 250 bytes
var data = crypto.generateRandom(255);
var rsp = card.sendApdu(0x00, 0xF4, 0x00, 0xFA, data, 0x00, [0x9000]);
assert(rsp.length == 250);
var infoBlock = card.sendApdu(0x00, 0xF0, 0x00, 0x00, 0x00, [0x9000]);
print(infoBlock);

// Case 4 extended - send 4096 bytes, request 4096 bytes
var data = crypto.generateRandom(4096);
var rsp = card.sendApdu(0x00, 0xF4, 0x10, 0x00, data, 65536, [0x9000]);
assert(rsp.length == 4096);
var infoBlock = card.sendApdu(0x00, 0xF0, 0x00, 0x00, 0x00, [0x9000]);
print(infoBlock);
