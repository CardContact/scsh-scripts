/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2009 CardContact Software & System Consulting
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
 * @fileoverview Class supporting EMV cards
 */


load("emv.js");
load("emvview.js");
load("dataAuthentication.js");
//load("transaction.js");

// Example code
var card = new Card(_scsh3.reader);
card.reset(Card.RESET_COLD);

var crypto = new Crypto();

var e = new EMV(card, crypto);
var v = new EMVView(e);

var d = new DataAuthentication(e);
d.addSchemePublicKey(new ByteString("A000000003", HEX), 1, new Key("schemepublickeys/kp_visa_1024_01.xml"));
d.addSchemePublicKey(new ByteString("A000000003", HEX), 7, new Key("schemepublickeys/kp_visa_1152_07.xml"));
d.addSchemePublicKey(new ByteString("A000000003", HEX), 8, new Key("schemepublickeys/kp_visa_1408_08.xml"));
d.addSchemePublicKey(new ByteString("A000000003", HEX), 9, new Key("schemepublickeys/kp_visa_1984_09.xml"));


e.selectPSE(false);

var aid = e.getAID();

if (aid != null) {
	e.selectADF(aid);
} else {
	e.tryAID();
}


e.initApplProc();
e.readApplData();

v.displayDataElements();

//d.decryptIssuerPKCertificate();

var issuerPublicKeyModulus = d.retrievalIssuerPublicKey();

d.verifySSAD(issuerPublicKeyModulus);

var  iccPublicKeyModulus = d.retrievalICCPublicKey(issuerPublicKeyModulus);
d.dynamicDataAuthentication(iccPublicKeyModulus);

e.generateAC();

var getData = card.sendApdu(0x80, 0xCA, 0x9F36, 0x9F36, 0x00);
print(getData);



/*
p1
0x00 = AAC = reject transaction
0x40 = TC = proceed offline
0x80 = ARQC = go online


var p1 = 0x40;

var authorisedAmount = new ByteString("000000000001", HEX);
var secondaryAmount = new ByteString("000000000000", HEX);
var tvr = new ByteString("0000000000", HEX);
var transCurrencyCode = new ByteString("0978", HEX);
var transDate = new ByteString("090730", HEX);
var transType = new ByteString("21", HEX);
var unpredictableNumber = crypto.generateRandom(4);
var iccDynamicNumber = card.sendApdu(0x00, 0x84, 0x00, 0x00, 0x00);
var DataAuthCode = e.cardDE[0x9F45];

var Data = authorisedAmount.concat(secondaryAmount).concat(tvr).concat(transCurrencyCode).concat(transDate).concat(transType).concat(unpredictableNumber).concat(iccDynamicNumber).concat(DataAuthCode); 

var generateAC = card.sendApdu(0x80, 0xAE, p1, 0x00, Data, 0x00);
*/

card.close();
