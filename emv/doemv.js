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
 * @fileoverview Example script performing an emv transaction.
 */


load("emv.js");
load("emvView.js");
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

var issuerPublicKeyModulus = d.retrieveIssuerPublicKey();

d.verifySSAD(issuerPublicKeyModulus);

var  iccPublicKeyModulus = d.retrieveICCPublicKey(issuerPublicKeyModulus);
d.dynamicDataAuthentication(iccPublicKeyModulus);

e.generateAC();

//var getData = card.sendApdu(0x80, 0xCA, 0x9F, 0x36, 0x00);
//print(getData);


card.close();
