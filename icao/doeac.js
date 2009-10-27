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
 * @fileoverview Do a complete session with PACE, TA and CA
 */

load("eac20.js");

var crypto = new Crypto();

var certstorepath = GPSystem.mapFilename("cvc", GPSystem.CWD);

var certstore = new CVCertificateStore(certstorepath);


// var card = new EAC20Sim();
var card = new Card(_scsh3.reader);

card.reset(Card.RESET_COLD);

var chat = new ASN1(0x7F4C, 
						new ASN1(ASN1.OBJECT_IDENTIFIER, new ByteString(PACE.id_IS, OID)),
						new ASN1(0x53, new ByteString("23", HEX))
					);

var eac = new EAC20(crypto, card);

print("Reading EF.CardInfo...");
eac.readCardInfo();

print("Performing PACE...");
var pwd = new ByteString("000001", ASCII);
var sm = eac.performPACE(0, EAC20.ID_CAN, pwd, chat);

print("Performing TA...");
var car = eac.getTrustAnchorCAR(false);

var cvcchain = certstore.getCertificateChainFor(car);

eac.verifyCertificateChain(cvcchain);

// Get key for terminal certificate
var termkey = certstore.getTerminalKeyFor(car);

var ad = new ASN1(0x67);

eac.prepareChipAuthentication(0);

eac.performTerminalAuthentication(termkey, ad.getBytes());

print("Reading EF.CardSecurity...");
eac.readCardSecurity();

print("Performing CA...");
eac.performChipAuthentication();

print("Reading using secure messaging...");
var mf = eac.mf;
var ef = new CardFile(mf, ":011C");
ef.readBinary(0, 4);

