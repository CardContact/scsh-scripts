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
 * @fileoverview Do a complete eID authentication session with PACE, TA and CA
 */

load("../icao/eac20.js");

// Define Card Access Number
var can = "488444";

// Create the crypto object we require to perform all cryptographic operations
var crypto = new Crypto();

// Allocate a certificate store that contains the required certificate chain and
// a key for terminal authentication
var certstorepath = GPSystem.mapFilename("cvc", GPSystem.CWD);
var terminalpath = "/UTCVCA/UTDVCA/UTTERM";

var certstore = new CVCertificateStore(certstorepath);

// Allocate a card object for access to the card
var card = new Card(_scsh3.reader);

card.reset(Card.RESET_COLD);

// Define the CHAT object we use for the PACE protocol
var chat = new ASN1(0x7F4C, 
						new ASN1(ASN1.OBJECT_IDENTIFIER, new ByteString(PACE.id_IS, OID)),
						new ASN1(0x53, new ByteString("23", HEX))
					);

// Create an EAC object that controls the protocol execution
var eac = new EAC20(crypto, card);

print("Reading EF.CardInfo...");
eac.readCardInfo();

print("Performing PACE...");
var pwd = new ByteString(can, ASCII);
var sm = eac.performPACE(0, EAC20.ID_CAN, pwd, chat);

print("Performing TA...");
var car = eac.getTrustAnchorCAR(false);

// Determine terminal key and build certificate chain to trust anchor
var terminalchr = certstore.getCurrentCHR(terminalpath);
var cvcchain = certstore.getCertificateChain(terminalpath, terminalchr, car);

if (cvcchain == null) {
	throw new Error("No matching certificate chain for CAR " + car);
}

eac.verifyCertificateChain(cvcchain);

// Get key for terminal certificate
var termkey = certstore.getPrivateKey(terminalpath, terminalchr);

// Create authentication data object. Here empty
var ad = new ASN1(0x67);

// Prepare for the later chip authentication step
eac.prepareChipAuthentication(0);

// Perform terminal authentication
eac.performTerminalAuthentication(termkey, ad.getBytes());

print("Reading EF.CardSecurity...");
eac.readCardSecurity();

print("Performing CA...");
eac.performChipAuthentication();

print("Reading using secure messaging...");
var mf = eac.mf;
var ef = new CardFile(mf, ":011C");
var data = ef.readBinary(0);
print(data);

