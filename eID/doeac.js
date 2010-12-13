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

// Create object to access certificate store
var certstore = new CVCertificateStore(certstorepath);

// Allocate a card object for access to the card
var card = new Card(_scsh3.reader);

// Reset the card
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

// Determine current trust anchor in nPA
var car = eac.getTrustAnchorCAR(false);

// Determine current terminal key and build certificate chain to trust anchor
var terminalchr = certstore.getCurrentCHR(terminalpath);
if (terminalchr == null) {
	throw new Error("Could not determine current terminal key for " + terminalpath + ". Valid certificate chain and terminal key installed ?");
}

// Determine a certificate chain from the trust anchor to the terminal key
var cvcchain = certstore.getCertificateChain(terminalpath, terminalchr, car);

if (cvcchain == null) {
	throw new Error("No matching certificate chain for CAR " + car + ". Valid certificate chain and terminal key installed ?");
}

eac.verifyCertificateChain(cvcchain);

// Get key for terminal certificate
var termkey = certstore.getPrivateKey(terminalpath, terminalchr);

// Create the authentication data object. Here empty
var ad = null;

// Prepare for the later chip authentication step
eac.prepareChipAuthentication(0x41);

// Perform terminal authentication
eac.performTerminalAuthentication(termkey, ad);

print("Reading EF.CardSecurity...");
eac.readCardSecurity();

print("Performing CA...");
eac.performChipAuthentication();

print("Reading files from eID application using secure messaging...");
var mf = eac.getMF();

// Select DF
var dfeid = new CardFile(mf, "#E80704007F00070302");

// Read DG using short file identifier
var dg1 = new CardFile(dfeid, ":01");
print("DG1 (Document Type):");
print(dg1.readBinary());

var dg2 = new CardFile(dfeid, ":02");
print("DG2 (Issuing State):");
print(dg2.readBinary());

var dg3 = new CardFile(dfeid, ":03");
print("DG3 (Date of Expiration):");
print(dg3.readBinary());

var dg4 = new CardFile(dfeid, ":04");
print("DG4 (Given Name):");
print(dg4.readBinary());

var dg5 = new CardFile(dfeid, ":05");
print("DG5 (Surname):");
print(dg5.readBinary());

var dg6 = new CardFile(dfeid, ":06");
print("DG6 (Artist Name):");
print(dg6.readBinary());

var dg7 = new CardFile(dfeid, ":07");
print("DG7 (Academic Grade):");
print(dg7.readBinary());

var dg8 = new CardFile(dfeid, ":08");
print("DG8 (Date of Birth):");
print(dg8.readBinary());

var dg9 = new CardFile(dfeid, ":09");
print("DG9 (Place of Birth):");
print(dg9.readBinary());

var dg17 = new CardFile(dfeid, ":11");
print("DG17 (Place of Residence):");
print(dg17.readBinary());
