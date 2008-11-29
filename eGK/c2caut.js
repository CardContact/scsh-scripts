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
 *  Card-to-Card authentification between German HPC und eGK
 *
 */

load("cvc.js");

//
// Perform a card to card mutual authentication between a German eGK and HPC
//
// The procedure involves 6 steps
//   1. Read ICCSN and card verifiable certificates (CVC) from eGK
//   2. Read ICCSN and card verifiable certificates (CVC) from HPC
//   3. Verify CVC chain from eGK in HPC
//   4. Verify CVC chain from HPC in eGK
//   5. Authenticate eGK against HPC
//   6. Authenticate HPC against eGK
//
// Prerequisite: The PIN must be verified on the HPC
//
function Card2CardAuthentication(card_HIC, card_HPC, rootpuk) {
	
	// Step 1 - Read ICCSN.EGK, CVC.eGK.AUT and CVC.CA_eGK.CS from eGK

	// Read ICCSN.EGK, construct ASN1 object and extract ICCSN

	var ef_gdo = new CardFile(card_HIC, ":02");
	var gdo = ef_gdo.readBinary();
	var gdo_tlv = new ASN1(gdo);
//	print(gdo_tlv);
	var iccsn = gdo_tlv.value;
	var iccsn_egk = iccsn;
	print("ICCSN of eGK:");
	print(iccsn_egk);

	// Read CVC.CA_eGK.CS and construct ASN1 object

	var ef_cvc_ca_egk = new CardFile(card_HIC, ":04");
	var cvc_ca_egk_bin = ef_cvc_ca_egk.readBinary();
	
	var cvc_ca_egk_tlv = new ASN1(cvc_ca_egk_bin);
	print("CVC.CA_eGK.CS:");
//	print(cvc_ca_egk_tlv);

	var cvc_ca_egk = new CVC(cvc_ca_egk_bin);
	cvc_ca_egk.verifyWithOneOf(rootpuk);
	cvc_ca_egk.dump();

	// Read CVC.eGK.AUT and construct ASN1 object

	var ef_cvc_egk = new CardFile(card_HIC, ":03");
	var cvc_egk_bin = ef_cvc_egk.readBinary();
	var cvc_egk_tlv = new ASN1(cvc_egk_bin);
	print("CVC.eGK.AUT:");
//	print(cvc_egk_tlv);

	var cvc_egk = new CVC(cvc_egk_bin);
	cvc_egk.verifyWith(cvc_ca_egk.getPublicKey());
	cvc_egk.dump();



	// Step 2 - Read ICCSN.HPC, CVC.HPC.AUT and CVC.CA_HPC.CS from HPC

	// Read ICCSN.HPC, construct ASN1 object and extract ICCSN

	var ef_gdo = new CardFile(card_HPC, ":02");
	var gdo = ef_gdo.readBinary();
	var gdo_tlv = new ASN1(gdo);
//	print(gdo_tlv);
	var iccsn = gdo_tlv.value;
	var iccsn_hpc = iccsn;
	print("ICCSN of HPC");
	print(iccsn_hpc);

	// Read CVC.CA_HPC.CS and construct ASN1 object

	var ef_cvc_ca_hpc = new CardFile(card_HPC, ":04");
	var cvc_ca_hpc_bin = ef_cvc_ca_hpc.readBinary();
	var cvc_ca_hpc_tlv = new ASN1(cvc_ca_hpc_bin);
	print("CVC.CA_HPC.AUT:");
//	print(cvc_ca_hpc_tlv);

	var cvc_ca_hpc = new CVC(cvc_ca_hpc_bin);
	cvc_ca_hpc.verifyWithOneOf(rootpuk);
	cvc_ca_hpc.dump();

	// Read CVC.HPC.AUT and construct ASN1 object

	var ef_cvc_hpc = new CardFile(card_HPC, ":03");
	var cvc_hpc_bin = ef_cvc_hpc.readBinary();
	var cvc_hpc_tlv = new ASN1(cvc_hpc_bin);
	print("CVC.HPC.AUT:");
//	print(cvc_hpc_tlv);

	var cvc_hpc = new CVC(cvc_hpc_bin);
	cvc_hpc.verifyWith(cvc_ca_hpc.getPublicKey());
	cvc_hpc.dump();



	// Step 3 - Verify CVC chain from eGK in HPC

	// Make PuK.eGK.AUT available in HPC
	// Send MANAGE_SE to select root public key

	// Create data body with tag '83' and the Certificate Authority Reference (CAR) from
	// CVC.CA_eGK.CS
	var do_tlv = new ASN1(0x83, cvc_ca_egk.getCertificationAuthorityReference());

	print("Selecting key for certificate verification: " + do_tlv.getBytes());
	card_HPC.sendApdu(0x00, 0x22, 0x81, 0xB6, do_tlv.getBytes(), [0x9000]);

	// Send PSO:VERIFY_CERTIFICATE to verify cvc_ca_egk

	// Create data body with concatenation of signature and public key remainder
	var data = new ByteBuffer();
	data.append(cvc_ca_egk_tlv.get(0).getBytes());
	data.append(cvc_ca_egk_tlv.get(1).getBytes());

	print("Sending PSO:VERIFY_CERTIFICATE(CVC.CA_eGK.CS) to HPC");
//	print(data.toByteString());
	card_HPC.sendApdu(0x00, 0x2A, 0x00, 0xAE, data.toByteString(), [0x9000]);

	print("CVC.CA_eGK.CS verified.");

	// Send MANAGE_SE to select public key of certification authority from CVC.CA_eGK.CS

	// Create data body with tag '83' and the Certificate Authority Reference (CAR) from
	// CVC.eGK.AUT
	var do_tlv = new ASN1(0x83, cvc_egk.getCertificationAuthorityReference());

	print("Selecting key for certificate verification: " + do_tlv.getBytes());
	card_HPC.sendApdu(0x00, 0x22, 0x81, 0xB6, do_tlv.getBytes(), [0x9000]);

	// Send PSO:VERIFY_CERTIFICATE to verify cvc_egk

	// Create data body with concatenation of signature and public key remainder
	var data = new ByteBuffer();
	data.append(cvc_egk_tlv.get(0).getBytes());
	data.append(cvc_egk_tlv.get(1).getBytes());

	print("Sending PSO:VERIFY_CERTIFICATE(CVC.eGK.AUT) to HPC");
//	print(data.toByteString());
	card_HPC.sendApdu(0x00, 0x2A, 0x00, 0xAE, data.toByteString(), [0x9000]);

	print("CVC.eGK.AUT verified.");



	// Step 4 - Verify CVC chain from HPC in eGK

	// Make PuK.HPC.AUT available in HIC
	// Send MANAGE_SE to select root public key

	// Create data body with tag '83' and the Certificate Authority Reference (CAR) from
	// CVC.CA_HPC.CS
	var do_tlv = new ASN1(0x83, cvc_ca_hpc.getCertificationAuthorityReference());

	print("Selecting key for certificate verification: " + do_tlv.getBytes());
	card_HIC.sendApdu(0x00, 0x22, 0x81, 0xB6, do_tlv.getBytes(), [0x9000]);

	// Send PSO:VERIFY_CERTIFICATE to verify cvc_ca_hpc

	// Create data body with concatenation of signature and public key remainder
	var data = new ByteBuffer();
	data.append(cvc_ca_hpc_tlv.get(0).getBytes());
	data.append(cvc_ca_hpc_tlv.get(1).getBytes());

	print("Sending PSO:VERIFY_CERTIFICATE(CVC.CA_HPC.CS) to eGK");
//	print(data.toByteString());
	card_HIC.sendApdu(0x00, 0x2A, 0x00, 0xAE, data.toByteString(), [0x9000]);

	print("CVC.CA_HPC.CS verified.");

	// Send MANAGE_SE to select public key of certification authority from CVC.CA_HPC.CS

	// Create data body with tag '83' and the Certificate Authority Reference (CAR) from
	// CVC.HPC.AUT
//	var car = cvc_hpc_tlv.get(2).value;
//	var car = new ByteString("44 45 44 54 58 11 01 08", HEX); // #### tmp !!!! DEDTX

//	var prefix = new ByteString("00000000", HEX);	// Siemens ?
//	car = prefix.concat(car);
	var do_tlv = new ASN1(0x83, cvc_hpc.getCertificationAuthorityReference());

	print("Selecting key for certificate verification: " + do_tlv.getBytes());
	card_HIC.sendApdu(0x00, 0x22, 0x81, 0xB6, do_tlv.getBytes(), [0x9000]);

	// Send PSO:VERIFY_CERTIFICATE to verify cvc_hpc

	// Create data body with concatenation of signature and public key remainder
	var data = new ByteBuffer();
	data.append(cvc_hpc_tlv.get(0).getBytes());
	data.append(cvc_hpc_tlv.get(1).getBytes());

	print("Sending PSO:VERIFY_CERTIFICATE(CVC.HPC.AUT) to eGK");
//	print(data.toByteString());
	card_HIC.sendApdu(0x00, 0x2A, 0x00, 0xAE, data.toByteString(), [0x9000]);

	print("CVC.HPC.AUT verified.");



	// Step 5 - Perform HIC to HPC authentification

	// Send MANAGE_SE to key references for PuK.eGK.AUT

	// Create data body with tag '83' and the key identifier

	var data = new ByteBuffer();
	data.append((new ASN1(0x83, cvc_egk.getCertificateHolderReference())).getBytes());
	data.append((new ASN1(0x80, new ByteString("00", HEX))).getBytes());

	print("Selecting key in HPC for eGK authentification: " + data.toByteString());
	card_HPC.sendApdu(0x00, 0x22, 0x81, 0xA4, data.toByteString(), [0x9000]);

	// Send MANAGE_SE to key references for PrK.eGK.AUT

	// Create data body with tag '83' and the Certificate Authority Reference (CAR) from
	// CVC.HPC.AUT

	var data = new ByteBuffer();
	data.append((new ASN1(0x84, new ByteString("10", HEX))).getBytes());
	data.append((new ASN1(0x80, new ByteString("00", HEX))).getBytes());
	
	print("Selecting key in eGK for HPC authentification: " + data.toByteString());
	card_HIC.sendApdu(0x00, 0x22, 0x41, 0xA4, data.toByteString(), [0x9000]);

	// GET_CHALLENGE from HPC

	var challenge_hpc = card_HPC.sendApdu(0x00, 0x84, 0x00, 0x00, 0x08, [0x9000]);
	print("Challenge from HPC = " + challenge_hpc);

	// Do INTERNAL_AUTHENTICATE with HIC

	var cryptograminput = challenge_hpc.concat(iccsn_hpc.bytes(2, 8));
	var cryptogram_hic = card_HIC.sendApdu(0x00, 0x88, 0x00, 0x00, cryptograminput, 0x00, [0x9000]);
	print("Cryptogram from HIC = " + cryptogram_hic);

	// Do EXTERNAL_AUTHENTICATE with HPC

	card_HPC.sendApdu(0x00, 0x82, 0x00, 0x00, cryptogram_hic, [0x9000]);



	// Step 6 - Perform HPC to HIC authentification

	// Send MANAGE_SE to key references for PuK.HPC.AUT

	// Create data body with tag '83' and the key identifier

	var data = new ByteBuffer();
	data.append((new ASN1(0x83, cvc_hpc.getCertificateHolderReference())).getBytes());
	data.append((new ASN1(0x80, new ByteString("00", HEX))).getBytes());

	print("Selecting key in eGK for HPC authentification: " + data.toByteString());
	card_HIC.sendApdu(0x00, 0x22, 0x81, 0xA4, data.toByteString(), [0x9000]);

	// Send MANAGE_SE to key references for PrK.HPC.AUT

	// Create data body with tag '83' and the Certificate Authority Reference (CAR) from
	// CVC.HPC.AUT

	var data = new ByteBuffer();
	data.append((new ASN1(0x84, new ByteString("10", HEX))).getBytes());
	data.append((new ASN1(0x80, new ByteString("00", HEX))).getBytes());
	
	print("Selecting key in HPC for eGK authentification: " + data.toByteString());
	card_HPC.sendApdu(0x00, 0x22, 0x41, 0xA4, data.toByteString(), [0x9000]);

	// GET_CHALLENGE from HIC

	var challenge_hic = card_HIC.sendApdu(0x00, 0x84, 0x00, 0x00, 0x08, [0x9000]);
	print("Challenge from HIC = " + challenge_hic);

	// Do INTERNAL_AUTHENTICATE with HPC

	var cryptograminput = challenge_hic.concat(iccsn_egk.bytes(2, 8));
	var cryptogram_hpc = card_HPC.sendApdu(0x00, 0x88, 0x00, 0x00, cryptograminput, 0x00, [0x9000]);
	print("Cryptogram from HPC = " + cryptogram_hpc);

	// Do EXTERNAL_AUTHENTICATE with HIC

	card_HIC.sendApdu(0x00, 0x82, 0x00, 0x00, cryptogram_hpc, [0x9000]);
}


/*
// Create the card objects

// Uncomment the following, if you have two PC/SC reader rather than a terminal
// with multiple slots.
// var card_HIC = new Card("ORGA CardMouse USB 0"); // Reader with eGK
// var card_HPC = new Card("SCM Microsystems Inc. SCR33x USB Smart Card Reader 0"); // Reader with HPC

var card_HIC = new Card(_scsh3.reader + "#1"); // Reader with eGK
var card_HPC = new Card(_scsh3.reader + "#2"); // Reader with HPC

card_HPC.reset(Card.RESET_COLD);
card_HIC.reset(Card.RESET_COLD);

// Select application on HPC
var mf_hpc = new CardFile(card_HPC, ":3F00");

print("Please enter PIN for HPC");
// Verify PIN for HPC
ok = mf_hpc.performCHV(true, 1);

if (!ok) {
	print("PIN Verification failed");
	exit;
}

Card2CardAuthentication(card_HIC, card_HPC);
*/