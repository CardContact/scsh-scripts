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
 *  Generate a 2048 bit RSA key pair
 */

load("tools.js");

var card = new Card(_scsh3.reader);
card.reset(Card.RESET_COLD);


// Select Applet
card.sendApdu(0x00, 0xA4, 0x04, 0x00, mcaid, [0x9000]);

// MSCGenerateKeyPair

var param = new ByteString("01"		// Algorithm ( "01" - RSA, "02" - RSA_CRT, "03" - DSA, "04" - EC_F2M, "05" - EC_FP
			 + "0800"	// Key size in bits
			 + "FFFF"	// Private Key Read Access ("FFFF" - NEV)
			 + "FFFF"	// Private Key Write Access
			 + "0001"	// Private Key Use Access
			 + "0000"	// Public Key Read Access ("0000" - ALW)
			 + "FFFF"	// Public Key Write Access
			 + "FFFF"	// Public Key Use Access
			 + "00"		// Options
			 , HEX);
			 
print("Generating key...");		 
card.sendApdu(0xB0, 0x30, 0x02, 0x03, param);

// MSCExportKey
card.sendApdu(0xB0, 0x34, 0x03, 0x00, new ByteString("00", HEX), [0x9000]);

var kb = readKeyBlob(card);

print(kb.header);
print("Modulus : " + kb[0]);
print("Exponent: " + kb[1]);
