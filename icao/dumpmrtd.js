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
 *  Dump the content of a passport with Basic Access Control to file
 *
 *  Before running this script, please make sure that the variable mrz2 is set
 *  to the second line of the machine readable zone on your passport.
 */

// MRZ of silver data set
//
// P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<
// L898902C<3UTO6908061F9406236ZE184226B<<<<<14
// '-DocNo--'   '-DoB-' '-DoE-'
var mrz2 = "L898902C<3UTO6908061F9406236ZE184226B<<<<<14";

// MRZ of Tsukuba data set
//
// WG30004036UTO6007078M0511014<<<<<<<<<<<<<<06
// '-DocNo--'   '-DoB-' '-DoE-'

// var mrz2 = "WG30004036UTO6007078M0511014<<<<<<<<<<<<<<06";


// Import some tools
load("tools.js");


/*
 * Read file from passport and save to disk
 *
 */
function handleFile(secureChannel, lds, name, fid) {
	print("Reading " + name + " (" + fid + ")...");
	
	// Select file
	var ef = new CardFile(lds, ":" + fid);

	if (secureChannel) {	
		// Set secure channel as credential for read access
		ef.setCredential(CardFile.READ, Card.ALL, secureChannel);
	}
	
	// Read first 4 bytes of file
	var res = ef.readBinary(0, 4);
	
	// Determine file length from TLV header
	var len = lengthFromHeader(res);
	
	// Read complete file
	var res = ef.readBinary(0, len);
	print("Content");
	print(res);
	
	writeFileOnDisk(name + ".bin", res);
	
	return res;
}



/*
 * Save picture from DG2
 *
 */
function savePicture(dg2) {
	// Save picture to .jpeg file
	var tlv = new ASN1(dg2);
	var bin = tlv.get(0).get(1).get(1).value;
	var offset = bin.find(new ByteString("FFD8", HEX));
	
	if (offset >= 0) {
		writeFileOnDisk("face.jpg", bin.bytes(offset));
	}
}


// Create card and crypto object
var card = new Card(_scsh3.reader);
card.reset(Card.RESET_COLD);

var crypto = new Crypto();

// Select LDS application
var lds = new CardFile(card, "#A0000002471001");

var secureChannel = null;

// Try reading EF_COM to figure out if BAC is needed
card.sendApdu(0x00, 0xB0, 0x9E, 0x00, 0x01);

if (card.SW != 0x9000) {

	// Calculate kenc and kmac for mutual authentication from the MRZ data
	print("Trying BAC with MRZ2=" + mrz2);
	
	var kenc = calculateBACKey(crypto, mrz2, 1);
	var kmac = calculateBACKey(crypto, mrz2, 2);

	// Dummy to load crypto libraries (Saves some time later)
	crypto.encrypt(kenc, Crypto.DES_CBC, new ByteString("0000000000000000", HEX), new ByteString("0000000000000000", HEX));

	secureChannel = openSecureChannel(card, crypto, kenc, kmac);

	/* Only works with script based secure messaging. See tools.js for details
	secureChannel.enableTrace();
	*/

	// Enable SELECT commands to be send in secure messaging
	// lds.setCredential(CardFile.SELECT, CardFile.ALL, secureChannel);

	/*
	card.setCredential(secureChannel);
	var resp = card.sendSecMsgApdu(Card.ALL, 0x00, 0xA4, 0x02, 0x0C, new ByteString("011E", HEX));
	print(resp);
	*/
}

handleFile(secureChannel, lds, "EF_COM", "1E");
handleFile(secureChannel, lds, "EF_DG1", "01");
var dg2 = handleFile(secureChannel, lds, "EF_DG2", "02");
savePicture(dg2);
handleFile(secureChannel, lds, "EF_SOD", "1D");



