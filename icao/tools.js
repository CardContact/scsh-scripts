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
 *  Tools for accessing a ICAO conform Machine Readable Travel Document
 */



/*
 * Calculate a single Basic Access Control (BAC) key from the second
 * line of the Machine Readable Zone (MRZ).
 *
 * The function extracts the Document Number, Date of Birth and Date of Expiration
 * from the second line of the machine readable zone
 *
 * E.g. MRZ of Silver Data Set
 *   P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<
 *   L898902C<3UTO6908061F9406236ZE184226B<<<<<14
 *   '-DocNo--'   '-DoB-' '-DoE-'
 *
 * This extract is then hashed, concatenated with a key number and
 * hashed again.
  
 * crypto	Crypto object used for hashing
 * mrz2		String containing second line of MRZ
 * keyno	Number of key to calculate (1 for Kenc and 2 for Kmac)
 *
 * Returns	Key object
 */

function calculateBACKey(crypto, mrz2, keyno) {

	// Convert to byte string
	var strbin = new ByteString(mrz2, ASCII);

	// Extract Document Number, Date of Birth and Date of Expiration
	var hash_input = strbin.bytes(0, 10);
	hash_input = hash_input.concat(strbin.bytes(13, 7));
	hash_input = hash_input.concat(strbin.bytes(21, 7));
	print("Hash Input   : " + hash_input.toString(ASCII));

	// Hash input	
	var mrz_hash = crypto.digest(Crypto.SHA_1, hash_input);
	print("MRZ Hash     : " + mrz_hash);

	// Extract first 16 byte and append 00000001 or 00000002
	var bb = new ByteBuffer(mrz_hash.bytes(0, 16));
	bb.append(new ByteString("000000", HEX));
	bb.append(keyno);

	// Hash again to calculate key value	
	var keyval = crypto.digest(Crypto.SHA_1, bb.toByteString());
	keyval = keyval.bytes(0, 16);
	print("Value of Key : " + keyval);
	var key = new Key();
	key.setComponent(Key.DES, keyval);

	return key;
}



/*
 * Calculate a single Basic Access Control (BAC) key from a 3-line
 * Machine Readable Zone (MRZ).
 *
 * The function extracts the Document Number, Date of Birth and Date of Expiration
 * from the second line of the machine readable zone
 *
 * E.g. MRZ of Silver Data Set
 *   I<UTOL898902C<3<<<<<<<<<<<<<<<
 *        '-DocNo--'
 *   6908061F9406236UTO<<<<<<<<<<<1
 *   '-DoB-' '-DoE-'
 *   ERIKSON<<ANNA<MARIA<<<<<<<<<<<
 *
 * This extract is then hashed, concatenated with a key number and
 * hashed again.
  
 * crypto	Crypto object used for hashing
 * mrz		String containing second line of MRZ
 * keyno	Number of key to calculate (1 for Kenc and 2 for Kmac)
 *
 * Returns	Key object
 */
function calculateBACKeyFrom3LineMRZ(crypto, mrz, keyno) {

	// Convert to byte string
	var strbin = new ByteString(mrz, ASCII);

	// Extract Document Number, Date of Birth and Date of Expiration
	var hash_input = strbin.bytes(5, 10);
	hash_input = hash_input.concat(strbin.bytes(30, 7));
	hash_input = hash_input.concat(strbin.bytes(38, 7));
	print("Hash Input   : " + hash_input.toString(ASCII));

	// Hash input	
	var mrz_hash = crypto.digest(Crypto.SHA_1, hash_input);
	print("MRZ Hash     : " + mrz_hash);

	// Extract first 16 byte and append 00000001 or 00000002
	var bb = new ByteBuffer(mrz_hash.bytes(0, 16));
	bb.append(new ByteString("000000", HEX));
	bb.append(keyno);

	// Hash again to calculate key value	
	var keyval = crypto.digest(Crypto.SHA_1, bb.toByteString());
	keyval = keyval.bytes(0, 16);
	print("Value of Key : " + keyval);
	var key = new Key();
	key.setComponent(Key.DES, keyval);

	return key;
}



// The SecureChannel object is required as a credential for the CardFile objects
// SecureChannel objects must at least implement a wrap() method. The unwrap()
// method is optional, but called when defined

function SecureChannel(crypto, kenc, kmac, ssc) {
	this.crypto = crypto;
	this.kenc = kenc;
	this.kmac = kmac;
	this.ssc = ssc;
	this.trace = false;
}



SecureChannel.prototype.enableTrace = function () {
	this.trace = true;
}



//
// Increment send sequence counter
//
SecureChannel.prototype.incssc = function () {
	var c = this.ssc.bytes(4, 4).toUnsigned() + 1;
	bb = new ByteBuffer(this.ssc.bytes(0, 4));
	bb.append((c >> 24) & 0xFF);
	bb.append((c >> 16) & 0xFF);
	bb.append((c >>  8) & 0xFF);
	bb.append((c      ) & 0xFF);
	this.ssc = bb.toByteString();
}



//
// Wrap command-APDU with secure messaging
//
SecureChannel.prototype.wrap = function(apduToWrap) {
	if (this.trace) {
		print("Command-APDU to wrap :");
		print(apduToWrap);
	}

	var b = new ByteBuffer();
	var macb = new ByteBuffer();

	// Transform CLA byte and add header	
	var cla = apduToWrap.byteAt(0);
	cla |= 0x0C;
	b.append(cla);
	b.append(apduToWrap.bytes(1, 3));

	this.incssc();
	macb.append(this.ssc);
	macb.append(b.toByteString().pad(Crypto.ISO9797_METHOD_2));

	var do87 = null;

	var le = apduToWrap.bytes(apduToWrap.length - 1, 1);
	
	if (apduToWrap.length > 5) {
		var lc = apduToWrap.byteAt(4);
		var plain = apduToWrap.bytes(5, lc);
		plain = plain.pad(Crypto.ISO9797_METHOD_2);
		if (this.trace) {
			print("Input to cipher:");
			print(plain);
		}
		
		var cipher = this.crypto.encrypt(this.kenc, Crypto.DES_CBC, plain, new ByteString("0000000000000000", HEX));
		do87 = new ByteString("01", HEX);
		do87 = do87.concat(cipher);
		do87 = new TLV(0x87, do87, TLV.EMV);
		do87 = do87.getTLV();
		
		macb.append(do87);
		
		if (apduToWrap.length == 5 + lc) {
			le = new ByteString("", HEX);
		}
	} else if (apduToWrap.length == 4) {
		le = new ByteString("", HEX);
	}

	var do97;
	if (le.length > 0) {	
		do97 = new ByteString("9701", HEX);
		do97 = do97.concat(le);
		macb.append(do97);
	} else {
		do97 = new ByteString("", HEX);
	}
	
	if (this.trace) {
		print("Input to MAC calculation :");
	}
	
	var macinput = macb.toByteString().pad(Crypto.ISO9797_METHOD_2);
	if (this.trace) {
		print(macinput);
	}
	
	var mac = this.crypto.sign(this.kmac, Crypto.DES_MAC_EMV, macinput);
	if (this.trace) {
		print("Calculated MAC :");
		print(mac);
	}
	
	var macdo = new ByteString("8E08", HEX);
	macdo = macdo.concat(mac);
	
	if (do87 != null) {
		b.append(do87.length + do97.length + macdo.length);
		b.append(do87);
	} else {
		b.append(do97.length + macdo.length);
	}

	b.append(do97);
	b.append(macdo);
	
	if (le.length > 0) {
		b.append(0);
	}
	
	if (this.trace) {
		print("Wrapped Command-APDU :");
		print(b.toByteString());
	}
	
	return(b.toByteString());
}



//
// Unwrap response-APDU with secure messaging
//
SecureChannel.prototype.unwrap = function(apduToUnwrap) {
	if (this.trace) {
		print("Response-APDU to unwrap :");
		print(apduToUnwrap);
	}
	
	if (apduToUnwrap.length == 2) {
		return(apduToUnwrap);
	}
	
	var b = new ByteBuffer();
	var macb = new ByteBuffer();

	this.incssc();

	macb.append(this.ssc);

	var tl = new TLVList(apduToUnwrap.left(apduToUnwrap.length - 2), TLV.EMV);
	
	var mac = null;
	for (i = 0; i < tl.length; i++) {
		var t = tl.index(i);
		
		if (t.getTag() == 0x8E) {
			mac = t.getValue();
		} else {
			macb.append(t.getTLV());
		}
	}
	
	if (mac == null) {
		throw new GPError("SecureChannelCredential", GPError.OBJECT_NOT_FOUND, 0, "MAC data object missing");
	}

	if (this.trace) {
		print(macb.toByteString());
	}
	
	if (!this.crypto.verify(this.kmac, Crypto.DES_MAC_EMV, macb.toByteString().pad(Crypto.ISO9797_METHOD_2), mac)) {
		throw new GPError("SecureChannelCredential", GPError.CRYPTO_FAILED, 0, "MAC verification failed");
	}

	var t = tl.find(0x87);
	if (t != null) {
		var cryptogram = t.getValue();
		var padding = cryptogram.byteAt(0);
		cryptogram = cryptogram.right(cryptogram.length - 1);

		if (padding != 0x01) {
			throw new GPError("SecureChannelCredential", GPError.INVALID_MECH, padding, "Unsupported padding mode " + padding + " in cryptogram");
		}
		
		var plain = this.crypto.decrypt(this.kenc, Crypto.DES_CBC, cryptogram, new ByteString("0000000000000000", HEX));
		for (i = plain.length - 1; (i > 0) && (plain.byteAt(i) != 0x80); i--);
		
		b.append(plain.left(i));
	}

	var t = tl.find(0x81);
	
	if (t != null) {
		b.append(t.getValue());
	}
	
	var t = tl.find(0x99);
	if (t == null) {
		b.append(apduToUnwrap.right(2));
	} else {
		b.append(t.getValue());
	}
	
	if (this.trace) {
		print("Unwrapped Response-APDU :");
		print(b.toByteString());
	}
	return(b.toByteString());
}


/*
 * Open secure channel using basic access control keys
 *
 * card		Card object for access to passport
 * crypto	Crypto object to be used for cryptographic operations
 * kenc		Kenc key
 * kmac		Kmac key
 *
 * Returns	Open secure channel object
 */
 
function openSecureChannel(card, crypto, kenc, kmac) {

	// Perform mutual authentication procedure
	print("Performing mutual authentication");
	var rndicc = card.sendApdu(0x00, 0x84, 0x00, 0x00, 0x08, [0x9000]);

	var rndifd = crypto.generateRandom(8);
	var kifd = crypto.generateRandom(16);

	var plain = rndifd.concat(rndicc).concat(kifd);
	print("Plain Block  : " + plain);

	var cryptogram = crypto.encrypt(kenc, Crypto.DES_CBC, plain, new ByteString("0000000000000000", HEX));
	print("Cryptogram   : " + cryptogram);

	var mac = crypto.sign(kmac, Crypto.DES_MAC_EMV, cryptogram.pad(Crypto.ISO9797_METHOD_2));
	print("MAC          : " + mac);

	var autresp = card.sendApdu(0x00, 0x82, 0x00, 0x00, cryptogram.concat(mac), 0);
	
	if (card.SW != 0x9000) {
		print("Mutual authenticate failed with " + card.SW.toString(16) + " \"" + card.SWMSG + "\". MRZ correct ?");
		throw new GPError("MutualAuthentication", GPError.CRYPTO_FAILED, 0, "Card did not accept MAC");
	}
	
	print("Response     : " + autresp);

	cryptogram = autresp.bytes(0, 32);
	mac = autresp.bytes(32, 8);

	if (!crypto.verify(kmac, Crypto.DES_MAC_EMV, cryptogram.pad(Crypto.ISO9797_METHOD_2), mac)) {
		throw new GPError("MutualAuthentication", GPError.CRYPTO_FAILED, 0, "Card MAC did not verify correctly");
	}

	plain = crypto.decrypt(kenc, Crypto.DES_CBC, cryptogram, new ByteString("0000000000000000", HEX));
	print("Plain Block  : " + plain);

	if (!plain.bytes(0, 8).equals(rndicc)) {
		throw new GPError("MutualAuthentication", GPError.CRYPTO_FAILED, 0, "Card response does not contain matching RND.ICC");
	}

	if (!plain.bytes(8, 8).equals(rndifd)) {
		throw new GPError("MutualAuthentication", GPError.CRYPTO_FAILED, 0, "Card response does not contain matching RND.IFD");
	}

	var kicc = plain.bytes(16, 16);
	keyinp = kicc.xor(kifd);

	var hashin = keyinp.concat(new ByteString("00000001", HEX));
	var kencval = crypto.digest(Crypto.SHA_1, hashin);
	kencval = kencval.bytes(0, 16);
	print("Kenc         : " + kencval);
	var kenc = new Key();
	kenc.setComponent(Key.DES, kencval);

	var hashin = keyinp.concat(new ByteString("00000002", HEX));
	var kmacval = crypto.digest(Crypto.SHA_1, hashin);
	kmacval = kmacval.bytes(0, 16);
	print("Kmac         : " + kmacval);
	var kmac = new Key();
	kmac.setComponent(Key.DES, kmacval);

	var ssc = rndicc.bytes(4, 4).concat(rndifd.bytes(4, 4));
	print("SSC          : " + ssc);

// Disable to use script-secure messaging secure messaging
	var sc = new IsoSecureChannel(crypto);
	sc.setEncKey(kenc);
	sc.setMacKey(kmac);
	sc.setSendSequenceCounter(ssc);
	return sc;
//

// Enable to use script-secure messaging secure messaging
//	return new SecureChannel(crypto, kenc, kmac, ssc);
//
}



/*
 * Write a byte string object to file
 *
 * The filename is mapped to the location of the script
 *
 * name		Name of file
 * content	ByteString content for file
 *
 */
 
function writeFileOnDisk(name, content) {

	// Map filename
	var filename = GPSystem.mapFilename(name, GPSystem.USR);
	print("Writing " + filename);

	var file = new java.io.FileOutputStream(filename);
	file.write(content);
	file.close();
}



/*
 * Read a byte string object from file
 *
 * The filename is mapped to the location of the script
 *
 * name		Name of file
 *
 */
 
function readFileFromDisk(name) {

	// Map filename
	var filename = GPSystem.mapFilename(name, GPSystem.USR);
	print("Reading " + filename);

	var file = new java.io.FileInputStream(filename);
	
	var content = new ByteBuffer();
	var buffer = new ByteString("                                                                                                                                                                                                                                                                ", ASCII);
	var len;
	
	while ((len = file.read(buffer)) >= 0) {
		content.append(buffer.bytes(0, len));
	}
	
	file.close();
	return(content.toByteString());
}


/*
 * Extract the length of the file from the TLV encoding at the beginning of the
 * file
 *
 * header	First bytes read from file
 *
 * Return	Total length of TLV object
 */
 
function lengthFromHeader(header) {
	var value;
	
	value = header.byteAt(1);
	
	if (value > 0x82) {
		throw new GPError("lengthfromheader()", GPError.INVALID_DATA, value, "");
	}
	
	switch(value) {
		case 0x81:
			value = header.byteAt(2) + 1;
			break;
		case 0x82:
			value = (header.byteAt(2) << 8) + header.byteAt(3) + 2;
			break;
	}
	return value + 2;
}
 