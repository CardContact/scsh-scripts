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
 * @fileoverview The class DataAuthentication supports Static Data Authentication and Dynamic Data Authentication.
 */

/**
 * DataAuthentication class constructor
 * @class This class implements data authentication
 * @constructor
 * @requires EMV
 * @param {EMV} emv an instance of the EMV class
 */
function DataAuthentication(emv) {	
	this.emv = emv;
	this.crypto= emv.crypto;
	this.schemePublicKeyTable = [];
}

/**
 * Get the Registered Application Provider Identifier from EMV data model
 *
 * @type ByteString
 * @return the 5 byte RID
 */
DataAuthentication.prototype.getRID = function() {
	var aid = this.emv.cardDE[EMV.AID];
	var rid = aid.left(5);
	return(rid);
}

/**
 * Get the Public Key Index
 *
 * @type Number
 * @return the Public Key Index
 */
DataAuthentication.prototype.getPubKeyIndex = function() {
	var index = this.emv.cardDE[0x8F];
	var index = index.toUnsigned();
	return(index);
}

/**
 * Add a new public key to the array
 *
 * @param {ByteString} rid the Registered Application Provider Identifier
 * @param {Number} index the public key index
 * @param {Key} key the public key
 */
DataAuthentication.prototype.addSchemePublicKey = function(rid, index, key) {
	if(typeof(this.schemePublicKeyTable[rid.toString(HEX)]) == "undefined") {	
		this.schemePublicKeyTable[rid.toString(HEX)] = [];
	}
	this.schemePublicKeyTable[rid.toString(HEX)][index] = key;
}

/**
 * Get the public key
 *
 *@type Key
 *@return the public key
*/
DataAuthentication.prototype.getSchemePublicKey = function() {
	var rid = this.getRID();
	var index = this.getPubKeyIndex();
	
	var key = this.schemePublicKeyTable[rid.toString(HEX)][index];
	return(key);
}

/**
 * Decryption of the Issuer Public Key Certificate
 *
 * @return the decrypted Issuer Public Key Certificate
*/
DataAuthentication.prototype.decryptIssuerPKCertificate = function() {
	var certificate = this.emv.cardDE[0x90];
	var key = this.getSchemePublicKey();
	var decryptedCertificate = crypto.decrypt(key, Crypto.RSA, certificate);
	return(decryptedCertificate);
}

/**
 * Retrieval of Issuer Public Key
 *
 * @type Key
 * @return the Issuer Public Key
*/
DataAuthentication.prototype.retrieveIssuerPublicKey = function() {
	var key = this.getSchemePublicKey();
	var modulus = key.getComponent(Key.MODULUS);
	var cert = this.decryptIssuerPKCertificate();		

	// Step 1: Issuer Public Key Certificate and Certification Authority Public Key Modulus have the same length
	assert(cert.length == modulus.length);

	// Step 2: The Recovered Data Trailer is equal to 'BC'
	assert(cert.byteAt(modulus.length - 1) == 0xBC);
	
	// Step 3: The Recovered Data Header is equal to '6A'	
	assert(cert.byteAt(0) == 0x6A);
	
	// Step 4: The Certificate Format is equal to '02'	
	assert(cert.byteAt(1) == 0x02);
	
	// Step 5: Concatenation
	var list;
	list = cert.bytes(1, 14 + (modulus.length - 36));
	var remainder = this.emv.cardDE[0x92];
	var exponent = this.emv.cardDE[0x9F32];
	var remex = remainder.concat(exponent);
	
	list = list.concat(remex);
		
	// Step 6: Generate hash from concatenation
	var hashConcat = this.crypto.digest(Crypto.SHA_1, list);

	// Step 7: Compare the hash result with the recovered hash result. They have to be equal 
	var hashCert = cert.bytes(15 + (modulus.length - 36), 20); 
	assert(hashCert.equals(hashConcat));

	// Step 8: Verify that the Issuer Identifier matches the lefmost 3-8 PAN digits	
	var pan = this.emv.cardDE[0x5A];
	pan = pan.left(4);
	var panCert = cert.bytes(2, 4);

	var panCert = panCert.toString(HEX);
	var pan = pan.toString(HEX);
	for(var i = 0; i < 8; i++) {
		if(panCert.charAt(i) == 'F') {
			var panCert = panCert.substr(0, i);
			var pan = pan.substr(0, i);
		}
	}
	assert(pan == panCert);

	// Step 9: Verify that the last day of the month specified in the Certification Expiration Date is equal to or later than today's date.  

	// Step 10: Optional step

	// Step 11: Check the Issuer Public Key Algorithm Indicator
	var pkAlgorithmIndicator = cert.byteAt(12);

	// Step 12: Concatenate the Leftmost Digits of the Issuer Public Key and the Issuer Public Key Remainder (if present) to obtain the Issuer Public Key Modulus
	var leftmostDigits = cert.bytes(15, (modulus.length - 36));
	var issuerPublicKeyModulus = leftmostDigits.concat(remainder);
	return(issuerPublicKeyModulus);
}

/**
 * Verification of Signed Static Application Data
 *
 * @param {Key} key the Issuer Public Key
*/
DataAuthentication.prototype.verifySSAD = function(issuerPublicKeyModulus) {
	var issuerPublicKeyModulus =  issuerPublicKeyModulus;
	var key = new Key();
	key.setType(Key.PUBLIC);
	key.setComponent(Key.MODULUS, issuerPublicKeyModulus);
	key.setComponent(Key.EXPONENT, this.emv.cardDE[0x9F32]);
	var SSAD = this.emv.cardDE[0x93];
	
	// Step 1: Signed Static Application Data and Issuer Public Key Modulus have the same length
	assert(SSAD.length == issuerPublicKeyModulus.length);

	// Step 2: The Recovered Data Trailer is equal to 'BC'
	var decryptedSSAD = crypto.decrypt(key, Crypto.RSA, SSAD);
	assert(decryptedSSAD.byteAt(decryptedSSAD.length -1) == 0xBC);

	// Step 3: The Recovered Data Header is equal to '6A'
	assert(decryptedSSAD.byteAt(0) == 0x6A);

	// Step 4: The Signed Data Format is equal to '03'
	assert(decryptedSSAD.byteAt(1) == 0x03);

	// Step 5: Concatenation
	var list = decryptedSSAD.bytes(1, (decryptedSSAD.length - 22));
	var daInput = this.emv.getDAInput();
	var sdaTagList = this.emv.cardDE[0x9F4A];
	if(typeof(sdaTagList != "undefined")) {
		for(var i = 0; i < sdaTagList.length; i++) {
			var tag = sdaTagList.byteAt(i);
			var value = new ByteBuffer();
			value = value.append(this.emv.cardDE[tag]);
		}
	}
	
	list = list.concat(daInput);
	if(value != 0) {
		value = value.toByteString();
		list = list.concat(value);
	}

	// Step 6: Generate hash from concatenation
	var hashConcat = this.crypto.digest(Crypto.SHA_1, list);
	
	// Step 7: Compare recovered hash with generated hash. Store the Data Authentication Code from SSAD in tag '9F45'
	var hashSSAD  = decryptedSSAD.bytes(decryptedSSAD.length - 21, 20);
	assert(hashConcat.equals(hashSSAD));
	this.emv.cardDE[0x9F45] = decryptedSSAD.bytes(3, 2);
	
	print("<-----------------------------SDA was successful------------------------------>\n");
}

/**
 * Retrieval of ICC Public Key
 *
 * @param {Key} key the Issuer Public Key
 * @type Key
 * @return the ICC Public Key
*/
DataAuthentication.prototype.retrieveICCPublicKey = function(issuerPublicKeyModulus) {
	var issuerPublicKeyModulus =  issuerPublicKeyModulus;
	var key = new Key();
	key.setType(Key.PUBLIC);
	key.setComponent(Key.MODULUS, issuerPublicKeyModulus);
	key.setComponent(Key.EXPONENT, this.emv.cardDE[0x9F32]);
	var iccCert = this.emv.cardDE[0x9F46];
	
	// Step 1: ICC Public Key Certificate and Issuer Public Key Modulus have the same length
	assert(iccCert.length == issuerPublicKeyModulus.length);

	// Step 2: The Recovered Data Trailer is equal to 'BC'
	var decryptedICC = crypto.decrypt(key, Crypto.RSA, iccCert);
	assert(decryptedICC.byteAt(decryptedICC.length - 1) == 0xBC);
	
	// Step 3: The Recovered Data Header is equal to '6A'	
	assert(decryptedICC.byteAt(0) == 0x6A);
	
	// Step 4: The Certificate Format is equal to '04'	
	assert(decryptedICC.byteAt(1) == 0x04);
	
	// Step 5: Concatenation
	var list = decryptedICC.bytes(1, (decryptedICC.length - 22));
	var remainder = this.emv.cardDE[0x9F48];
	var exponent = this.emv.cardDE[0x9F47];
	var remex = remainder.concat(exponent);
	list = list.concat(remex);	
	var daInput = this.emv.getDAInput();
	list = list.concat(daInput);

	var sdaTagList = this.emv.cardDE[0x9F4A];
	if(typeof(sdaTagList != "undefined")) {
		var value = new ByteBuffer();
		for(var i = 0; i < sdaTagList.length; i++) {
			var tag = sdaTagList.byteAt(i);			
			value = value.append(this.emv.cardDE[tag]);
		}
		value = value.toByteString();
		list = list.concat(value);
	}
		
	// Step 6: Generate hash from concatenation
	var hashConcat = this.crypto.digest(Crypto.SHA_1, list);	
	
	// Step 7: Compare recovered hash with generated hash
	var hashICC  = decryptedICC.bytes(decryptedICC.length - 21, 20);
	assert(hashConcat.equals(hashICC));

	// Step 8: Verify that the Issuer Identifier matches the lefmost 3-8 PAN digits	
	var pan = this.emv.cardDE[0x5A];	
	var panCert = decryptedICC.bytes(2, 10);

	var panCert = panCert.toString(HEX);
	var pan = pan.toString(HEX);
	for(var i = 0; i < 20; i++) {
		if(panCert.charAt(i) == 'F') {
			var panCert = panCert.substr(0, i);
			var pan = pan.substr(0, i);
		}
	}
	assert(pan == panCert);

	// Step 9: Verify that the last day of the month specified in the Certification Expiration Date is equal to or later than today's date.  

	// Step 10: Check the ICC Public Key Algorithm Indicator
	var pkAlgorithmIndicator = decryptedICC.byteAt(18);


	// Step 11: Concatenate the Leftmost Digits of the ICC Public Key and the ICC Public Key Remainder (if present) to obtain the ICC Public Key Modulus
	
	var modulus = key.getComponent(Key.MODULUS);
	var leftmostDigits = decryptedICC.bytes(21, (modulus.length - 42));
	var iccPublicKeyModulus = leftmostDigits.concat(remainder);
	return(iccPublicKeyModulus)
}	

/**
 * Generation and verification of the dynamic signature.
 * A successfully retrieval of the ICC Public Key is required.
 *
 * @param {Key} key the ICC Public Key
*/
DataAuthentication.prototype.dynamicDataAuthentication = function(iccPublicKeyModulus) {
	var iccPublicKeyModulus = iccPublicKeyModulus;
	
	var Data = crypto.generateRandom(4);
	var internalAuthenticate = card.sendApdu(0x00, 0x88, 0x00, 0x00, Data, 0x00);
	var asn = new ASN1(internalAuthenticate);
	var tag = asn.find(0x9F4B);
	var SDAD = tag.value;
	
	var picKey = new Key();
	picKey.setType(Key.PUBLIC);
	picKey.setComponent(Key.MODULUS, iccPublicKeyModulus);
	picKey.setComponent(Key.EXPONENT, this.emv.cardDE[0x9F47]);
	var decryptedSDAD = crypto.decrypt(picKey, Crypto.RSA, SDAD);
	// Step 1: SDAD and ICC Public Key Modulus have the same length
	assert(SDAD.length == iccPublicKeyModulus.length);
	
	// Step 2: The Recovered Data Trailer is equal to 'BC'
	assert(decryptedSDAD.byteAt(decryptedSDAD.length - 1) == 0xBC);
	
	// Step 3: The Recovered Data Header is equal to '6A'
	assert(decryptedSDAD.byteAt(0) == 0x6A);
	
	// Step 4: The Signed Data Format is equal to '05'
	assert(decryptedSDAD.byteAt(1) == 0x05);
	
	// Step 5: Concatenation of Signed Data Format, Hash Algorithm Indicator, ICC Dynamic Data Length, ICC Dynamic Data, Pad Pattern, random number
	var LDD = decryptedSDAD.byteAt(3);
	var list = decryptedSDAD.bytes(1, 3 + LDD + decryptedSDAD.length - LDD - 25);
	list = list.concat(Data);
	
	// Step 6: Genereate hash from concatenation
	var hashConcat = this.crypto.digest(Crypto.SHA_1, list);
	
	// Step 7: Compare recovered hash with generated hash
	var hashSDAD = decryptedSDAD.bytes(decryptedSDAD.length - 21, 20);
	print("<-----------------------------DDA was successful------------------------------>\n");
}



			