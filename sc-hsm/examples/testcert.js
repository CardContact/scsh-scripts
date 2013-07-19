/**
 *  ---------
 * |.##> <##.|  SmartCard-HSM Support Scripts
 * |#       #|  
 * |#       #|  Copyright (c) 2011-2012 CardContact Software & System Consulting
 * |'##> <##'|  Andreas Schwier, 32429 Minden, Germany (www.cardcontact.de)
 *  --------- 
 *
 * Consult your license package for usage terms and conditions.
 * 
 * @fileoverview Perform a signature generation and verification using keys stored on a SmartCard-HSM with the issuercert.js scripts
 */

load("../../icao/cvcertstore.js");
load("../lib/smartcardhsm.js");
load("../lib/hsmkeystore.js");

load("tools/eccutils.js");


// Some default values
var userPIN = new ByteString("648219", ASCII);



// Use default crypto provider
var crypto = new Crypto();

// Create card access object
var card = new Card(_scsh3.reader);
card.reset(Card.RESET_COLD);

// Create SmartCard-HSM card service
var sc = new SmartCardHSM(card);

// Verify user PIN
sc.verifyUserPIN(userPIN);

// Create key store
var ks = new HSMKeyStore(sc);

// Obtain crypto object for SmartCard-HSM
var sccrypto = sc.getCrypto();

// Message to be signed
var message = new ByteString("Hello World", ASCII);

// List all stored keys
var keylist = ks.enumerateKeys();

for each (keyname in keylist) {
	print("Key label: " + keyname);

	// Get key handle
	var key = ks.getKey(keyname);
	assert(key != null);

	// Get certificate
	var cert = ks.getEndEntityCertificate(keyname);
	assert(cert != null);

//	print(cert);
	var publicKey = cert.getPublicKey();

	if (keyname.indexOf("ECC") < 0) {
		var signature = sccrypto.sign(key, Crypto.RSA, message);		// Uses default signing algorithm PKCS#1 V1.5
		print("Signature: " + signature.toString(HEX));
		var ok = crypto.verify(publicKey, Crypto.RSA_SHA256, message, signature);
	} else {
		var signature = sccrypto.sign(key, Crypto.ECDSA, message);		// Uses default signing algorithm ECDSA with SHA-256
		print("Signature: " + signature.toString(HEX));
		var ok = crypto.verify(publicKey, Crypto.ECDSA_SHA256, message, signature);
	} 
	print("Signature verification " + (ok ? "passed" : "failed"));
}
