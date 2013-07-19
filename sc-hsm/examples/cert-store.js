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
 * @fileoverview Store X.509 certificate on the SmartCard
 */


// Load classes
load("../lib/smartcardhsm.js");
load("../lib/hsmkeystore.js");

// Card access
var card = new Card();

// Reset card
card.reset(Card.RESET_COLD);

// Select SmartCard-HSM application
card.sendApdu(0x00, 0xA4, 0x04, 0x04, new ByteString("E8 2B 06 01 04 01 81 C3 1F 02 01", HEX), [0x9000]);

// Create card access object
var sc = new SmartCardHSM(card);

// Verify user PIN
var userPIN = Dialog.prompt("Please enter user PIN for SmartCard-HSM", "648219");
assert(userPIN != null);
sc.verifyUserPIN(new ByteString(userPIN, ASCII));

// Key store front-end
var hsmks = new HSMKeyStore(sc);
sc.enumerateKeys();

// Keypair label
var eMailAddress = Dialog.prompt("Please enter your e-mail address", ""); 
var label = eMailAddress;
var key = sc.getKey(label);

// openssl x509 -outform der -in certificate.pem -out certificate.der

// Select certificate (*.der) for storing on the SmartCard
var hsmks = new HSMKeyStore(sc);
var certder = Dialog.prompt("Select X.509 certificate", "", null, "*.der");
var cert = new X509(certder);
hsmks.storeEndEntityCertificate(label, cert);
print("X.509 certificate written to SmartCard...");