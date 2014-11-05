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
 * @fileoverview Script to issue X.509 certificates for keys generated on the SmartCard-HSM
 *
 * <p>This script generates EC key on secp256k1, the Bitcoin curve and performs a signature operation</p>
 *
 */


load("../lib/smartcardhsm.js");

var pin = new ByteString("648219", ASCII);


// Attach to card and reset
var crypto = new Crypto();
var card = new Card(_scsh3.reader);
card.reset(Card.RESET_COLD);


// Create card service instance
var sc = new SmartCardHSM(card);


sc.verifyUserPIN(pin);

var keyid = 1;
var chr = new PublicKeyReference("UT", "TESTKEY01", "00000");
var innerCAR = new PublicKeyReference("DECA00001" + "00001");
var algo = new ByteString("id-TA-ECDSA-SHA-256", OID);

var dp = new Key();
dp.setType(Key.PUBLIC);
dp.setComponent(Key.ECC_CURVE_OID, new ByteString("1.3.132.0.10", OID));

var keydata = SmartCardHSM.buildGAKPwithECC(innerCAR, algo, chr, dp);

var rsp = this.sc.generateAsymmetricKeyPair(keyid, 0, keydata);

print(new ASN1(rsp));

var cvc = new CVC(rsp);
var puk = cvc.getPublicKey();

// Create the message digest as input data

var data = new ByteString("Hello World", ASCII);
var hash = crypto.digest(Crypto.SHA_256, data);

print("Sign...");

var algorithm = 0x70; //ECDSA
var rsp = sc.sign(keyid, algorithm, hash);
print(new ASN1(rsp));

//Verify 

var verified = crypto.verify(puk, Crypto.ECDSA_SHA256, data, rsp);
assert(verified, "Verification of ECC signature failed");
