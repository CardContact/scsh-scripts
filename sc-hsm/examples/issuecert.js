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
 * <p>This script uses a simple CA located in the ca/ directory.</p>
 * <p>You can change the issueCertificate() calls to create your own test setup.</p>
 *
 */

load("../lib/smartcardhsm.js");

load("tools/eccutils.js");

load("../ca/ca.js");

load("../lib/hsmkeystore.js");

// Some default values
var userPIN = new ByteString("648219", ASCII);
var initializationCode = new ByteString("57621880", ASCII);



// Some default value
var name = "Joe Doe";
var emailaddress = "joe.doe@openehic.org";



function issueCertificate(ca, hsmks, cn, keysizeOrCurve, profile, emailaddress) {
	var label = cn;
	var subject = [ { C:"DE" }, { O:"CardContact" }, { OU:"CardContact Demo CA 1" }, { CN:cn } ];

	print("Generating key pair for " + cn);
	if (typeof(keysizeOrCurve) == "string") {
		var req = hsmks.generateECCKeyPair(label, keysizeOrCurve);
	} else {
		var req = hsmks.generateRSAKeyPair(label, keysizeOrCurve);
	}
	// No request checking so far
	var publicKey = req.getPublicKey();

	if (typeof(keysizeOrCurve) == "string") {
		publicKey.setComponent(Key.ECC_CURVE_OID, new ByteString(keysizeOrCurve, OID));
	}

	var extvalues = { email : emailaddress };
	print("Issuing certificate for " + cn);
	var cert = ca.issueCertificate(publicKey, subject, profile, extvalues);
	print(cert);

	hsmks.storeEndEntityCertificate(label, cert);
}




// Use default crypto provider
var crypto = new Crypto();

// Create card access object
var card = new Card(_scsh3.reader);

card.reset(Card.RESET_COLD);

// Create SmartCard-HSM card service
var sc = new SmartCardHSM(card);

var doinit = true;
// Check if device is yet un-initialized
if (!sc.isInitialized()) {
	var page = "<html><p><b>Warning:</b></p><br/>" +
			   "<p>This is a new device that has never been initialized before.</p><br/>" +
			   "<p>If you choose to continue, then the device initialization code will be set to " + initializationCode.toString(ASCII) + "</p><br/>" +
			   "<p>Please be advised, that this code can not be changed once set. The same code must be used in subsequent re-initialization of the device.</p><br/>" +
			   "<p>Press OK to continue or Cancel to abort.</p>" +
			   "</html>";
	var userAction = Dialog.prompt(page);
	assert(userAction != null);
} else {
	doinit = (Dialog.prompt("OK to initialize device ?") != null);
}

if (doinit) {
	sc.initDevice(new ByteString("0001", HEX), userPIN, initializationCode, 3);
}

// Verify user PIN
assert(sc.verifyUserPIN(userPIN) == 0x9000, "PIN Verification failed");

name = Dialog.prompt("User Name", name);
assert(name != null);

emailaddress = Dialog.prompt("e-Mail address", emailaddress);
assert(emailaddress != null);


// Create and initialize simple CA
var ca = new X509CA(crypto);

var fn = GPSystem.mapFilename("../ca/DEMO-CA.jks", GPSystem.CWD);
var ks = new KeyStore("SUN", "JKS", fn, "openscdp");
var key = new Key();
key.setID("DEMOCA");

ks.getKey(key, "openscdp");
ca.setSignerKey(key);

var cert = ks.getCertificate("DEMOCA");
ca.setSignerCertificate(cert);

var hsmks = new HSMKeyStore(sc);

issueCertificate(ca, hsmks, name + " (RSA2048)", 2048, "EmailAndTLSClient", emailaddress);
issueCertificate(ca, hsmks, name + " (ECC-SECP256)", "secp256r1", "TLSClient", emailaddress);
issueCertificate(ca, hsmks, name + " (ECC-SECP192)", "secp192r1", "TLSClient", emailaddress);
issueCertificate(ca, hsmks, name + " (ECC-BP224)", "brainpoolP224r1", "TLSClient", emailaddress);
issueCertificate(ca, hsmks, name + " (ECC-BP320)", "brainpoolP320r1", "TLSClient", emailaddress);
issueCertificate(ca, hsmks, name + " (RSA1536)", 1536, "EmailAndTLSClient", emailaddress);
issueCertificate(ca, hsmks, name + " (RSA1024)", 1024, "EmailAndTLSClient", emailaddress);
