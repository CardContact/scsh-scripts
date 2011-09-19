load("EAC2CVCertificateGenerator.js");

function test(crypto, priKey, pubKey, taOID) {
	generator = new EAC2CVCertificateGenerator(crypto);

	var CAR = "decvca00000";
	generator.setCAR(CAR);

	var CHR = "decvca00000";
	generator.setCHR(CHR);

	generator.setEffectiveDate(new Date());

	var notAfter = "110225";
	generator.setExpiryDate(notAfter);

	var chatOID = "0.4.0.127.0.7.3.1.2.1"; // inspection system
	generator.setChatOID(new ByteString(chatOID, OID));

	var chatAuth = "E3"; // CVCA, read access to eID, DG3, DG4
	
	generator.setChatAuthorizationLevel(new ByteString(chatAuth, HEX));

	generator.setPublicKey(pubKey);

	var profileIdentifier = 0x00;

	generator.setProfileIdentifier(profileIdentifier);

	generator.setTAAlgorithmIdentifier(taOID);

	//var extensions = new Array();
	//extensions[0] = new ASN1("ext1", ASN1.OBJECT_IDENTIFIER, new ByteString("2A1200", HEX));
	//extensions[1] = new ASN1("ext2", ASN1.OBJECT_IDENTIFIER, new ByteString("2A1200", HEX));

	//generator.setExtensions(extensions);

	generator.setIncludeDomainParameters(true);

	var cvc = generator.generateCVCertificate(priKey, taOID);
	print(cvc);
	
	print(new ASN1(cvc.getBytes()));
	cvc.verifyWith(crypto, cvc.getPublicKey(), cvc.getPublicKeyOID());
}


var crypto = new Crypto();

var priKey = new Key();
var pubKey = new Key();
priKey.setType(Key.PRIVATE);
pubKey.setType(Key.PUBLIC);
priKey.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP256t1", OID));
pubKey.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP256t1", OID));
crypto.generateKeyPair(Crypto.EC, pubKey, priKey);

test(crypto, priKey, pubKey, new ByteString("id-TA-ECDSA-SHA-256", OID));


var priKey = new Key();
var pubKey = new Key();
priKey.setType(Key.PRIVATE);
pubKey.setType(Key.PUBLIC);
pubKey.setSize(1024);
crypto.generateKeyPair(Crypto.RSA, pubKey, priKey);

test(crypto, priKey, pubKey, new ByteString("id-TA-RSA-v1-5-SHA-256", OID));
