load("EAC2CVRequestGenerator.js");

function test(crypto, priKey, pubKey, taOID) {
	var reqGenerator = new EAC2CVRequestGenerator(crypto);

	// Set CPI
	reqGenerator.setProfileIdentifier(0x00);

	// Set "inner" CAR
	var CAR = "decvca00000";
	reqGenerator.setCAR(CAR);
    
	// Set public key for request
	reqGenerator.setPublicKey(pubKey);

	// Set oid of algorithm
	reqGenerator.setTAAlgorithmIdentifier(taOID);

	// Set some dummy extensions
	var ext1 = new ASN1("ext1", new ByteString("06022A11", HEX));
	var ext2 = new ASN1("ext2", new ByteString("06022A12", HEX));
	reqGenerator.setExtensions([ext1, ext2]);

	// Set CHR for the request
	var CHR = "dedvca00001";
	reqGenerator.setCHR(CHR);

	// Generate the request
	var req = reqGenerator.generateAuthenticatedCVRequest(priKey, priKey, new PublicKeyReference("dedvca00000"), taOID);
	print(req);

	var cvreq = new CVC(req);
	print(cvreq);

	assert(cvreq.verifyWith(crypto, pubKey, taOID));
	assert(cvreq.verifyATWith(crypto, pubKey, taOID));
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
