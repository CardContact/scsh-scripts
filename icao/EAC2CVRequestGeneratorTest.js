load("EAC2CVRequestGenerator.js");

var CAR = "decvca00000";
var CHR = "dedvca00001";

var crypto = new Crypto();
    
var priKey = new Key();
var pubKey = new Key();
priKey.setType(Key.PRIVATE);
pubKey.setType(Key.PUBLIC);
priKey.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP256t1", OID));
pubKey.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP256t1", OID));
crypto.generateKeyPair(Crypto.EC, pubKey, priKey);

var reqGenerator = new EAC2CVRequestGenerator(crypto);

// Set CPI
reqGenerator.setProfileIdentifier(0x00);

// Set "inner" CAR
reqGenerator.setCAR(CAR);
    
// Set public key for request
reqGenerator.setPublicKey(pubKey);

// Set oid of algorithm
var taAlgorithmIdentifier = "0.4.0.127.0.7.2.2.2.2.3"; // ECDSA - SHA 256
reqGenerator.setTAAlgorithmIdentifier(new ByteString(taAlgorithmIdentifier, OID));

// Set some dummy extensions
var ext1 = new ASN1("ext1", new ByteString("06022A11", HEX));
var ext2 = new ASN1("ext2", new ByteString("06022A12", HEX));
reqGenerator.setExtensions([ext1, ext2]);

// Set CHR for the request
reqGenerator.setCHR(CHR);

// Generate the request
var req = reqGenerator.generateAuthenticatedCVRequest(priKey, priKey, new PublicKeyReference("dedvca00000"));
var cvreq = new CVC(req);
print(cvreq);

assert(cvreq.verifyWith(crypto, pubKey));
assert(cvreq.verifyATWith(crypto, pubKey));

outline = new OutlineNode("CV-Request");
outline.insert(req);
outline.show();