load("EAC2CVRequestGenerator.js");

var CAR = "decvca0000";
var CHR = "dedvca0001";

var crypto = new Crypto("BC");
    
//Create empty private key object
var priKey = new Key("kp_dvca_ec_private.xml");

var pubKey = new Key("kp_dvca_ec_public.xml");

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
var req = reqGenerator.generateCVRequest(priKey);
   
outline = new OutlineNode("CV-Request");
outline.insert(req);
outline.show();