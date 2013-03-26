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
 * @fileoverview Generator for PKCS#10 encoded certificate requests
 */


// Load classes
load("tools/file.js");
load("../lib/smartcardhsm.js");
load("../lib/hsmkeystore.js");



// Information for PKCS#10 Request
var data = new ASN1(ASN1.SEQUENCE);

var commonname = Dialog.prompt("Common Name", "");					// Common Name
if ((commonname != null) && (commonname != "")) {
  data.add(new ASN1(ASN1.SET,
		   new ASN1(ASN1.SEQUENCE,		// Common name
		   new ASN1(ASN1.OBJECT_IDENTIFIER, new ByteString("id-at-commonName", OID)),
		   new ASN1(ASN1.UTF8String, new ByteString(commonname, UTF8))))); 
  }


var business = Dialog.prompt("Business Name", "OpenSCDP");				// Business Name
if ((business != null) && (business != "")) {
  data.add(new ASN1(ASN1.SET,
		   new ASN1(ASN1.SEQUENCE, 		// Business Name
		   new ASN1(ASN1.OBJECT_IDENTIFIER, new ByteString("id-at-organizationName", OID)),
		   new ASN1(ASN1.PrintableString, new ByteString(business, ASCII)))));
  }

  
var department = Dialog.prompt("Department Name", "");					// Department Name
if ((department != null) && (department != "")) {
  data.add(new ASN1(ASN1.SET,
		   new ASN1(ASN1.SEQUENCE, 		// Department Name
		   new ASN1(ASN1.OBJECT_IDENTIFIER, new ByteString("id-at-organizationalUnitName", OID)),
		   new ASN1(ASN1.PrintableString, new ByteString(department, ASCII)))));
  }
  

var town = Dialog.prompt("Town", "");							// Town
if ((town != null) && (town != "")) {
  data.add(new ASN1(ASN1.SET,
		   new ASN1(ASN1.SEQUENCE, 		// Town
		   new ASN1(ASN1.OBJECT_IDENTIFIER, new ByteString("id-at-localityName", OID)),
		   new ASN1(ASN1.PrintableString, new ByteString(town, ASCII)))));
  }
  
  
var province = Dialog.prompt("Province", "");						// Province
if ((province != null) && (province != "")) {
  data.add(new ASN1(ASN1.SET,
		   new ASN1(ASN1.SEQUENCE, 		// Province
		   new ASN1(ASN1.OBJECT_IDENTIFIER, new ByteString("id-at-stateOrProvinceName", OID)),
		   new ASN1(ASN1.PrintableString, new ByteString(province, ASCII)))));
  }
  
   
var country = Dialog.prompt("Country", "DE");						// Country
if ((country != null) && (country != "")) {
  data.add(new ASN1(ASN1.SET,
		   new ASN1(ASN1.SEQUENCE,				// Country
		   new ASN1(ASN1.OBJECT_IDENTIFIER, new ByteString("id-at-countryName", OID)),
		   new ASN1(ASN1.PrintableString, new ByteString(country, ASCII)))));
  }


var eMailAddress = Dialog.prompt("Please enter your e-mail address", ""); 		// User's e-mail address
if ((eMailAddress != null) && (eMailAddress != "")) {
  data.add(new ASN1(ASN1.SET,
		   new ASN1(ASN1.SEQUENCE, 		// User's e-mail address
		   new ASN1(ASN1.OBJECT_IDENTIFIER, new ByteString("1 2 840 113549 1 9 1", OID)),
		   new ASN1(ASN1.IA5String, new ByteString(eMailAddress, ASCII)))));
  }
  
  
/// CertificationRequestInfo
var certificationRequestInfo = new ASN1(ASN1.SEQUENCE);
certificationRequestInfo.add(new ASN1(ASN1.INTEGER, new ByteString("00", HEX))); 	// Version number
certificationRequestInfo.add(data);
				      
// Use default crypto provider
var crypto = new Crypto();

// Card access
var card = new Card();

// Reset card
card.reset(Card.RESET_COLD);

// Create card access object
var sc = new SmartCardHSM(card);

// Verify user PIN
var userPIN = Dialog.prompt("Please enter user PIN for SmartCard-HSM", "648219");
assert(userPIN != null);
sc.verifyUserPIN(new ByteString(userPIN, ASCII));

// Keypair label
var label = eMailAddress;
print("Using label \"" + label + "\" for key");

// Key store front-end
var hsmks = new HSMKeyStore(sc);
sc.enumerateKeys();

// Check for same-named keypair
var key = sc.getKey(label);
if (key) {
	assert(Dialog.prompt("A key with the label " + label + " already exists. Press OK to delete the key"));
	hsmks.deleteKey(label);
}

// Generate asymmetric keypair
print("Generating a 2048 bit RSA key pair can take up to 60 seconds. Please wait...");
var req = hsmks.generateRSAKeyPair(label, 2048);

// Get public-key
var pubkey = req.getPublicKey();
var encPK = new ASN1(ASN1.SEQUENCE);
encPK.add(new ASN1(ASN1.INTEGER, pubkey.getComponent(Key.MODULUS)));	// modulus
encPK.add(new ASN1(ASN1.INTEGER,pubkey.getComponent(Key.EXPONENT)));	// exponent

// Information the public-key
var SubjectPublicKeyInfo = new ASN1(ASN1.SEQUENCE);
SubjectPublicKeyInfo.add(new ASN1(ASN1.SEQUENCE,
				    new ASN1(ASN1.OBJECT_IDENTIFIER, new ByteString("rsaEncryption", OID)),	// public-key algorithm
				    new ASN1(ASN1.NULL)));							// attributes
SubjectPublicKeyInfo.add(new ASN1(ASN1.BIT_STRING, 
				    new ByteString("00", HEX).concat(encPK.getBytes()))); 			// public-key
certificationRequestInfo.add(SubjectPublicKeyInfo);

var Attributes = new ASN1(ASN1.CONTEXT | 0x20 | 0x00);								// attributes
certificationRequestInfo.add(Attributes);

var signature = sc.getCrypto().sign(sc.getKey(label), Crypto.RSA_SHA256, certificationRequestInfo.getBytes());	// signed certificationRequestInfo


/// CertificationRequest
var AlgorithmIdentifier = new ASN1(ASN1.SEQUENCE);
AlgorithmIdentifier.add(new ASN1(ASN1.OBJECT_IDENTIFIER, 
				   new ByteString("sha256WithRSAEncryption", OID)));				// algorithm
AlgorithmIdentifier.add(new ASN1(ASN1.NULL));									// parameter

// Encoded signature
var encodedsignature = new ASN1(ASN1.BIT_STRING, 
				  new ByteString("00", HEX).concat(signature));

// PKCS#10 Request
var CertRequest = new ASN1(ASN1.SEQUENCE);
CertRequest.add(certificationRequestInfo);
CertRequest.add(AlgorithmIdentifier);
CertRequest.add(encodedsignature);

//print(CertRequest);

// Writing PKCS#10 Request to file
var csrfile = new File("CSR_" + label);
var csrbinary = CertRequest.getBytes();
var csrbase64 = csrbinary.toBase64(true);
var header = new ByteString("-----BEGIN CERTIFICATE REQUEST-----\n", ASCII);
var footer = new ByteString("\n-----END CERTIFICATE REQUEST-----", ASCII);
var pem = header.concat(csrbase64).concat(footer);
csrfile.writeAll(pem);

print("PKCS#10 Request written to file >> " + "CSR_" + label + " <<");
