defineClass("de.cardcontact.scdp.cms.JsCMSGenerator");

load("BlackListGenerator.js");

load("tools/x509certificategenerator.js");
load("tools/oid/icao.js");
load("tools/oid/pkix.js");

/*
 * Write a byte string object to file
 *
 * The filename is mapped to the location of the script
 *
 * name		Name of file
 * content	ByteString content for file
 *
 */
function writeFileOnDisk(name, content) {

	// Map filename
	var filename = GPSystem.mapFilename(name, GPSystem.USR);
	print("Writing " + filename);

	var file = new java.io.FileOutputStream(filename);
	file.write(content);
	file.close();
}

// Create the crypto object
var crypto = new Crypto();

// Generate an asymmetric 2048 bit key pair and a self signed certificate for Alice
print("Generating key pair and self-signed certificate for Alice...\n");

var privKeyA = new Key();
privKeyA.setType(Key.PRIVATE);

var pubKeyA = new Key();
pubKeyA.setType(Key.PUBLIC);
pubKeyA.setSize(2048);
	
crypto.generateKeyPair(Crypto.RSA, pubKeyA, privKeyA);
	
var x = new X509CertificateGenerator(crypto);

x.reset();
x.setSerialNumber(new ByteString("01", HEX));
x.setSignatureAlgorithm(Crypto.RSA);
var issuer = { C:"UT", O:"ACME Corporation", CN:"Test-CA" };
x.setIssuer(issuer);
x.setNotBefore("060825120000Z");
x.setNotAfter("160825120000Z");
var subject = { C:"UT", O:"Utopia CA", OU:"ACME Corporation", CN:"Alice" };
x.setSubject(subject);
x.setPublicKey(pubKeyA);
x.addKeyUsageExtension(	X509CertificateGenerator.digitalSignature |
							X509CertificateGenerator.keyCertSign |
							X509CertificateGenerator.cRLSign );
							
x.addBasicConstraintsExtension(true, 0);
x.addSubjectKeyIdentifierExtension();
x.addAuthorityKeyIdentifierExtension(pubKeyA);

var certA = x.generateX509Certificate(privKeyA);


// Define how many elements should be added to the added/removed lists
var numberOfEntries = 10;
print("Creating list for " + numberOfEntries + " entries\n");

// Generate black list with added items
generator = new BlackListGenerator();

// Set black list version
var version = new ByteString("00", HEX);
generator.setVersion(version);

// Set black list type
generator.setType(BlackListGenerator.ADDED_LIST);
var listID = new ByteString("01", HEX); 
generator.setListID(listID);

// Define some random value for the sector ID
var sector_A = crypto.generateRandom(32);

var sectorSpecificIDs_A = new Array();

// Create sector specific entries at random and add them to the list
for (var i = 0; i < numberOfEntries; i++) {
	sectorSpecificIDs_A[i] = crypto.generateRandom(32);
}

// Add the complete details to the list
generator.addBlackListDetails(sector_A, sectorSpecificIDs_A);


// Create a second sector ID at random
var sector_B = crypto.generateRandom(32);

var sectorSpecificIDs_B = new Array();

// Create entries to the added list
for (var i = 0; i < numberOfEntries; i++) {
	sectorSpecificIDs_B[i] = crypto.generateRandom(32);
}

generator.addBlackListDetails(sector_B, sectorSpecificIDs_B);

var blackList = generator.generateBlackList();
var bl_added = new ASN1(blackList);
print(bl_added);
print("Total bytes: " + blackList.length);

// Construct and create the CMS signed data object
var cmsGenerator = new CMSGenerator(CMSGenerator.TYPE_SIGNED_DATA);
cmsGenerator.setDataContent(blackList);
cmsGenerator.addSigner(privKeyA, certA, new ByteString("id-sha1", OID), true);

var contentOID = new ByteString("0.4.0.127.0.7.3.2.2", OID);
var cms = cmsGenerator.generate(contentOID);

writeFileOnDisk("blacklist.bin", cms);