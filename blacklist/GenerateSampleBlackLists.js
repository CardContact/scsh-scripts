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

var crypto = new Crypto();

// Generate an asymmetric 2048 bit key pair and a self signed certificate for Alice
print("Generating data for Alice...\n");

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

// 32 byte data blocks for sector ID and sector specific revocations
var sectorID = new ByteString("0001020304050607080900010203040506070809000102030405060708090001", HEX);
var sectorSpecificID = new ByteString("0101010101010101010101010101010101010101010101010101010101010101", HEX);

// Define how many elements should be added to the added/removed lists
var numberOfEntries = 50000;

// Generate black list with added items
generator = new BlackListGenerator();

var version = new ByteString("00", HEX);
generator.setVersion(version);

generator.setType(BlackListGenerator.ADDED_LIST);
var listID = new ByteString("01", HEX); 
generator.setListID(listID);

var sector_A = sectorID;

var sectorSpecificIDs_A = new Array();

// Create entries to the added list
for (var i = 0; i < numberOfEntries; i++) {
	sectorSpecificIDs_A[i] = sectorSpecificID;
}

generator.addBlackListDetails(sector_A, sectorSpecificIDs_A);

var blackList = generator.generateBlackList();
var bl_added = new ASN1(blackList);
print(bl_added);
print("Total bytes: " + blackList.length);

// Construct and create the CMS signed data object
var cmsGenerator = new CMSGenerator(CMSGenerator.TYPE_SIGNED_DATA);
cmsGenerator.setDataContent(blackList);
cmsGenerator.addSigner(privKeyA, certA, new ByteString("id-sha1", OID), true);

var cms = cmsGenerator.generate();
print(cms);

writeFileOnDisk("blacklist.bin", cms);

/*
// Generate black list with removed items
generator = new BlackListGenerator();

var version = new ByteString("00", HEX);
generator.setVersion(version);

generator.setType(BlackListGenerator.REMOVED_LIST);

var listID = new ByteString("03", HEX); 
generator.setListID(listID);

var sector_B = sectorID;
var sectorSpecificIDs_B = new Array();
// Create entries to the added list
for (var i = 0; i < numberOfEntries; i++) {
	sectorSpecificIDs_B[i] = sectorSpecificID;
}
generator.addBlackListDetails(sector_B, sectorSpecificIDs_B);

var blackList = generator.generateBlackList();
var bl_removed = new ASN1(blackList);
print(bl_removed);
print("Total bytes: " + blackList.length);
*/