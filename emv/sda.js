/**
 * SDA class constructor
 * @class This class implements static data authentication
 * @constructor
 * @param {EMV} emv an instance of the EMV class
 */
function SDA(emv) {
	this.emv = emv;
	this.crypto= emv.crypto;
	this.schemePublicKeyTable = [];
}

/**
 * Get RID from EMV data model
 *
 * @type ByteString
 * @return the 5 byte RID
 */
SDA.prototype.getRID = function() {
	var aid = this.emv.cardDE[EMV.AID];
	var rid = aid.left(5);
	return(rid);
}

/**
 * Get the public key index
 *
 * @type Number
 * @return the public key index
 */
SDA.prototype.getPubKeyIndex = function() {
	var index = this.emv.cardDE[0x8F];
	var index = index.toUnsigned();
	//print(index);
	return(index);
}

/*
SDA.schemePublicKeyTable = [];
SDA.schemePublicKeyTable["A000000003"] = [];
SDA.schemePublicKeyTable["A000000003"][0x01] = new Key("schemepublickeys/kp_visa_1024_01.xml");
*/


/**
 * Add a new public key to the array
 *
 * @param {ByteString} rid
 * @param {Number} index the public key index
 * @param {Key} key the public key
 */
SDA.prototype.addSchemePublicKey = function(rid, index, key) {
	
	this.schemePublicKeyTable[rid.toString(HEX)] = [];
	this.schemePublicKeyTable[rid.toString(HEX)][index] = key;
}


/**
 * Get the public key
 *
 *@type Key
 *@return the public key
*/
SDA.prototype.getSchemePublicKey = function() {
	var rid = this.getRID();
	var index = this.getPubKeyIndex();
	
	var key = this.schemePublicKeyTable[rid.toString(HEX)][index];
	
	return(key);
}

/**
 * Decrypt the Issuer PK Certificate
*/
SDA.prototype.decryptIssuerPKCertificate = function() {

	var certificate = this.emv.cardDE[0x90];
//	print("Encrypted Issuer PK Certificate: ");
//	print(certificate);

	var key = this.getSchemePublicKey();

	var decryptedCertificate = crypto.decrypt(key, Crypto.RSA, certificate);
//	print("Decrypted Issuer PK Certificate: ");
//	print(decryptedCertificate);
	return(decryptedCertificate);
}

SDA.prototype.authenticate = function() {
	var key = this.getSchemePublicKey();
	var modulus = key.getComponent(Key.MODULUS);
	var cert = this.decryptIssuerPKCertificate();		
	
	assert(cert.length == modulus.length);
	assert(cert.byteAt(0) == 0x6A);
	assert(cert.byteAt(1) == 0x02);
	
	print(modulus.length);
	var list;
	list = cert.bytes(1, 14 + (modulus.length - 36));
	print(list);
}
/*
VisaPublicKey = [];
VisaPublicKey[1] = {
					modulus: new ByteString("C696034213D7D8546984579D1D0F0EA519CFF8DEFFC429354CF3A871A6F7183F1228DA5C7470C055387100CB935A712C4E2864DF5D64BA93FE7E63E71F25B1E5F5298575EBE1C63AA617706917911DC2A75AC28B251C7EF40F2365912490B939BCA2124A30A28F54402C34AECA331AB67E1E79B285DD5771B5D9FF79EA630B75", HEX),
					exponent: new ByteString("03", HEX)
				};
*/				