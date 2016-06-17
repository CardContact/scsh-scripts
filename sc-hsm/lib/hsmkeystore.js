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
 * @fileoverview Class implementing a key store for X.509 certificate and private keys stored on a SmartCard-HSM
 */


/**
 * Create a simple key store front-end
 *
 * @class Class implementing some simple access functions to generate key pairs and store certificates
 * @param {SmartCardHSM} sc the SmartCard-HSM card service
 */ 
function HSMKeyStore(sc) {
	this.sc = sc;
}



/**
 * Generate a RSA key pair
 *
 * @param {String} label the label under which the key pair shall be stored
 * @param {Number} keysize the key size in bits (1024, 1536 or 2048)
 */
HSMKeyStore.prototype.generateRSAKeyPair = function(label, keysize) {
	this.sc.enumerateObjects();

	var key = this.sc.getKey(label);
	if (key) {
		var newkid = key.getId();
	} else {
		var newkid = this.sc.determineFreeKeyId();
	}

	var chr = new PublicKeyReference("UTNULL00000");
	var car = new PublicKeyReference("UTNULL00000");
	var algo = new ByteString("id-TA-RSA-v1-5-SHA-256", OID);

	var keydata = SmartCardHSM.buildGAKPwithRSA(car, algo, chr, keysize);
	var keydesc = SmartCardHSM.buildPrkDforRSA(newkid, label, keysize);

	var reqbin = this.sc.generateAsymmetricKeyPair(newkid, 0, keydata);

	var fid = ByteString.valueOf((SmartCardHSM.PRKDPREFIX << 8) + newkid);
	this.sc.updateBinary(fid, 0, keydesc.getBytes());
	var req = new CVC(reqbin);
	
	var hkey = new SmartCardHSMKey(this.sc, newkid);
	hkey.setDescription(keydesc);
	this.sc.addKeyToMap(hkey);
	return req;
}



/**
 * Generate an ECDSA key pair
 *
 * @param {String} label the label under which the key pair shall be stored
 * @param {String} curve the curve object identifier
 */
HSMKeyStore.prototype.generateECCKeyPair = function(label, curve) {
	this.sc.enumerateObjects();

	var key = this.sc.getKey(label);
	if (key) {
		var newkid = key.getId();
	} else {
		var newkid = this.sc.determineFreeKeyId();
	}

	var chr = new PublicKeyReference("UTNULL00000");
	var car = new PublicKeyReference("UTNULL00000");
	var algo = new ByteString("id-TA-ECDSA-SHA-256", OID);

	var dp = new Key();
	dp.setComponent(Key.ECC_CURVE_OID, new ByteString(curve, OID));

	var keydata = SmartCardHSM.buildGAKPwithECC(car, algo, chr, dp);
	print("Keysize: " + dp.getSize());
	var keydesc = SmartCardHSM.buildPrkDforECC(newkid, label, dp.getSize());

	var reqbin = this.sc.generateAsymmetricKeyPair(newkid, 0, keydata);

	var fid = ByteString.valueOf((SmartCardHSM.PRKDPREFIX << 8) + newkid);
	this.sc.updateBinary(fid, 0, keydesc.getBytes());
	var req = new CVC(reqbin);
	
	var hkey = new SmartCardHSMKey(this.sc, newkid);
	hkey.setDescription(keydesc);
	this.sc.addKeyToMap(hkey);
	return req;
}



/**
 * Store certificate under given label
 *
 * @param {String} label the label under which the certificate shall be stored
 * @param {X509} cert the certificate
 */
HSMKeyStore.prototype.storeEndEntityCertificate = function(label, cert) {
	var key = this.sc.getKey(label);
	if (key) {
		var kid = key.getId();
	} else {
		throw new GPError("HSMKeyStore", GPError.INVALID_DATA, 0, "Could not find a key with label " + label);
	}
	
	var fid = ByteString.valueOf((SmartCardHSM.EECERTIFICATEPREFIX << 8) + kid);
	this.sc.updateBinary(fid, 0, cert.getBytes());
}



/**
 * Delete key and certificate with given label
 *
 * @param {String} label the label of the key to be removed
 */
HSMKeyStore.prototype.deleteKey = function(label) {
	var key = this.sc.getKey(label);
	if (key) {
		var kid = key.getId();
	} else {
		throw new GPError("HSMKeyStore", GPError.INVALID_DATA, 0, "Could not find a key with label " + label);
	}
	
	var fid = ByteString.valueOf((SmartCardHSM.KEYPREFIX << 8) + kid);
	this.sc.deleteFile(fid);

	try	{
		var fid = ByteString.valueOf((SmartCardHSM.PRKDPREFIX << 8) + kid);
		this.sc.deleteFile(fid);

		var fid = ByteString.valueOf((SmartCardHSM.EECERTIFICATEPREFIX << 8) + kid);
		this.sc.deleteFile(fid);
	}
	catch(e) {
		// Ignore
	}
	this.enumerateKeys();
}



/**
 * Return list of keys
 *
 * @type String[]
 * @return the list of key names
 */
HSMKeyStore.prototype.enumerateKeys = function() {
	return this.sc.enumerateKeys();
}



/**
 * Get key for given label
 *
 * @param {String} label the certificate label
 * @type Key
 * @return the key
 */
HSMKeyStore.prototype.getKey = function(label) {
	this.sc.enumerateKeys();
	var key = this.sc.getKey(label);
	if (!key) {
		throw new GPError("HSMKeyStore", GPError.INVALID_DATA, 0, "Could not find a key with label " + label);
	}
	return key;
}



/**
 * Get certificate for given label
 *
 * @param {String} label the certificate label
 * @type X509
 * @return the certificate
 */
HSMKeyStore.prototype.getEndEntityCertificate = function(label) {
	var key = this.getKey(label);
	var kid = key.getId();
	var fid = ByteString.valueOf((SmartCardHSM.EECERTIFICATEPREFIX << 8) + kid);
	var certbin = this.sc.readBinary(fid);
	return new X509(certbin);
}
