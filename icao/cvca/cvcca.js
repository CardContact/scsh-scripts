/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2010 CardContact Software & System Consulting
 * |'##> <##'|  Andreas Schwier, 32429 Minden, Germany (www.cardcontact.de)
 *  --------- 
 *
 *  This file is part of OpenSCDP.
 *
 *  OpenSCDP is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  OpenSCDP is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with OpenSCDP; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * @fileoverview Simple CVC-CA for testing purposes
 */


if (typeof(__ScriptingServer) == "undefined") {
	load("../cvcertstore.js");
	load("../EAC2CVRequestGenerator.js");
	load("../EAC2CVCertificateGenerator.js");
}



/**
 * Creates a new CVC-CA instance
 *
 * @class Class supporting a certification authority that can issue CVC certificates
 * for the EAC protocol.
 *
 * @constructor
 * @param {Crypto} crypto the crypto provider to use
 * @param {CVCertificateStore} certstore the certificate store to use
 * @param {String} path the path of holderIDs (eg. "/UTCVCA/UTDVCA/UTTERM")
 */
function CVCCA(crypto, certstore, holderId, parentId, path) {
	this.crypto = crypto;
	this.certstore = certstore;
	
	if (typeof(path) == "undefined") {	// ToDo: Remove after migration
		this.holderId = holderId;
		this.parentId = parentId;
	
		if (this.isRootCA()) {		// CVCA
			this.path = "/" + holderId;
		} else {					// DVCA
			this.path = "/" + parentId + "/" + holderId;
		}
	} else {
		this.path = path;
		var pe = path.substr(1).split("/");
		var l = pe.length;
		assert(l >= 1);
		this.holderId = pe[l - 1];
		if (l > 1) {
			this.parentId = pe[l - 2];
		} else {
			this.parentId = this.holderId;
		}
	}
	this.keyspec = new Key();
	this.keyspec.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP256r1", OID));
	this.taAlgorithmIdentifier = new ByteString("id-TA-ECDSA-SHA-256", OID);
}



/**
 * Returns true if this is a root CA
 *
 * @returns true if this is a root CA
 * @type boolean
 */
CVCCA.prototype.isRootCA = function() {
	return this.holderId == this.parentId;
}



/**
 * Returns true if this CA is operational.
 *
 * @returns true if this CA is operational
 * @type boolean
 */
CVCCA.prototype.isOperational = function() {
	var currentchr = this.certstore.getCurrentCHR(this.path);
	return currentchr != null;
}



/**
 * Sets the key specification for generating requests
 *
 * @param {Key} keyparam a key object containing key parameters (e.g. EC Curve)
 * @param {ByteString} algorithm the terminal authentication algorithm object identifier
 */
CVCCA.prototype.setKeySpec = function(keyparam, algorithm) {
	this.keyspec = keyparam;
	this.taAlgorithmIdentifier = algorithm;
}



/**
 * Generate a certificate request
 *
 * @param {PublicKeyReference} car the CA at which this request is addressed
 * @param {boolean} forceInitial force an initial request, even if a current certificate is available
 * @return the certificate request
 * @type CVC
 */
CVCCA.prototype.generateRequest = function(car, forceinitial) {

	// Obtain key parameter

	var prk = new Key(this.keyspec);
	prk.setType(Key.PRIVATE);
	var puk = new Key(this.keyspec);
	puk.setType(Key.PUBLIC);

	// Determine CHR
	var currentchr = this.certstore.getCurrentCHR(this.path);
	var nextchr = this.certstore.getNextCHR(this.path);
	
	// Generate key pair
	this.crypto.generateKeyPair(Crypto.EC, puk, prk);
	
	// Save private key
	this.certstore.storePrivateKey(this.path, nextchr, prk);
	
	// Generate certificate request
	var reqGenerator = new EAC2CVRequestGenerator(this.crypto);

	// Set CPI
	reqGenerator.setProfileIdentifier(0x00);

	// Set public key for request
	reqGenerator.setPublicKey(puk);

	// Set oid of algorithm
	reqGenerator.setTAAlgorithmIdentifier(this.taAlgorithmIdentifier);

	// Set CHR for the request
	reqGenerator.setCHR(nextchr);

	if ((typeof(car) != "undefined") && (car != null)) {
		reqGenerator.setCAR(car);
	}
	
	if ((currentchr != null) && !forceinitial) {
		var previousprk = this.certstore.getPrivateKey(this.path, currentchr);
		var req = reqGenerator.generateAuthenticatedCVRequest(prk, previousprk, currentchr);
	} else {
		// Generate the request
		var req = reqGenerator.generateCVRequest(prk);
	}
	
	req = new CVC(req);
	
	this.certstore.storeRequest(this.path, req);
	
	return req;
}



/**
 * Generate certificate for certificate request
 *
 * <p>Certificate contents is defined through the policy object:</p>
 * <pre>
 *  	var policy = { certificateValidityDays: 2,
 * 				   chatRoleOID: new ByteString("id-IS", OID),
 * 				   chatRights: new ByteString("E3", HEX),
 * 				   includeDomainParameter: true,
 * 				   extensions: []
 * 				 };
 * </pre>
 *
 * @param {CVC} req the certificate request
 * @param {Object} policy the object with policy settings
 * @returns the certificate
 * @type CVC
 */
CVCCA.prototype.generateCertificate = function(req, policy) {
	var car = this.certstore.getCurrentCHR(this.path);
	var maxExpDate = null;
	
	if (car == null) {				// No CA certificate found
		if (this.isRootCA()) {
			car = req.getCHR();		// Generate a self-signed root certificate
		} else {
			throw new GPError("CVCCA", GPError.INVALID_DATA, 0, "No current certificate found");
		}
	} else {
		if (policy.shellModelForExpirationDate) {
			var cacvc = this.certstore.getCertificate(this.path, car);
			maxExpDate = cacvc.getCXD();
		}
	}
	
	var generator = new EAC2CVCertificateGenerator(this.crypto);
	generator.setCAR(car);
	generator.setCHR(req.getCHR());
	var effDate = new Date();
	effDate.setHours(12, 0, 0, 0);
	var expDate = new Date((policy.certificateValidityDays - 1) * (1000 * 60 * 60 * 24) + effDate.getTime());
	expDate.setHours(12, 0, 0, 0);

	// Expiration date of issued certificate must not exceed expiration date of issuing CA
	if ((maxExpDate != null) && (expDate.getTime() > maxExpDate.getTime())) {
		expDate = maxExpDate;
	}
	
	generator.setEffectiveDate(effDate);
	generator.setExpiryDate(expDate);
	generator.setChatOID(policy.chatRoleOID);
	generator.setChatAuthorizationLevel(policy.chatRights);
	generator.setPublicKey(req.getPublicKey());
	generator.setProfileIdentifier(0x00);
	generator.setTAAlgorithmIdentifier(this.taAlgorithmIdentifier);
	generator.setIncludeDomainParameters(policy.includeDomainParameter);
	generator.setExtensions(policy.extensions);
	var prk = this.certstore.getPrivateKey(this.path, car);
	var cvc = generator.generateCVCertificate(prk, Crypto.ECDSA_SHA256);
	
	return cvc;
}



/**
 * Store issued certificate
 *
 * @param {CVC} cert a newly issued certificate
 */
CVCCA.prototype.storeCertificate = function(cert) {
	var chrHolder = cert.getCHR().getHolder();
	this.certstore.storeCertificate(this.path + "/" + chrHolder, cert, false);
}



/**
 * Import a certificate into the certificate store and make it the current certificate
 *
 * @param {CVC} cert the certificate
 */
CVCCA.prototype.importCertificate = function(cert) {
	var prk = this.certstore.getPrivateKey(this.path, cert.getCHR());
	if (prk == null) {
		throw new GPError("CVCCA", GPError.INVALID_DATA, 0, "Invalid certificate");
	}
	var c = this.certstore.getCertificate(this.path, cert.getCHR());
	this.certstore.storeCertificate(this.path, cert, (c == null));
}



/**
 * Import a list of certificates into the certificate store
 *
 * @param {CVC[]} certs the list of certificates
 */
CVCCA.prototype.importCertificates = function(certs) {
	var mycerts = [];
	var othercerts = [];

	// Separate my certificates from all others
	for (var i = 0; i < certs.length; i++) {
		var cvc = certs[i];
		var chr = cvc.getCHR();
		if (this.holderId == chr.getHolder()) {
			mycerts.push(cvc);
		} else {
			othercerts.push(cvc);
		}
	}
	
	// Insert all other certificates into certificate store
	var list = this.certstore.insertCertificates(this.crypto, othercerts, true);
	
	// Process my own certificates. Should be one at maximum, matching a request
	for (var i = 0; i < mycerts.length; i++) {
		var cert = mycerts[i];
		var chr = cert.getCHR();
		
		var havecert = this.certstore.getCertificate(this.path, chr);
		if (havecert != null) {
			GPSystem.trace("We already have " + cert.toString() + " - ignored...");
		} else {
			var prk = this.certstore.getPrivateKey(this.path, chr);
			if (prk == null) {
				GPSystem.trace("We do not have a key for " + cert.toString() + " - ignored...");
			} else {
				this.certstore.storeCertificate(this.path, cert, true);
			}
		}
	}
	
	return list;
}



/**
 * Returns a list of relevant certificates.
 *
 * <p>If the CA is the root CA, then all self-signed and link certificates are returned.</p>
 * <p>If the CA is a DVCA, then all certificates of the associated root and the current
 *    DVCA certificate is returned.</p>
 *
 * @param {PublicKeyReference} fromCAR the optional starting point for the list if not a root CA
 */
CVCCA.prototype.getCertificateList = function(fromCAR) {
	var list;
	
	if (this.isRootCA()) {
		list = this.certstore.listCertificates(this.path);
	} else {
		var path = this.path;
		
		while(true) {
			var chr = this.certstore.getCurrentCHR(path);
			if (chr == null) {
				var ofs = path.lastIndexOf("/");
				if (ofs == 0) {
					list = [];
				} else {
					path = path.substr(0, ofs);
					continue;
				}
			} else {
				list = this.certstore.getCertificateChain(path, chr, fromCAR);
			}
			break;
		}
	}
	
	return list;
}



/**
 * Return certificate issued by this CA
 *
 * @param {PublicKeyReference} chr the certificate holder reference
 * @returns the certificate or null if not found
 * @type CVC
 */
CVCCA.prototype.getIssuedCertificate = function(chr) {
	var path = this.path + "/" + chr.getHolder();
	
	var cvc = this.certstore.getCertificate(path, chr);
	if (cvc == null) {
		GPSystem.trace("No certificate found for " + chr);
		return null;
	}
	
	return cvc;
}



/**
 * Return authentic public key with domain parameter for a given CHR subordinate to the CA
 *
 * @param {PublicKeyReference} chr the certificate holder reference
 * @returns the public key or null
 * @type Key
 */
CVCCA.prototype.getAuthenticPublicKey = function(chr) {
	var cvc = this.getIssuedCertificate(chr);
	
	if (this.isRootCA()) {
		var dp = this.certstore.getDomainParameter(cvc.getCAR());
	} else {
		var dvcacvc = this.certstore.getCertificate(this.path, cvc.getCAR());
		if (dvcacvc == null) {
			GPSystem.trace("No certificate found for " + cvc.getCAR());
			return null;
		}
		var dp = this.certstore.getDomainParameter(dvcacvc.getCAR());
	}
	
	return(cvc.getPublicKey(dp));
}



CVCCA.testPath = GPSystem.mapFilename("testca", GPSystem.CWD);

CVCCA.test = function() {
	
	var crypto = new Crypto();
	
	var ss = new CVCertificateStore(CVCCA.testPath + "/cvca");
	var cvca = new CVCCA(crypto, ss, null, null, "/UTCVCA");
	
	// Create a new request
	var req = cvca.generateRequest(null, false);
	print("Request: " + req);
	print(req.getASN1());
	
	assert(req.verifyWith(crypto, req.getPublicKey()));
	
	// Create self-signed or link certificate based on request
	var policy = { certificateValidityDays: 2,
				   chatRoleOID: new ByteString("id-IS", OID),
				   chatRights: new ByteString("E3", HEX),
				   includeDomainParameter: true,
				   extensions: []
				 };
	var cert = cvca.generateCertificate(req, policy);
	print("Certificate: " + cert);
	print(cert.getASN1());

	// Import certificate into store, making it the most current certificate
	cvca.storeCertificate(cert);
	
	// Generate additional self-signed root certificate
	// This must be done after the link certificate has been imported
	var policy = { certificateValidityDays: 2,
				   chatRoleOID: new ByteString("id-IS", OID),
				   chatRights: new ByteString("E3", HEX),
				   includeDomainParameter: true,
				   extensions: []
				 };
	var cert = cvca.generateCertificate(req, policy);
	print("Certificate: " + cert);
	print(cert.getASN1());

	// Import certificate into store, making it the most current certificate
	cvca.storeCertificate(cert);

	var ss = new CVCertificateStore(CVCCA.testPath + "/dvca");
	var dvca = new CVCCA(crypto, ss, null, null, "/UTCVCA/UTDVCA");

	var certlist = cvca.getCertificateList();
	var list = dvca.importCertificates(certlist);

	if (list.length > 0) {
		print("Warning: Could not import the following certificates");
		for (var i = 0; i < list.length; i++) {
			print(list[i]);
		}
	}

	// Create a new request
	var req = dvca.generateRequest(null, false);
	print("Request: " + req);
	print(req.getASN1());
	
	// Sign this request with root CA
	// This must be done after the link certificate has been imported
	var policy = { certificateValidityDays: 2,
				   chatRoleOID: new ByteString("id-IS", OID),
				   chatRights: new ByteString("A3", HEX),
				   includeDomainParameter: false,
				   extensions: []
				 };
	var cert = cvca.generateCertificate(req, policy);
	print("Certificate: " + cert);
	print(cert.getASN1());

	cvca.storeCertificate(cert);
	dvca.importCertificate(cert);


	var ss = new CVCertificateStore(CVCCA.testPath + "/term");
	var term = new CVCCA(crypto, ss, null, null, "/UTCVCA/UTDVCA/UTTERM");

	var certlist = dvca.getCertificateList();
	print("Certificate list: ");
	print(certlist);
	var list = term.importCertificates(certlist);

	if (list.length > 0) {
		print("Warning: Could not import the following certificates");
		for (var i = 0; i < list.length; i++) {
			print(list[i]);
		}
	}

	// Create a new request
	var req = term.generateRequest(null, false);
	print("Request: " + req);
	print(req.getASN1());
	
	// Sign this request with DVCA
	// This must be done after the link certificate has been imported
	var policy = { certificateValidityDays: 2,
				   chatRoleOID: new ByteString("id-IS", OID),
				   chatRights: new ByteString("23", HEX),
				   includeDomainParameter: false,
				   extensions: []
				 };
	var cert = dvca.generateCertificate(req, policy);
	print("Certificate: " + cert);
	print(cert.getASN1());

	dvca.storeCertificate(cert);
	term.importCertificate(cert);
}


// CVCCA.test();
