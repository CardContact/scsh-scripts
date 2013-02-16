/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2009 CardContact Software & System Consulting
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
 * @fileoverview Script to generate a full reference EAC PKI
 */
 
load("../icao/cvcca.js");
load("../icao/pace.js");

 
 
/**
 * Generate a complete CVC PKI setup for testing purposes
 *
 * @param {Crypto} crypto the crypto provider to use
 * @param {CVCertificateStore} certstore place to store keys and certificates
 */ 
function CVCCAGenerator(crypto, certstore) {
	this.crypto = crypto;
	this.certstore = certstore;
	this.keyspec = new Key();
	this.keyspec.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP256r1", OID));
	this.taAlgorithmIdentifier = new ByteString("id-TA-ECDSA-SHA-256", OID);
	this.verbose = false;
}



/**
 * Log message
 *
 * @param {String} msg the message
 */
CVCCAGenerator.prototype.log = function(msg) {
	if (this.verbose) {
		GPSystem.trace(msg);
	}
}



/**
 * Create a CVCA at the given path and with the defined policy.
 *
 * <p>Calling this method a second time will create a link certificate.</p>
 *
 * @param {String} path a path of certificate holder names
 * @param {Object} policy the certificate policy
 */
CVCCAGenerator.prototype.createCVCA = function(path, policy) {
	var cvca = new CVCCA(this.crypto, this.certstore, null, null, path);
	cvca.setKeySpec(this.keyspec, this.taAlgorithmIdentifier);
	
	// Create a new request
	var req = cvca.generateRequest(null, false);
	this.log("Request: " + req);
	this.log(req.getASN1());

	assert(req.verifyWith(this.crypto, req.getPublicKey()));

	var cert = cvca.generateCertificate(req, policy);
	this.log("Certificate: " + cert);
	this.log(cert.getASN1());

	// Import certificate into store, making it the most current certificate
	cvca.importCertificate(cert);
}



/**
 * Create a DVCA at the given path and with the defined policy.
 *
 * @param {String} path a path of certificate holder names
 * @param {Object} policy the certificate policy
 */
CVCCAGenerator.prototype.createDVCA = function(path, policy) {
	var cvca = new CVCCA(this.crypto, this.certstore, null, null, CVCertificateStore.parentPathOf(path));
	cvca.setKeySpec(this.keyspec, this.taAlgorithmIdentifier);

	var dvca = new CVCCA(this.crypto, this.certstore, null, null, path);
	dvca.setKeySpec(this.keyspec, this.taAlgorithmIdentifier);

	// Create a new request
	var req = dvca.generateRequest(null, false);
	this.log("Request: " + req);
	this.log(req.getASN1());

	assert(req.verifyWith(this.crypto, req.getPublicKey()));

	var cert = cvca.generateCertificate(req, policy);
	this.log("Certificate: " + cert);
	this.log(cert.getASN1());

	// Import certificate into store, making it the most current certificate
	dvca.importCertificate(cert);
}



/**
 * Create a terminal at the given path and with the defined policy.
 *
 * @param {String} path a path of certificate holder names
 * @param {Object} policy the certificate policy
 */
CVCCAGenerator.prototype.createTerminal = function(path, policy) {
	var dvca = new CVCCA(this.crypto, this.certstore, null, null, CVCertificateStore.parentPathOf(path));
	dvca.setKeySpec(this.keyspec, this.taAlgorithmIdentifier);

	var term = new CVCCA(this.crypto, this.certstore, null, null, path);
	term.setKeySpec(this.keyspec, this.taAlgorithmIdentifier);

	// Create a new request
	var req = term.generateRequest(null, false);
	this.log("Request: " + req);
	this.log(req.getASN1());

	assert(req.verifyWith(this.crypto, req.getPublicKey()));

	var cert = dvca.generateCertificate(req, policy);
	this.log("Certificate: " + cert);
	this.log(cert.getASN1());

	// Import certificate into store, making it the most current certificate
	term.importCertificate(cert);
}


CVCCAGenerator.CWD = GPSystem.mapFilename("", GPSystem.CWD);


/**
 * Setup EAC PKI
 */
CVCCAGenerator.setup = function() {
	var crypto = new Crypto();
	var ss = new CVCertificateStore(CVCCAGenerator.CWD + "/cvc");
	var g = new CVCCAGenerator(crypto, ss);
//	g.verbose = true;

	// Create CVCAs
	var policy = { certificateValidityDays: 3650,
			chatRoleOID: new ByteString("id-IS", OID),
			   chatRights: new ByteString("C3", HEX),
			   includeDomainParameter: true
			 };
	g.createCVCA("/UTISCVCA", policy);


	var policy = { certificateValidityDays: 3650,
			   chatRoleOID: new ByteString("id-AT", OID),
			   chatRights: new ByteString("FFFFFFFFFF", HEX),
			   includeDomainParameter: true
			 };
	g.createCVCA("/UTATCVCA", policy);


	var policy = { certificateValidityDays: 3650,
			   chatRoleOID: new ByteString("id-ST", OID),
			   chatRights: new ByteString("C3", HEX),
			   includeDomainParameter: true
			 };
	g.createCVCA("/UTSTCVCA", policy);



	// Create DVCAs
	var policy = { certificateValidityDays: 3650,
			   chatRoleOID: new ByteString("id-IS", OID),
			   chatRights: new ByteString("83", HEX),
			   includeDomainParameter: false
			 };
	g.createDVCA("/UTISCVCA/UTISDVCAOD", policy);


	var policy = { certificateValidityDays: 3650,
			   chatRoleOID: new ByteString("id-IS", OID),
			   chatRights: new ByteString("43", HEX),
			   includeDomainParameter: false
			 };
	g.createDVCA("/UTISCVCA/UTISDVCAOF", policy);


	var policy = { certificateValidityDays: 3650,
			   chatRoleOID: new ByteString("id-AT", OID),
			   chatRights: new ByteString("BFFFFFFFFF", HEX),
			   includeDomainParameter: false
			 };
	g.createDVCA("/UTATCVCA/UTATDVCAOD", policy);


	var policy = { certificateValidityDays: 3650,
			   chatRoleOID: new ByteString("id-AT", OID),
			   chatRights: new ByteString("7FFFFFFFFF", HEX),
			   includeDomainParameter: false
			 };
	g.createDVCA("/UTATCVCA/UTATDVCANO", policy);


	var policy = { certificateValidityDays: 3650,
			   chatRoleOID: new ByteString("id-ST", OID),
			   chatRights: new ByteString("83", HEX),
			   includeDomainParameter: false
			 };
	g.createDVCA("/UTSTCVCA/UTSTDVCAAB", policy);


	var policy = { certificateValidityDays: 3650,
			   chatRoleOID: new ByteString("id-ST", OID),
			   chatRights: new ByteString("43", HEX),
			   includeDomainParameter: false
			 };
	g.createDVCA("/UTSTCVCA/UTSTDVCACP", policy);



	// Create terminals
	var policy = { certificateValidityDays: 3650,
			   chatRoleOID: new ByteString("id-IS", OID),
			   chatRights: new ByteString("03", HEX),
			   includeDomainParameter: false
			 };
	g.createTerminal("/UTISCVCA/UTISDVCAOD/UTTERM", policy);


	var policy = { certificateValidityDays: 3650,
			   chatRoleOID: new ByteString("id-IS", OID),
			   chatRights: new ByteString("03", HEX),
			   includeDomainParameter: false
			 };
	g.createTerminal("/UTISCVCA/UTISDVCAOF/UTTERM", policy);


	var policy = { certificateValidityDays: 3650,
			   chatRoleOID: new ByteString("id-AT", OID),
			   chatRights: new ByteString("3FFFFFFFFF", HEX),
			   includeDomainParameter: false
			 };
	g.createTerminal("/UTATCVCA/UTATDVCAOD/UTTERM", policy);


	var sectorPublicKey1 = new Key(CVCCAGenerator.CWD + "/kp_puk_SectorKey1.xml");
	sectorPublicKey1.setComponent(Key.ECC_CURVE_OID, sectorPublicKey1.getComponent(Key.ECC_CURVE_OID));
	var encodedSectorPublicKey1 = PACE.encodePublicKey("id-RI-ECDH-SHA-256", sectorPublicKey1, true).getBytes();
	var encodedSectorPublicKeyHash1 = crypto.digest(Crypto.SHA_256, encodedSectorPublicKey1);

	var sectorPublicKey2 = new Key(CVCCAGenerator.CWD + "/kp_puk_SectorKey2.xml");
	sectorPublicKey2.setComponent(Key.ECC_CURVE_OID, sectorPublicKey2.getComponent(Key.ECC_CURVE_OID));
	var encodedSectorPublicKey2 = PACE.encodePublicKey("id-RI-ECDH-SHA-256", sectorPublicKey2, true).getBytes();
	var encodedSectorPublicKeyHash2 = crypto.digest(Crypto.SHA_256, encodedSectorPublicKey2);

	var sectorId = new ASN1(0x73,
				new ASN1(ASN1.OBJECT_IDENTIFIER, new ByteString("id-sector", OID)),
				new ASN1(0x80, encodedSectorPublicKeyHash1),
				new ASN1(0x81, encodedSectorPublicKeyHash2)
			);

	var policy = { certificateValidityDays: 3650,
			   chatRoleOID: new ByteString("id-AT", OID),
			   chatRights: new ByteString("3FFFFFFFFF", HEX),
			   includeDomainParameter: false,
			   extensions: [ sectorId ]
			 };
	g.createTerminal("/UTATCVCA/UTATDVCANO/UTTERM", policy);


	var policy = { certificateValidityDays: 3650,
			   chatRoleOID: new ByteString("id-ST", OID),
			   chatRights: new ByteString("03", HEX),
			   includeDomainParameter: false
			 };
	g.createTerminal("/UTSTCVCA/UTSTDVCAAB/UTTERM", policy);


	var policy = { certificateValidityDays: 3650,
			   chatRoleOID: new ByteString("id-ST", OID),
			   chatRights: new ByteString("03", HEX),
			   includeDomainParameter: false
			 };
	g.createTerminal("/UTSTCVCA/UTSTDVCACP/UTTERM", policy);
}
