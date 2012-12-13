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
 
load("../icao/cvca/cvcca.js");

 
 
function CVCCAGenerator(crypto, certstore) {
	this.crypto = crypto;
	this.certstore = certstore;
	this.keyspec = new Key();
	this.keyspec.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP256r1", OID));
	this.taAlgorithmIdentifier = new ByteString("id-TA-ECDSA-SHA-256", OID);
}



CVCCAGenerator.prototype.createCVCA = function(path, policy) {
	var cvca = new CVCCA(this.crypto, this.certstore, null, null, path);
	cvca.setKeySpec(this.keyspec, this.taAlgorithmIdentifier);
	
	// Create a new request
	var req = cvca.generateRequest(null, false);
	print("Request: " + req);
	print(req.getASN1());

	assert(req.verifyWith(this.crypto, req.getPublicKey()));

	var cert = cvca.generateCertificate(req, policy);
	print("Certificate: " + cert);
	print(cert.getASN1());

	// Import certificate into store, making it the most current certificate
	cvca.importCertificate(cert);
}



CVCCAGenerator.prototype.createDVCA = function(path, policy) {
	var cvca = new CVCCA(this.crypto, this.certstore, null, null, CVCertificateStore.parentPathOf(path));
	cvca.setKeySpec(this.keyspec, this.taAlgorithmIdentifier);

	var dvca = new CVCCA(this.crypto, this.certstore, null, null, path);
	dvca.setKeySpec(this.keyspec, this.taAlgorithmIdentifier);

	// Create a new request
	var req = dvca.generateRequest(null, false);
	print("Request: " + req);
	print(req.getASN1());

	assert(req.verifyWith(this.crypto, req.getPublicKey()));

	var cert = cvca.generateCertificate(req, policy);
	print("Certificate: " + cert);
	print(cert.getASN1());

	// Import certificate into store, making it the most current certificate
	dvca.importCertificate(cert);
}



CVCCAGenerator.prototype.createTerminal = function(path, policy) {
	var dvca = new CVCCA(this.crypto, this.certstore, null, null, CVCertificateStore.parentPathOf(path));
	dvca.setKeySpec(this.keyspec, this.taAlgorithmIdentifier);

	var term = new CVCCA(this.crypto, this.certstore, null, null, path);
	term.setKeySpec(this.keyspec, this.taAlgorithmIdentifier);

	// Create a new request
	var req = term.generateRequest(null, false);
	print("Request: " + req);
	print(req.getASN1());

	assert(req.verifyWith(this.crypto, req.getPublicKey()));

	var cert = dvca.generateCertificate(req, policy);
	print("Certificate: " + cert);
	print(cert.getASN1());

	// Import certificate into store, making it the most current certificate
	term.importCertificate(cert);
}



var crypto = new Crypto();
var ss = new CVCertificateStore(GPSystem.mapFilename("cvc", GPSystem.CWD));
var g = new CVCCAGenerator(crypto, ss);

// Create CVCAs
var policy = { certificateValidityDays: 365,
			   chatRoleOID: new ByteString("id-IS", OID),
			   chatRights: new ByteString("C3", HEX),
			   includeDomainParameter: true,
			   extensions: []
			 };
g.createCVCA("/UTISCVCA", policy);


var policy = { certificateValidityDays: 365,
			   chatRoleOID: new ByteString("id-AT", OID),
			   chatRights: new ByteString("FFFFFFFFFF", HEX),
			   includeDomainParameter: true,
			   extensions: []
			 };
g.createCVCA("/UTATCVCA", policy);


var policy = { certificateValidityDays: 365,
			   chatRoleOID: new ByteString("id-ST", OID),
			   chatRights: new ByteString("C3", HEX),
			   includeDomainParameter: true,
			   extensions: []
			 };
g.createCVCA("/UTSTCVCA", policy);



// Create DVCAs
var policy = { certificateValidityDays: 365,
			   chatRoleOID: new ByteString("id-IS", OID),
			   chatRights: new ByteString("83", HEX),
			   includeDomainParameter: false,
			   extensions: []
			 };
g.createDVCA("/UTISCVCA/UTISDVCAOD", policy);


var policy = { certificateValidityDays: 365,
			   chatRoleOID: new ByteString("id-IS", OID),
			   chatRights: new ByteString("43", HEX),
			   includeDomainParameter: false,
			   extensions: []
			 };
g.createDVCA("/UTISCVCA/UTISDVCAOF", policy);


var policy = { certificateValidityDays: 365,
			   chatRoleOID: new ByteString("id-AT", OID),
			   chatRights: new ByteString("BFFFFFFFFF", HEX),
			   includeDomainParameter: false,
			   extensions: []
			 };
g.createDVCA("/UTATCVCA/UTATDVCAOD", policy);


var policy = { certificateValidityDays: 365,
			   chatRoleOID: new ByteString("id-AT", OID),
			   chatRights: new ByteString("7FFFFFFFFF", HEX),
			   includeDomainParameter: false,
			   extensions: []
			 };
g.createDVCA("/UTATCVCA/UTATDVCANO", policy);


var policy = { certificateValidityDays: 365,
			   chatRoleOID: new ByteString("id-ST", OID),
			   chatRights: new ByteString("83", HEX),
			   includeDomainParameter: true,
			   extensions: []
			 };
g.createDVCA("/UTSTCVCA/UTSTDVCAAB", policy);


var policy = { certificateValidityDays: 365,
			   chatRoleOID: new ByteString("id-ST", OID),
			   chatRights: new ByteString("43", HEX),
			   includeDomainParameter: true,
			   extensions: []
			 };
g.createDVCA("/UTSTCVCA/UTSTDVCACP", policy);



// Create terminals
var policy = { certificateValidityDays: 365,
			   chatRoleOID: new ByteString("id-IS", OID),
			   chatRights: new ByteString("03", HEX),
			   includeDomainParameter: false,
			   extensions: []
			 };
g.createTerminal("/UTISCVCA/UTISDVCAOD/UTTERM", policy);


var policy = { certificateValidityDays: 365,
			   chatRoleOID: new ByteString("id-IS", OID),
			   chatRights: new ByteString("03", HEX),
			   includeDomainParameter: false,
			   extensions: []
			 };
g.createTerminal("/UTISCVCA/UTISDVCAOF/UTTERM", policy);


var policy = { certificateValidityDays: 365,
			   chatRoleOID: new ByteString("id-AT", OID),
			   chatRights: new ByteString("3FFFFFFFFF", HEX),
			   includeDomainParameter: false,
			   extensions: []
			 };
g.createTerminal("/UTATCVCA/UTATDVCAOD/UTTERM", policy);


var policy = { certificateValidityDays: 365,
			   chatRoleOID: new ByteString("id-AT", OID),
			   chatRights: new ByteString("3FFFFFFFFF", HEX),
			   includeDomainParameter: false,
			   extensions: []
			 };
g.createTerminal("/UTATCVCA/UTATDVCANO/UTTERM", policy);


var policy = { certificateValidityDays: 365,
			   chatRoleOID: new ByteString("id-ST", OID),
			   chatRights: new ByteString("03", HEX),
			   includeDomainParameter: true,
			   extensions: []
			 };
g.createTerminal("/UTSTCVCA/UTSTDVCAAB/UTTERM", policy);


var policy = { certificateValidityDays: 365,
			   chatRoleOID: new ByteString("id-ST", OID),
			   chatRights: new ByteString("03", HEX),
			   includeDomainParameter: true,
			   extensions: []
			 };
g.createTerminal("/UTSTCVCA/UTSTDVCACP/UTTERM", policy);
