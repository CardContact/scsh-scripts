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
 * @fileoverview Support for a card verifiable certificates store according to EAC 1.1/2.0
 */
 



load("pkcs8.js");
load("cvc.js");



/**
 * Create an object to access a certificate store.
 *
 * @class Class that abstracts a certificate and key store for a EAC PKI.
 *
 * @constructor
 * @param {String} path the root of the certificate store
 */
function CVCertificateStore(path) {
	this.path = path;
}



/**
 * Loads a binary file from disk
 *
 * @param {String} filename the fully qualified file name
 * @return the binary content
 * @type ByteString
 */
CVCertificateStore.loadBinaryFile = function(filename) {
	// Open stream
	var f = new java.io.FileInputStream(filename);
	
	// Determine file size
	var flen = f.available();

	// Allocate native byte array
	var bs = java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, flen);
	
	// Read into byte array
	var len = f.read(bs);

	// Allocate JavaScript ByteBuffer from native/wrapped byte array
	var bb = new ByteBuffer(bs);
	
	// Convert to JavaScript ByteString
	var data = bb.toByteString();

	return data;
}



/**
 * Returns the current terminal certificate for a given CVCA reference.
 *
 * @param {PublicKeyReference} cvcaref the public key reference (CHR) of the root CA.
 * @return the current terminal CVC
 * @type CVC
 */
CVCertificateStore.prototype.getTerminalCertificateFor = function(cvcaref) {
	var fn = this.path + "/" + cvcaref.getHolder() + "/terminal/current.cvcert";
	
	var bin = CVCertificateStore.loadBinaryFile(fn);
	
	var cvc = new CVC(bin);
	
	return cvc;
}



/**
 * Returns the document verifier certificate for a given CVCA and DV reference.
 *
 * @param {PublicKeyReference} cvcaref the public key reference (CHR) of the CVCA.
 * @param {PublicKeyReference} dvcaref the public key reference (CHR) of the DV.
 * @return the document verifier CVC
 * @type CVC
 */
CVCertificateStore.prototype.getDVCACertificateFor = function(cvcaref, dvcaref) {
	var fn = this.path + "/" + cvcaref.getHolder() + "/" + dvcaref.getHolder() + "/" + dvcaref.toString() + ".cvcert";
	
	var bin = CVCertificateStore.loadBinaryFile(fn);
	
	var cvc = new CVC(bin);
	
	return cvc;
}



/**
 * Returns the country verifying certification authority's certificate for a given CVCA reference.
 *
 * @param {PublicKeyReference} cvcaref the public key reference (CHR) of the CVCA.
 * @param {PublicKeyReference} dvcaref the public key reference (CHR) of the DV.
 * @return the country verifying certification authority's certificate
 * @type CVC
 */
CVCertificateStore.prototype.getCVCACertificateFor = function(cvcaref) {
	var fn = this.path + "/" + cvcaref.getHolder() + "/" + cvcaref.toString() + ".cvcert";
	
	var bin = CVCertificateStore.loadBinaryFile(fn);
	
	var cvc = new CVC(bin);
	
	return cvc;
}



/**
 * Returns a certificate chain for the current terminal certificate up to, but not including the 
 * the CVCA certificated referenced.
 *
 * @param {PublicKeyReference} cvcaref the public key reference (CHR) of the CVCA.
 * @return the list of certificates starting with optional CVCA link certificates, the DV certificate and
 *         the terminal certificate
 * @type CVC[]
 */
CVCertificateStore.prototype.getCertificateChainFor = function(cvcaref) {
	var chain = new Array();
	
	var termcert = this.getTerminalCertificateFor(cvcaref);
	chain.push(termcert);
	
	var dvcaref = termcert.getCAR();
	
	var dvcacert = this.getDVCACertificateFor(cvcaref, dvcaref);
	chain.push(dvcacert);
	
	var ref = dvcacert.getCAR();
	
	while (ref.toString() != cvcaref.toString()) {
		var cvcacert = this.getCVCACertificateFor(cvcaref);
		chain.push(cvcacert);
		
		var ref = cvcacert.getCAR();
	}

	return(chain.reverse());
}



/**
 * Return the current terminal key for a PKI identified by the CVCA reference
 *
 * @param {PublicKeyReference} cvcaref the public key reference (CHR) of the CVCA.
 * @return the private key
 * @type Key
 */
CVCertificateStore.prototype.getTerminalKeyFor = function(cvcaref) {
	var fn = this.path + "/" + cvcaref.getHolder() + "/terminal/current.pkcs8";
	
	var bin = CVCertificateStore.loadBinaryFile(fn);

	return PKCS8.decodeKeyFromPKCS8Format(bin);
}



CVCertificateStore.testPath = GPSystem.mapFilename("cvc", GPSystem.CWD);


/**
 * Simple self-test
 */
CVCertificateStore.test = function() {
	var ss = new CVCertificateStore(CVCertificateStore.testPath);
	
	var pkr = new PublicKeyReference("TPCVCAAT00001");
	
	var cvc = ss.getTerminalCertificateFor(pkr);
	
	print(cvc);
	
	print(cvc.getCAR());
	
	var cvcchain = ss.getCertificateChainFor(pkr);
	
	for (var i = cvcchain.length - 1; i >= 0; i--) {
		print(cvcchain[i]);
	}
}
