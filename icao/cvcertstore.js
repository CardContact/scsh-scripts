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
 



if (typeof(__ScriptingServer) == "undefined") {
	load("pkcs8.js");
	load("cvc.js");
}


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

	f.close();
	
	// Allocate JavaScript ByteBuffer from native/wrapped byte array
	var bb = new ByteBuffer(bs);
	
	// Convert to JavaScript ByteString
	var data = bb.toByteString();

	return data;
}



/**
 * Saves a binary file to disk
 *
 * @param {String} filename the fully qualified file name
 * @param {ByteString} data the binary content
 */
CVCertificateStore.saveBinaryFile = function(filename, data) {
	// Open stream
	var f = new java.io.FileOutputStream(filename);
	f.write(data);
	f.close();
}



/**
 * Loads a XML file from disk
 *
 * @param {String} filename the fully qualified file name
 * @return the XML content
 * @type XML
 */
CVCertificateStore.loadXMLFile = function(filename) {
	// Open stream
	var f = new java.io.FileReader(filename);
	var bfr = new java.io.BufferedReader(f);

	// Skip processing instructions
	var result;
	do	{
		result = bfr.readLine();
	} while ((result != null) && (result.substr(0, 2) == "<?"));
	
	if (result == null) {
		bfr.close();
		f.close();
		return null;
	}
	
	var line;
	while ((line = bfr.readLine()) != null) {
		result += line + "\n";
	}
	bfr.close();
	f.close();
	
	return new XML(result);
}



/**
 * Saves XML to disk
 *
 * @param {String} filename the fully qualified file name
 * @param {XML} data the XML content
 */
CVCertificateStore.saveXMLFile = function(filename, xml) {
	var fw = new java.io.FileWriter(filename);
	fw.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
	fw.write(xml.toXMLString());
	fw.close();

}



/**
 * Strip the last element of the path, effectively defining the parent within the path
 *
 * @param {String} path the path to strip the last element from
 * @returns the parent path or null for the root
 * @type String
 */
CVCertificateStore.parentPathOf = function(path) {
	var ofs = path.lastIndexOf("/");
	if (ofs <= 0) {
		return null;
	}
	return path.substr(0, ofs);
}



/**
 * Return the n-element of the path
 *
 * @param {String} path the path to return the last element from
 * @returns the last path element or null for the root
 * @type String
 */
CVCertificateStore.nthElementOf = function(path, n) {
	var pe = path.substr(1).split("/");
	if (typeof(n) == "undefined") {
		return pe[pe.length - 1];
	}
	return pe[n];
}



/**
 * Check path for legal encodings
 */
CVCertificateStore.checkPath = function(path) {
	if ((path.indexOf("/..") >= 0) ||
		(path.indexOf("../") >= 0) ||
		(path.indexOf("\\..") >= 0) ||
		(path.indexOf("..\\") >= 0) ||
		(path.indexOf("\0") >= 0) ||
		(path.indexOf("~") >= 0)) {
		throw new GPError("CVCertificateStore", GPError.INVALID_ARGUMENTS, 0, "Path \"" + path + "\" contains illegal characters");
	}
}



/**
 * Map to absolute path on file system
 * @param {String} path the relative path
 * @type String
 * @return the absolute path on the file system
 */
CVCertificateStore.prototype.mapPath = function(path) {
	CVCertificateStore.checkPath(path);
	return this.path + path;
}



/**
 * Returns the current terminal certificate for a given CVCA reference.
 *
 * @param {PublicKeyReference} cvcaref the public key reference (CHR) of the root CA.
 * @return the current terminal CVC
 * @type CVC
 */
CVCertificateStore.prototype.getTerminalCertificateFor = function(cvcaref) {
	var fn = this.mapPath("/" + cvcaref.getHolder() + "/terminal/current.cvcert");
	
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
	var fn = this.mapPath("/" + cvcaref.getHolder() + "/" + dvcaref.getHolder() + "/" + dvcaref.toString() + ".cvcert");
	
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
	var fn = this.mapPath("/" + cvcaref.getHolder() + "/" + cvcaref.toString() + ".cvcert");
	
	var f = new java.io.File(fn);
	if (!f.exists()) {
		fn = this.path + "/" + cvcaref.getHolder() + "/" + cvcaref.toString() + ".selfsigned.cvcert";
	}
	
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
	var fn = this.mapPath("/" + cvcaref.getHolder() + "/terminal/current.pkcs8");
	
	var bin = CVCertificateStore.loadBinaryFile(fn);

	return PKCS8.decodeKeyFromPKCS8Format(bin);
}



/**
 * Store a private key in the certificate store
 *
 * @param {String} path the relative path of the PKI element (e.g. "/UTCVCA1/UTDVCA1/UTTERM")
 * @param {PublicKeyReference} chr the public key reference for this key
 * @param {Key} prk the private key
 */
CVCertificateStore.prototype.storePrivateKey = function(path, chr, prk) {
	var cfg = this.loadConfig(path);
	if (cfg == null) {
		cfg = this.getDefaultConfig(path);
		this.saveConfig(path, cfg);
	}
	
	var p8 = PKCS8.encodeKeyUsingPKCS8Format(prk);
	var fn = this.mapPath(path + "/" + chr.toString() + ".pkcs8");
	GPSystem.trace("Saving private key to " + fn);
	CVCertificateStore.saveBinaryFile(fn, p8);
}



/**
 * Get a private key in the certificate store
 *
 * @param {String} path the relative path of the PKI element (e.g. "/UTCVCA1/UTDVCA1/UTTERM")
 * @param {PublicKeyReference} chr the public key reference for this key
 * @returns the private key or null if not found
 * @type Key
 */
CVCertificateStore.prototype.getPrivateKey = function(path, chr) {
	var fn = this.mapPath(path + "/" + chr.toString() + ".pkcs8");

	try	{
		var bin = CVCertificateStore.loadBinaryFile(fn);
	}
	catch(e) {
//		GPSystem.trace(e);
		return null;
	}

	return PKCS8.decodeKeyFromPKCS8Format(bin);
}



/**
 * Remove private key
 *
 * @param {String} path the relative path of the PKI element (e.g. "/UTCVCA1/UTDVCA1/UTTERM")
 * @param {PublicKeyReference} chr the public key reference for this key
 * @returns true is deleted
 * @type boolean
 */
CVCertificateStore.prototype.deletePrivateKey = function(path, chr) {
	var fn = this.mapPath(path + "/" + chr.toString() + ".pkcs8");
	var f = new java.io.File(fn);
	return f["delete"]();		// delete is a reserved keyword
}



/**
 * Store a certificate request in the certificate store
 *
 * @param {String} path the relative path of the PKI element (e.g. "/UTCVCA1/UTDVCA1/UTTERM")
 * @param {CVC} req the request
 */
CVCertificateStore.prototype.storeRequest = function(path, req) {
	var chr = req.getCHR();
	var fn = this.mapPath(path + "/" + chr.toString() + ".cvreq");
	GPSystem.trace("Saving request to " + fn);
	CVCertificateStore.saveBinaryFile(fn, req.getBytes());
}



/**
 * Return request for given CHR
 *
 * @param {String} path the relative path of the PKI element (e.g. "/UTCVCA1/UTDVCA1/UTTERM")
 * @param {PublicKeyReference} chr the public key reference for the certificate
 * @type CVC
 * @return the request or null
 */
CVCertificateStore.prototype.getRequest = function(path, chr) {
	var fn = this.mapPath(path + "/" + chr.toString() + ".cvreq");
	var bin = null;
	
	try	{
		bin = CVCertificateStore.loadBinaryFile(fn);
	}
	catch (e) {
//		GPSystem.trace(e);
		return null;
	}
	return new CVC(bin);
}



/**
 * Remove request
 *
 * @param {String} path the relative path of the PKI element (e.g. "/UTCVCA1/UTDVCA1/UTTERM")
 * @param {PublicKeyReference} chr the public key reference for this request
 * @returns true is deleted
 * @type boolean
 */
CVCertificateStore.prototype.deleteRequest = function(path, chr) {
	var fn = this.mapPath(path + "/" + chr.toString() + ".cvreq");
	var f = new java.io.File(fn);
	return f["delete"]();		// delete is a reserved keyword
}



/**
 * Store a certificate in the certificate store
 *
 * @param {String} path the relative path of the PKI element (e.g. "/UTCVCA1/UTDVCA1/UTTERM")
 * @param {CVC} cert the certificate
 * @param {Boolean} makeCurrent true if this certificate become the current certificate
 */
CVCertificateStore.prototype.storeCertificate = function(path, cert, makeCurrent) {
	var car = cert.getCAR();
	var chr = cert.getCHR();
	if (car.equals(chr)) {
		var fn = this.mapPath(path + "/" + chr.toString() + ".selfsigned.cvcert");
	} else {
		var fn = this.mapPath(path + "/" + chr.toString() + ".cvcert");
	}

	var f = new java.io.File(fn);
	if (f.exists()) {
		return;
	}
	
	var cfg = this.loadConfig(path);
	if (cfg == null) {
		cfg = this.getDefaultConfig(path);
		this.saveConfig(path, cfg);
	}

	GPSystem.trace("Saving certificate to " + fn);
	CVCertificateStore.saveBinaryFile(fn, cert.getBytes());

	if (makeCurrent) {
		var cfg = this.loadConfig(path);
		cfg.sequence.currentCHR = chr.toString();
		this.saveConfig(path, cfg);
	}
}



/**
 * Remove certificate
 *
 * @param {String} path the relative path of the PKI element (e.g. "/UTCVCA1/UTDVCA1/UTTERM")
 * @param {PublicKeyReference} chr the public key reference for this certificate
 * @param {boolean} selfsigned delete the self-signed root certificate rather than a link certificate
 * @returns true is deleted
 * @type boolean
 */
CVCertificateStore.prototype.deleteCertificate = function(path, chr, selfsigned) {
	if (selfsigned) {
		var fn = this.mapPath(path + "/" + chr.toString() + ".selfsigned.cvcert");
	} else {
		var fn = this.mapPath(path + "/" + chr.toString() + ".cvcert");
	}
	var f = new java.io.File(fn);
	return f["delete"]();		// delete is a reserved keyword
}



/**
 * Return certificate for a given CHR in binary format
 *
 * <p>This method returns a self-signed root certificate if the selfsigned
 *    parameter is set. If not set or set to false, then matching link certificate,
 *    if any, is returned rather than the self-signed certificate.</p>
 *
 * @param {String} path the relative path of the PKI element (e.g. "/UTCVCA1/UTDVCA1/UTTERM")
 * @param {PublicKeyReference} chr the public key reference for the certificate
 * @param {boolean} selfsigned return the self-signed root certificate rather than a link certificate
 * @returns the certificate or null if not found
 * @type ByteString
 */
CVCertificateStore.prototype.getCertificateBinary = function(path, chr, selfsigned) {
	if (selfsigned) {
		var fn = this.mapPath(path + "/" + chr.toString() + ".selfsigned.cvcert");
	} else {
		var fn = this.mapPath(path + "/" + chr.toString() + ".cvcert");

		var f = new java.io.File(fn);
		if (!f.exists()) {
			var fn = this.mapPath(path + "/" + chr.toString() + ".selfsigned.cvcert");
		}
	}
	
	var bin = null;
	try	{
		bin = CVCertificateStore.loadBinaryFile(fn);
	}
	catch (e) {
//		GPSystem.trace(e);
	}
	return bin;
}



/**
 * Return certificate for a given CHR
 *
 * <p>This method returns a self-signed root certificate if the selfsigned
 *    parameter is set. If not set or set to false, then matching link certificate,
 *    if any, is returned rather than the self-signed certificate.</p>
 *
 * @param {String} path the relative path of the PKI element (e.g. "/UTCVCA1/UTDVCA1/UTTERM")
 * @param {PublicKeyReference} chr the public key reference for the certificate
 * @param {boolean} selfsigned return the self-signed root certificate rather than a link certificate
 * @returns the certificate or null if not found
 * @type CVC
 */
CVCertificateStore.prototype.getCertificate = function(path, chr, selfsigned) {
	var bin = this.getCertificateBinary(path, chr, selfsigned);
	
	if (bin == null) {
		return null;
	}
	
	var cvc = null;
	try	{
		cvc = new CVC(bin);
	}
	catch (e) {
		GPSystem.trace(e);
	}
	return cvc;
}



/**
 * Return a chain of certificates resembling a path from root to end entity.
 *
 * @param {String} path the relative path of the PKI element (e.g. "/UTCVCA1/UTDVCA1/UTTERM")
 * @param {PublicKeyReference} tochr the public key reference for the certificate at the end of the chain
 * @param {PublicKeyReference} fromcar the public key reference for the certificate to start with or root if undefined
 * @returns the list of certificates starting with a self signed root certificate (fromcar undefined) a certificate
 *          issued by fromcar up to an including the certificate referenced by tochr. Return null if fromcar is not found.
 * @type CVC[]
 */
CVCertificateStore.prototype.getCertificateChain = function(path, tochr, fromcar) {
	var chain = [];
	var chr = tochr;
	
	while (true) {
		var cvc = this.getCertificate(path, chr, false);
		if (cvc == null) {
			throw new GPError("CVCertificateStore", GPError.INVALID_ARGUMENTS, 0, "Could not locate certificate " + chr);
		}
		chain.push(cvc);
		if (typeof(fromcar) == "undefined") {
			if (cvc.getCAR().equals(cvc.getCHR())) {
				break;
			}
		} else {
			if (cvc.getCAR().equals(fromcar)) {
				break;
			}
			if (cvc.getCAR().equals(cvc.getCHR())) {
				return null;	// fromcar not found along the chain
			}
		}
		var ofs = path.lastIndexOf("/");
		if (ofs > 0) {
			path = path.substr(0, ofs);
		}
		chr = cvc.getCAR();
	}
	
	return chain.reverse();
}



/**
 * List certificates stored for given PKI element
 *
 * @param {String} path the relative path of the PKI element (e.g. "/UTCVCA1/UTDVCA1/UTTERM")
 * @returns a list of certificates, possibly empty
 * @type CVC[]
 */
CVCertificateStore.prototype.listCertificates = function(path) {
	var result = [];

	var fn = this.mapPath(path);
	var f = new java.io.File(fn);
	if (!f.exists()) {
		return result;
	}
	var files = f.list();
	
	for (var i = 0; i < files.length; i++) {
		var s = new String(files[i]);
		var n = s.match(/\.(cvcert|CVCERT)$/);
		if (n) {
			var bin = CVCertificateStore.loadBinaryFile(fn + "/" + s);
			var cvc = new CVC(bin);
			result.push(cvc);
		}
	}
	return result;
}



/**
 * List certificate holders for a given PKI element
 *
 * @param {String} path the relative path of the PKI element (e.g. "/UTCVCA1/UTDVCA1")
 * @returns a list of holder ids, possibly empty
 * @type String[]
 */
CVCertificateStore.prototype.listHolders = function(path) {
	var result = [];

	var fn = this.mapPath(path);
	var f = new java.io.File(fn);
	if (!f.exists()) {
		return result;
	}
	var files = f.list();
	
	for (var i = 0; i < files.length; i++) {
		var s = new String(files[i]);
		var fd = new java.io.File(f, s);
		if (fd.isDirectory()) {
			result.push(s);
		}
	}
	return result;
}



/**
 * Returns the domain parameter for a certificate identified by its CHR
 *
 * <p>This method traverses the certificate hierachie upwards and follows link certificates
 *    until domain parameter are found.</p>
 * 
 * @param {String} path the relative path of the PKI element (e.g. "/UTCVCA1/UTDVCA1")
 * @param {PublicKeyReference} chr the CHR of the certificate to start the search with
 * @return the domain parameter
 * @type Key
 */
CVCertificateStore.prototype.getDomainParameter = function(path, chr) {
	if (typeof(chr) == "undefined") {	// ToDo remove after migration
		chr = path;
		var path = "/" + chr.getHolder();
	}
	
	do	{
		var ofs = path.lastIndexOf("/");
		if (ofs > 0) {
			var cvc = this.getCertificate(path, chr);
			if (cvc == null) {
				throw new GPError("CVCertificateStore", GPError.INVALID_ARGUMENTS, 0, "Could not locate certificate " + chr);
			}
			chr = cvc.getCAR();
			path = path.substr(0, ofs);
		}
	} while (ofs > 0);
	
	do {
		var cvc = this.getCertificate(path, chr);
		
		if (cvc == null) {
			throw new GPError("CVCertificateStore", GPError.INVALID_ARGUMENTS, 0, "Could not locate certificate " + chr + " in " + path);
		}
		
		var p = cvc.getPublicKey();
		if (typeof(p.getComponent(Key.ECC_P)) != "undefined") {
			return p;
		}
		chr = cvc.getCAR();
	} while (!chr.equals(cvc.getCHR()));

	throw new GPError("CVCertificateStore", GPError.INVALID_ARGUMENTS, 0, "Could not locate current CVCA certificate");
}



/**
 * Returns the default domain parameter for a given PKI
 * 
 * @param {String} path the PKI path (e.g. "/UTCVCA1/UTDVCA1/UTTERM"). Only the first path element is relevant
 * @return the domain parameter
 * @type Key
 */
CVCertificateStore.prototype.getDefaultDomainParameter = function(path) {
	var pe = path.substr(1).split("/");
	chr = this.getCurrentCHR("/" + pe[0]);
	if (chr == null) {
		throw new GPError("CVCertificateStore", GPError.INVALID_ARGUMENTS, 0, "Could not locate current CVCA certificate");
	}
	return this.getDomainParameter(chr);
}



/**
 * Returns the default algorithm identifier OID from the most recent link certificate
 * 
 * @param {String} path the PKI path (e.g. "/UTCVCA1/UTDVCA1/UTTERM"). Only the first path element is relevant
 * @return the algorithm identifier
 * @type ByteString
 */
CVCertificateStore.prototype.getDefaultPublicKeyOID = function(path) {
	var pe = path.substr(1).split("/");
	chr = this.getCurrentCHR("/" + pe[0]);
	if (chr == null) {
		throw new GPError("CVCertificateStore", GPError.INVALID_ARGUMENTS, 0, "Could not locate current CVCA certificate");
	}
	var cvc = this.getCertificate("/" + pe[0], chr);
	if (cvc == null) {
		throw new GPError("CVCertificateStore", GPError.INVALID_ARGUMENTS, 0, "Could not locate current CVCA certificate");
	}
	
	return cvc.getPublicKeyOID();
}



/**
 * Return the current CHR for which a valid certificate exists
 *
 * @param {String} path the relative path of the PKI element (e.g. "/UTCVCA1/UTDVCA1")
 * @returns the current CHR for which a certificate exists or null if none exists
 * @type PublicKeyReference
 */
CVCertificateStore.prototype.getCurrentCHR = function(path) {
	var cfg = this.loadConfig(path);
	if (cfg == null) {
		return null;
	}

	if (cfg.sequence.currentCHR.toString()) {
		return new PublicKeyReference(cfg.sequence.currentCHR.toString());
	}
	
	return null;
}



/**
 * Return the next CHR
 *
 * @param {String} path the relative path of the PKI element (e.g. "/UTCVCA1/UTDVCA1")
 * @returns the next CHR based on the sequence counter maintained in the configuration file
 * @type PublicKeyReference
 */
CVCertificateStore.prototype.getNextCHR = function(path) {
	var cfg = this.loadConfig(path);
	if (cfg == null) {
		cfg = this.getDefaultConfig();
	}
	var seq = parseInt(cfg.sequence.current);
	seq += 1;
	cfg.sequence.current = seq;
	this.saveConfig(path, cfg);

	return this.getCHRForSequenceNumber(path, seq);
}



/**
 * Create a CHR for the given path and sequence number
 *
 * @param {String} path the relative path of the PKI element (e.g. "/UTCVCA1/UTDVCA1")
 * @return the CHR
 * @type PublicKeyReference
 */
CVCertificateStore.prototype.getCHRForSequenceNumber = function(path, sequence) {
	var pe = path.substr(1).split("/");
	var l = pe[pe.length - 1];

	var str = "" + sequence;
	str = "0000".substr(4 - (5 - str.length)).concat(str);
	return new PublicKeyReference(l + str);

}



/**
 * Insert certificates into certificate store
 *
 * <p>The import into the internal data structure is done in three steps:</p>
 * <ol>
 *  <li>If allowed, all self-signed certificates are imported</li>
 *  <li>All certificates issued by root CAs are imported</li>
 *  <li>All other certificates issued by subordinate CAs are imported</li>
 * </ol>
 * <p>Certificates at the terminal level can only be imported, if the issuing
 *    DVCA certificate is contained in the list. Even if a DVCA certificate
 *    is already stored, the import of such a certificate will be skipped if the
 *    DVCA certificate is not part of the imported list.</p>
 * <p>Before a certificate is imported, the signature is verified.</p>
 *
 * @param {Crypto} crypto the crypto provider to be used for certificate verification
 * @param {CVC[]} certlist the unordered list of certificates
 * @param {Boolean} insertSelfSigned true, if the import of root certificates is allowed
 * @returns the (ideally empty) list of unprocessed certificates. This does not contains certificates
 *          that fail signature verification.
 * @type CVC[]
 */
CVCertificateStore.prototype.insertCertificates = function(crypto, certlist, insertSelfSigned) {

	var chrmap = [];
	
	var unprocessed = [];
	for (var i = 0; i < certlist.length; i++) {
		var cvc = certlist[i];
		var chr = cvc.getCHR().toString();
		
		if (chr == cvc.getCAR().toString()) { // Self signed
			var result = cvc.verifyWith(crypto, cvc.getPublicKey(), cvc.getPublicKeyOID());

			if (result) {
				var path = "/" + cvc.getCHR().getHolder();
				if (insertSelfSigned) {		// Store self-signed certificates
					this.storeCertificate(path, cvc, true);
				}
			} else {
				GPSystem.trace("Self-signed certificate failed signature verification. " + cvc);
			}
		} else {
			unprocessed.push(cvc);
			chrmap[chr] = cvc;
		}
	}
	certlist = unprocessed;
	
	var unprocessed = [];		// Collect unprocessed certificates
	var capath = [];			// Map of CA names to CA paths
	for (var i = 0; i < certlist.length; i++) {	// Process all certificates issued by root
		var cvc = certlist[i];
		var car = cvc.getCAR();
		var cacert = this.getCertificate("/" + car.getHolder(), car);
		if (cacert != null) {	// Issued by a root CA
			var dp = this.getDomainParameter("/" + car.getHolder(), car);
			var result = cvc.verifyWith(crypto, cacert.getPublicKey(dp), cacert.getPublicKeyOID());
			if (result) {
				var chr = cvc.getCHR();
				var holder = chr.getHolder();
				
				if (holder == car.getHolder()) {	// Link certificate
					this.storeCertificate("/" + holder, cvc, true);
				} else {							// Subordinate certificate
					var path = "/" + car.getHolder() + "/" + holder;
					this.storeCertificate(path, cvc, true);
					capath[holder] = path;			// Store in list of processed DVCA
				}
			} else {
				GPSystem.trace("Certificate " + cvc + " failed signature verification with " + cacert);
			}
		} else {
			unprocessed.push(cvc);
		}
	}
	certlist = unprocessed;
	
	var unprocessed = [];		// Collect unprocessed certificates
	for (var i = 0; i < certlist.length; i++) {		// Process remaining certificates
		var cvc = certlist[i];
		var car = cvc.getCAR();
		
		var path = capath[car.getHolder()];			// Try to locate DVCA processed in previous step
		if (path) {
			var cacert = this.getCertificate(path, car);
			var cacertcar = cacert.getCAR();
			if (cacert != null) {
				// Determine root certificate to obtain domain parameter
				var dp = this.getDomainParameter(path, cacertcar);
				var result = cvc.verifyWith(crypto, cacert.getPublicKey(dp), cacert.getPublicKeyOID());
				if (result) {
					var chr = cvc.getCHR();
					var holder = chr.getHolder();
					
					this.storeCertificate(path + "/" + holder, cvc, true);
				} else {
					GPSystem.trace("Certificate " + cvc + " failed signature verification with " + cacvc);
				}
			} else {
				GPSystem.trace("Could not find certificate " + car.toString());
				unprocessed.push(cvc);
			}
		} else {
			GPSystem.trace("Could not locate CA " + car.toString());
			unprocessed.push(cvc);
		}
	}
	return unprocessed;
}



/**
 * Insert a single certificates into the certificate store
 *
 * <p>Before a certificate is imported, the signature is verified.</p>
 * <p>If the certificate is a terminal certificate, then the first element of the path given
 *    in cvcahint is used to determine the correct CVCA.</p>
 *
 * @param {Crypto} crypto the crypto provider to be used for certificate verification
 * @param {CVC} cvc the certificate
 * @param {String} cvcahint the PKI path (e.g. "/UTCVCA1/UTDVCA1/UTTERM"). Only the first path element is relevant
 * @returns true, if the certificate was inserted
 * @type boolean
 */
CVCertificateStore.prototype.insertCertificate = function(crypto, cvc, cvcahint) {

	var car = cvc.getCAR();
	var path = "/" + car.getHolder();
	var cacert = this.getCertificate(path, car);
	if (cacert == null) {
		var path = "/" + CVCertificateStore.nthElementOf(cvcahint, 0) + "/" + car.getHolder();
//		print("Using hint " + path);
		var cacert = this.getCertificate(path, car);
		if (cacert == null) {
			return false;
		}
	}
	
	var dp = this.getDomainParameter(path, car);
	var result = cvc.verifyWith(crypto, cacert.getPublicKey(dp), cacert.getPublicKeyOID());
	if (!result) {
		GPSystem.trace("Certificate " + cvc + " failed signature verification with " + cacert);
		return false;
	}

	var chr = cvc.getCHR();
	var holder = chr.getHolder();

	if (holder == car.getHolder()) {	// Link certificate
		this.storeCertificate("/" + holder, cvc, true);
	} else {							// Subordinate certificate
		this.storeCertificate(path + "/" + holder, cvc, true);
	}

	return true;
}



/**
 * Insert certificates into certificate store
 *
 * <p>The import into the internal data structure is done in three steps:</p>
 * <ol>
 *  <li>If allowed, all self-signed certificates are imported</li>
 *  <li>All possible certificate chains are build</li>
 *  <li>Certificate chains are processed starting with the topmost certificate in the hierachie</li>
 * </ol>
 * <p>Certificates at the terminal level can only be imported, if the issuing
 *    DVCA certificate is contained in the list or a hint for the relevant CVCA is
 *    given in the first element of the path contained in parameter cvcahint.</p>
 * <p>Before a certificate is imported, the signature is verified.</p>
 *
 * @param {Crypto} crypto the crypto provider to be used for certificate verification
 * @param {CVC[]} certlist the unordered list of certificates
 * @param {Boolean} insertSelfSigned true, if the import of root certificates is allowed
 * @param {String} cvcahint the PKI path (e.g. "/UTCVCA1/UTDVCA1/UTTERM"). Only the first path element is relevant
 * @returns the (ideally empty) list of unprocessed certificates. This does not contains certificates
 *          that fail signature verification.
 * @type CVC[]
 */
CVCertificateStore.prototype.insertCertificates2 = function(crypto, certlist, insertSelfSigned, cvcahint) {

	var chrmap = [];
	
	// Iterate certificate list and store self-signed certificates, if allowed
	// Generate a map of certificate holder references
	var unprocessed = [];
	for (var i = 0; i < certlist.length; i++) {
		var cvc = certlist[i];
		var chr = cvc.getCHR().toString();
		
		if (chr == cvc.getCAR().toString()) { // Self signed
			var result = cvc.verifyWith(crypto, cvc.getPublicKey(), cvc.getPublicKeyOID());

			if (result) {
				var path = "/" + cvc.getCHR().getHolder();
				if (insertSelfSigned) {		// Store self-signed certificates
					this.storeCertificate(path, cvc, true);
				}
			} else {
				GPSystem.trace("Self-signed certificate failed signature verification. " + cvc);
			}
		} else {
			var state = { cvc: cvc, end: true, stored: false };
			unprocessed.push(state);
			if (typeof(chrmap[chr]) == "undefined") {
				chrmap[chr] = state;
			} else {
				// Duplicate CHRs for terminals are allowed
				chrmap[cvc.getCAR().toString() + "/" + chr] = state;
			}
		}
	}
	
	// Mark certificates that are surely CAs, because an issued certificate is contained in the list
	certlist = unprocessed;
	for (var i = 0; i < certlist.length; i++) {
		var cvc = certlist[i].cvc;
		var state = chrmap[cvc.getCAR().toString()];
		if (typeof(state) != "undefined") {
//			print("Mark as CA: " + state.cvc);
			state.end = false;
		}
	}
	
	var unprocessed = [];
	for (var i = 0; i < certlist.length; i++) {
		var state = certlist[i];
		if (state.end) {		// Find all certificates which are at the end of the chain
			var list = [];
			var lastpathelement = state.cvc.getCHR().getHolder();
			var path = "/" + lastpathelement;
			var singlecert = true;
			while(true)	{		// Build a certificate chain and the path for the last certificate
				var pathelement = state.cvc.getCAR().getHolder();
				if (pathelement != lastpathelement) {		// CVCA Link Certificates don't add to the path
					path = "/" + pathelement + path;
				}
				lastpathelement = pathelement;

				if (!state.stored) {			// If not already stored, add to the list
					list.push(state);
					state.stored = true;
				}
				state = chrmap[state.cvc.getCAR().toString()];
				if (typeof(state) == "undefined") {
					break;
				}
				singlecert = false;
			}
			if (singlecert && cvcahint) {
//				print("Single certificate might be a terminal certificate, using cvca hint");
				path = cvcahint;
			} else {
//				print(path);
			}
			for (var j = list.length - 1; j >= 0; j--) {	// Process chain in reverse order
				var cvc = list[j].cvc;
				if (!this.insertCertificate(crypto, cvc, path)) {
					unprocessed.push(cvc);
				}
			}
		}
	}

	return unprocessed;
}



/**
 * Load configuration
 *
 * @param {String} path the relative path of the PKI element (e.g. "UTCVCA1/UTDVCA1")
 * @return the configuration object or null if none defined
 * @type XML
 */
CVCertificateStore.prototype.loadConfig = function(path) {
	var fn = this.mapPath(path + "/config.xml");
	var cfgxml = null;
	
	try	{
		var cfgxml = CVCertificateStore.loadXMLFile(fn);
	}
	catch(e) {
//		GPSystem.trace(e);
	}
	return cfgxml;
}



/**
 * Save configuration
 *
 * <p>This method will create the necessary path and save the configuration to config.xml</p>
 
 * @param {String} path the relative path of the PKI element (e.g. "UTCVCA1/UTDVCA1")
 * @param {XML} cfg the configuration object
 */
CVCertificateStore.prototype.saveConfig = function(path, cfg) {

	if (arguments.length != 2) {
		throw new GPError("CVCertificateStore", GPError.INVALID_ARGUMENTS, 0, "path and cfg argument required");
	}
	
	var fn = this.mapPath(path);
	var f = new java.io.File(fn);
	if (!f.exists()) {
		f.mkdirs();
	}
	
	var fn = this.mapPath(path + "/config.xml");
	CVCertificateStore.saveXMLFile(fn, cfg);
}



/**
 * Create a default configuration
 *
 * @returns a suitable default configuration object
 * @type XML
 */
CVCertificateStore.prototype.getDefaultConfig = function() {
	var defaultCfg = 
		<CAConfig>
			<sequence>
				<current>0</current>
			</sequence>
		</CAConfig>;
	return defaultCfg;
}
