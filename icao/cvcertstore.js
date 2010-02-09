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



/**
 * Store a private key in the certificate store
 *
 * @param {String} path the relative path of the PKI element (e.g. "UTCVCA1/UTDVCA1")
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
	var fn = this.path + "/" + path + "/" + chr.toString() + ".pkcs8";
	GPSystem.trace("Saving private key to " + fn);
	CVCertificateStore.saveBinaryFile(fn, p8);
}



/**
 * Get a private key in the certificate store
 *
 * @param {String} path the relative path of the PKI element (e.g. "UTCVCA1/UTDVCA1")
 * @param {PublicKeyReference} chr the public key reference for this key
 * @returns the private key or null if not found
 * @type Key
 */
CVCertificateStore.prototype.getPrivateKey = function(path, chr) {
	var fn = this.path + "/" + path + "/" + chr.toString() + ".pkcs8";

	try	{
		var bin = CVCertificateStore.loadBinaryFile(fn);
	}
	catch(e) {
		GPSystem.trace(e);
		return null;
	}

	return PKCS8.decodeKeyFromPKCS8Format(bin);
}



/**
 * Store a certificate request in the certificate store
 *
 * @param {String} path the relative path of the PKI element (e.g. "UTCVCA1/UTDVCA1")
 * @param {CVC} req the request
 */
CVCertificateStore.prototype.storeRequest = function(path, req) {
	var chr = req.getCHR();
	var fn = this.path + "/" + path + "/" + chr.toString() + ".cvreq";
	GPSystem.trace("Saving request to " + fn);
	CVCertificateStore.saveBinaryFile(fn, req.getBytes());
}



/**
 * Store a certificate in the certificate store
 *
 * @param {String} path the relative path of the PKI element (e.g. "UTCVCA1/UTDVCA1")
 * @param {CVC} cert the certificate
 * @param {Boolean} makeCurrent true if this certificate become the current certificate
 */
CVCertificateStore.prototype.storeCertificate = function(path, cert, makeCurrent) {
	var chr = cert.getCHR();
	var fn = this.path + "/" + path + "/" + chr.toString() + ".cvcert";
	GPSystem.trace("Saving certificate to " + fn);
	CVCertificateStore.saveBinaryFile(fn, cert.getBytes());

	if (makeCurrent) {
		var cfg = this.loadConfig(path);
		var seq = parseInt(cfg.sequence.current);
		cfg.sequence.current = seq + 1;
		cfg.sequence.currentCHR = chr.toString();
		this.saveConfig(path, cfg);
	}
}



/**
 * Return the current CHR for which a valid certificate exists
 *
 * @param {String} path the relative path of the PKI element (e.g. "UTCVCA1/UTDVCA1")
 * @returns the current CHR for which a certificate exists or null if none exists
 * @type PublicKeyReference
 */
CVCertificateStore.prototype.getCurrentCHR = function(path) {
	var cfg = this.loadConfig(path);
	if (cfg == null) {
		return null;
	}
	
	if (cfg.sequence.currentCHR) {
		print("Current CHR: " + cfg.sequence.currentCHR);
		return new PublicKeyReference(cfg.sequence.currentCHR);
	}
	
	var seq = parseInt(cfg.sequence.current);
	if (seq == 0) {
		return null;
	}
	
	return this.getCHRForSequenceNumber(path, seq);
}



/**
 * Return the next CHR
 *
 * @param {String} path the relative path of the PKI element (e.g. "UTCVCA1/UTDVCA1")
 * @returns the next CHR following the CHR for which a certificate exists or null if none exists
 * @type PublicKeyReference
 */
CVCertificateStore.prototype.getNextCHR = function(path) {
	var cfg = this.loadConfig(path);
	if (cfg == null) {
		return this.getCHRForSequenceNumber(path, 1);
	}
	var seq = parseInt(cfg.sequence.current);
	return this.getCHRForSequenceNumber(path, seq + 1);
}



/**
 * Create a CHR for the given path and sequence number
 *
 * @param {String} path the relative path of the PKI element (e.g. "UTCVCA1/UTDVCA1")
 * @return the CHR
 * @type PublicKeyReference
 */
CVCertificateStore.prototype.getCHRForSequenceNumber = function(path, sequence) {
	var pe = path.split("/");
	var l = pe[pe.length - 1];

	var str = "" + sequence;
	str = "0000".substr(4 - (5 - str.length)).concat(str);
	return new PublicKeyReference(l + str);

}



/**
 * Load configuration
 *
 * @param {String} path the relative path of the PKI element (e.g. "UTCVCA1/UTDVCA1")
 * @return the configuration object or null if none defined
 * @type XML
 */
CVCertificateStore.prototype.loadConfig = function(path) {
	var fn = this.path + "/" + path + "/config.xml";
	var cfgxml = null;
	
	try	{
		var cfgxml = CVCertificateStore.loadXMLFile(fn);
	}
	catch(e) {
		GPSystem.trace(e);
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
	
	var fn = this.path + "/" + path;
	var f = new java.io.File(fn);
	if (!f.exists()) {
		f.mkdirs();
	}
	
	var fn = this.path + "/" + path + "/config.xml";
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
