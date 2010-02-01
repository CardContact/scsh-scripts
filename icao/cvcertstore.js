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
 * @fileoverview Support for card verifiable certificates according to EAC 2.0
 */
 



load("pkcs8.js");



/**
 * Create a object to access a certificate store
 *
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
 */
CVCertificateStore.prototype.getTerminalCertificateFor = function(cvcaref) {
	var fn = this.path + "/" + cvcaref.getHolder() + "/terminal/current.cvcert";
	
	var bin = CVCertificateStore.loadBinaryFile(fn);
	
	var cvc = new CVC(bin);
	
	return cvc;
}



CVCertificateStore.prototype.getDVCACertificateFor = function(cvcaref, dvcaref) {
	var fn = this.path + "/" + cvcaref.getHolder() + "/" + dvcaref.getHolder() + "/" + dvcaref.toString() + ".cvcert";
	
	var bin = CVCertificateStore.loadBinaryFile(fn);
	
	var cvc = new CVC(bin);
	
	return cvc;
}



CVCertificateStore.prototype.getCVCACertificateFor = function(cvcaref) {
	var fn = this.path + "/" + cvcaref.getHolder() + "/" + cvcaref.toString() + ".cvcert";
	
	var bin = CVCertificateStore.loadBinaryFile(fn);
	
	var cvc = new CVC(bin);
	
	return cvc;
}



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

	return(chain);
}



CVCertificateStore.prototype.getTerminalKeyFor = function(cvcaref) {
	var fn = this.path + "/" + cvcaref.getHolder() + "/terminal/current.pkcs8";
	
	var bin = CVCertificateStore.loadBinaryFile(fn);

	return PKCS8.decodeKeyFromPKCS8Format(bin);
}



CVCertificateStore.testPath = GPSystem.mapFilename("cvc", GPSystem.CWD);


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



function CVC() {
	if (arguments.length > 0) {
		this.bin = arguments[0];
		if (this.bin.bytes(0, 2).toString(HEX) != "7F21") {
			throw new GPError("CVC", GPError.INVALID_DATA, 0, "Data does not seem to be CV certificate");
		}
		this.asn = new ASN1(this.bin);
	}
}



CVC.prototype.getCAR = function() {
	var cardo = this.asn.get(0).find(CVC.TAG_CAR);
	
	if (!cardo) {
		throw new GPError("CVC", GPError.OBJECT_NOT_FOUND, 0, "Certificate does not contain a CAR");
	}
	
	return new PublicKeyReference(cardo.value);
}



CVC.prototype.getCHR = function() {
	var chrdo = this.asn.get(0).find(CVC.TAG_CHR);
	
	if (!chrdo) {
		throw new GPError("CVC", GPError.OBJECT_NOT_FOUND, 0, "Certificate does not contain a CHR");
	}
	
	return new PublicKeyReference(chrdo.value);
}



CVC.prototype.getExtension = function(extoid) {
	var extdo = this.asn.get(0).find(CVC.TAG_EXTN);
	
	if (!extdo) {
		throw new GPError("CVC", GPError.OBJECT_NOT_FOUND, 0, "Certificate does not contain an extension");
	}

//	print(extdo);
	
	for (var i = 0; i < extdo.length; i++) {
		var ext = extdo.get(i);
		var oid = ext.get(0);
		assert(oid.tag == ASN1.OBJECT_IDENTIFIER);
		if (oid.value.equals(extoid)) {
			return ext;
		}
	}
	return null;
}



CVC.prototype.getBytes = function() {
	return this.bin;
}



CVC.prototype.toString = function() {
	var str = "CVC CAR=" + this.getCAR().toString() + " CHR=" + this.getCHR().toString();
	return str;
}



CVC.TAG_CPI = 0x5F29;
CVC.TAG_CAR = 0x42;
CVC.TAG_CHR = 0x5F20;
CVC.TAG_EXTN = 0x65;



/**
 * Create a public key reference (CAR/CHR) from binary representation or individual fields
 */
function PublicKeyReference() {
	if (arguments.length > 0) {
		if (arguments.length == 1) {
			if (typeof(arguments[0]) == "string") {
				this.bin = new ByteString(arguments[0], ASCII);
			} else {
				this.bin = arguments[0];
			}
		} else {
			var cc = arguments[0];
			var mn = arguments[1];
			var sq = arguments[2];
			this.bin = new ByteString(cc + mn + sq, ASCII);
		}
	}
}



PublicKeyReference.prototype.getCountryCode = function() {
	return this.bin.bytes(0, 2).toString(ASCII);
}



PublicKeyReference.prototype.getMnemonic = function() {
	return this.bin.bytes(2, this.bin.length - 7).toString(ASCII);
}



PublicKeyReference.prototype.getSequenceNo = function() {
	return this.bin.bytes(this.bin.length - 5, 5).toString(ASCII);
}



PublicKeyReference.prototype.getHolder = function() {
	return this.getCountryCode() + this.getMnemonic();
}



PublicKeyReference.prototype.getBytes = function() {
	return this.bin;
}



PublicKeyReference.prototype.toString = function() {
	return this.bin.toString(ASCII);
}



PublicKeyReference.test = function() {
	var p = new PublicKeyReference(new ByteString("UTABCDF0000", ASCII));
	assert(p.getCountryCode() == "UT");
	assert(p.getMnemonic() == "ABCD");
	assert(p.getSequenceNo() == "F0000");
	assert(p.getHolder() == "UTABCD");
	
	var p = new PublicKeyReference("UT", "ABCD", "F0000");
	assert(p.getCountryCode() == "UT");
	assert(p.getMnemonic() == "ABCD");
	assert(p.getSequenceNo() == "F0000");
	assert(p.getHolder() == "UTABCD");
	
	var p = new PublicKeyReference("UTABCDF0000");
	assert(p.getCountryCode() == "UT");
	assert(p.getMnemonic() == "ABCD");
	assert(p.getSequenceNo() == "F0000");
	assert(p.getHolder() == "UTABCD");
	
	assert(p.getBytes().toString(ASCII) == "UTABCDF0000");
}

