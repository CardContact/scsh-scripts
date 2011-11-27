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
 * @fileoverview Connector implementing a web service interface to a terminal control center as defined in TR-03129
 */


load("../cvc.js");


/**
 * Creates a web service connector to access services of a terminal control center as defined in TR-03129
 *
 * @class Class implementing a terminal control center web service connector
 * @constructor
 * @param {String} url the web service endpoint
 */
function TCCConnection(url) {
	this.url = url;
	this.soapcon = new SOAPConnection();
	this.verbose = true;
	this.lastError = null;
	this.version = "1.1";
}



/**
 * Get the last error return code
 *
 * @returns the last error return code received or null if none defined
 * @type String
 */
TCCConnection.prototype.getLastError = function() {
	return this.lastError;
}



/**
 * Close the connector and release allocated resources
 */
TCCConnection.prototype.close = function() {
	this.soapcon.close();
}



/**
 * Obtain a list of card verifiable certificates that can be used to provide the MRTD with a chain of certificates
 * up to and including the terminal certificate.
 *
 * @param {PublicKeyReference} keyNameMRTD the certificate holder reference of the trust anchor used by the MRTD
 * @returns a lists of card verifiable certificates from root to terminal or null in case of error
 * @type CVC[]
 */
TCCConnection.prototype.getCertificateChain = function(keyNameMRTD) {
	
	this.lastError = null;

	var ns = new Namespace("uri:EAC-PKI-TermContr-Protocol/" + this.version);
	var ns1 = new Namespace("uri:eacBT/" + this.version);

	if (this.version == "1.0") {
		var request =
			<ns:GetCertificateChain xmlns:ns={ns} xmlns:ns1={ns1}>
				<keyNameMRTD>{keyNameMRTD.getBytes().toString(BASE64)}</keyNameMRTD>
			</ns:GetCertificateChain>
	} else {
		var request =
			<ns:GetCertificateChain xmlns:ns={ns} xmlns:ns1={ns1}>
				<keyCAR>{keyNameMRTD.getBytes().toString(BASE64)}</keyCAR>
			</ns:GetCertificateChain>
	}
	
	if (this.verbose) {
		GPSystem.trace(request.toXMLString());
	}

	var response = this.soapcon.call(this.url, request);

	if (this.verbose) {
		GPSystem.trace(response.toXMLString());
	}

	var certmap = [];

	if (response.Result.ns1::returnCode.toString() == "ok_cert_available") {
		GPSystem.trace("Received certificates from TCC:");
		for each (var c in response.Result.ns1::certificateSeq.ns1::certificate) {
			var cvc = new CVC(new ByteString(c, BASE64));
			certmap[cvc.getCAR().toString()] = cvc;
			GPSystem.trace(cvc);
		}
	} else {
		this.lastError = response.Result.ns1::returnCode.toString();
		return null;
	}

	var certlist = [];

	var car = keyNameMRTD;
	var cvc = certmap[car.toString()];
	
	while (typeof(cvc) != "undefined") {
		certlist.push(cvc);
		GPSystem.trace("Added: " + c);
		car = cvc.getCHR()
		cvc = certmap[car.toString()]
	}

	return certlist;
}



/**
 * Obtain a signature from the TCC for a hash or a block of data
 *
 * @param {PublicKeyReference} keyCHR the key to be used for signing
 * @param {ByteString} digest the message digest or null if second variant is used
 * @returns the signature as a concatenation of coordinates on the curve or null in case of error
 * @type ByteString
 */
TCCConnection.prototype.getTASignature = function(keyCHR, digest) {
	
	this.lastError = null;

	var ns = new Namespace("uri:EAC-PKI-TermContr-Protocol/" + this.version);
	var ns1 = new Namespace("uri:eacBT/" + this.version);
	
	var request =
		<ns:GetTASignature xmlns:ns={ns} xmlns:ns1={ns1}>
			<hashTBS>
			</hashTBS>
			<idPICC>
			</idPICC>
			<challengePICC>
			</challengePICC>
			<hashPK>
			</hashPK>
			<auxPCD>
			</auxPCD>
			<keyCHR>{keyCHR.getBytes().toString(BASE64)}</keyCHR>
		</ns:GetTASignature>

	request.hashTBS.ns1::binary = <ns1:binary xmlns:ns1={ns1}>{digest.toString(BASE64)}</ns1:binary>;

	if (this.verbose) {
		GPSystem.trace(request.toXMLString());
	}

	var response = this.soapcon.call(this.url, request);

	if (this.verbose) {
		GPSystem.trace(response.toXMLString());
	}
	
	var signature = null;
	
	if (response.Result.ns1::returnCode.toString() == "ok_signature_available") {
		var signatureStr = response.Result.ns1::Signature.toString();
		GPSystem.trace("Received signature from TCC: " + signatureStr);
		signature = new ByteString(signatureStr, BASE64);
		GPSystem.trace("Received signature from TCC: " + signature);
	} else {
		this.lastError = response.Result.ns1::returnCode.toString();
	}

	return signature;
}



/**
 * Perform a simple test
 */
TCCConnection.test = function() {
	var c = new TCCConnection("http://localhost:8080/se/tcc");
	
	var chr = new PublicKeyReference("UTCVCA00001");
	var cl = c.getCertificateChain(chr);
	
	if (cl == null) {
		print("GetCertificateChain reports error: " + c.getLastError());
	}
	
	print("Received certificates:");
	for (var i = 0; i < cl.length; i++) {
		print(cl[i]);
	}

	// Extract terminal certificate, which is always the last in the list
	var tcert = cl[cl.length - 1];
	var chr = tcert.getCHR();
	
	var crypto = new Crypto();
	var message = new ByteString("Hello World", ASCII);
	
	var digest = crypto.digest(Crypto.SHA_256, message);
	
	var signature = c.getTASignature(chr, digest);
	
	if (signature == null) {
		print("GetTASignature reports error: " + c.getLastError());
		return;
	}
	
	print("Signature: " + signature);
	var signature = ECCUtils.wrapSignature(signature);

	// Important: Test only works for fixed domain parameter !!!
	var dp = new Key();
	dp.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP256r1", OID));

	var puk = tcert.getPublicKey(dp);
	var mech = CVC.getSignatureMech(tcert.getPublicKeyOID());

	print("Message: " + message);
	print("Hash: " + digest);

	print("Signature verification: " + crypto.verify(puk, mech, message, signature));
}

