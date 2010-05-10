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
 * @fileoverview A simple terminal control center (TCC) web service implementing TR-03129 web services
 */

load("tools/eccutils.js");


/**
 * Create a terminal control center (TCC) instance with web services
 *
 * @param {String} certstorepath the path to the certificate store
 * @param {String} path the PKI path for this service (e.g. "/UTCVCA/UTDVCA/UTTERM")
 * @param {String} parentURL the URL of the parent CA's webservice
 */ 
function TCCService(certstorepath, path, parentURL) {
	var pe = path.substr(1).split("/");
	assert(pe.length == 3);

	this.name = pe[2];
	this.type = "TCC";
	
	this.path = path;
	this.parent = pe[1];
	this.parentURL = parentURL;
	
	this.crypto = new Crypto();
	
	this.ss = new CVCertificateStore(certstorepath);
	this.tcc = new CVCCA(this.crypto, this.ss, this.name, this.parent, path);
	this.outqueue = [];
	this.outqueuemap = [];
}



/**
 * Sets the URL which is used to receive SendCertificate messages
 * 
 * @param {String} url
 */
TCCService.prototype.setSendCertificateURL = function(url) {
	this.myURL = url;
}



/**
 * Sets the key specification for generating requests
 *
 * @param {Key} keyparam a key object containing key parameters (e.g. EC Curve)
 * @param {ByteString} algorithm the terminal authentication algorithm object identifier
 */
TCCService.prototype.setKeySpec = function(keyparam, algorithm) {
	this.cvca.setKeySpec(keyparam, algorithm);
}



/**
 * Enumerate all pending service requests to superior systems
 *
 * @returns the pending service requests
 * @type ServiceRequest[]
 */
TCCService.prototype.listOutboundRequests = function() {
	return this.outqueue;
}



/**
 * Gets the indexed request
 *
 * @param {Number} index the index into the work queue identifying the request
 * @returns the indexed request
 * @type ServiceRequest
 */
TCCService.prototype.getOutboundRequest = function(index) {
	return this.outqueue[index];
}



/**
 * Adds an outbound request to the internal queue, removing the oldest entry if more than
 * 10 entries are contained
 *
 * @param {ServiceRequest} sr the service request
 */
TCCService.prototype.addOutboundRequest = function(sr) {
	if (this.outqueue.length >= 10) {
		var oldsr = this.outqueue.shift();
		var msgid = oldsr.getMessageID();
		if (msgid) {
			delete(this.outqueuemap[msgid]);
		}
	}
	this.outqueue.push(sr);
	var msgid = sr.getMessageID();
	if (msgid) {
		this.outqueuemap[msgid] = sr;
	}
}



/**
 * Update certificate list from parent CA
 *
 */
TCCService.prototype.updateCACertificates = function(async) {

	var msgid = null;
	
	if (async) {
		msgid = this.crypto.generateRandom(2).toString(HEX);
	}

	var sr = new ServiceRequest(msgid, this.myURL);
	this.addOutboundRequest(sr);
	
	var certlist = this.getCACertificatesFromDVCA(sr);
	var list = this.tcc.importCertificates(certlist);

	if (list.length > 0) {
		print("Warning: Could not import the following certificates");
		for (var i = 0; i < list.length; i++) {
			print(list[i]);
		}
	}
}



/**
 * Renew certificate through parent CA
 *
 */
TCCService.prototype.renewCertificate = function(async, forceinitial) {

	var dp = this.ss.getDefaultDomainParameter(this.path);
	var algo = this.ss.getDefaultPublicKeyOID(this.path);
	var car = this.ss.getCurrentCHR(CVCertificateStore.parentPathOf(this.path));

	this.tcc.setKeySpec(dp, algo);
	
	// Create a new request
	var req = this.tcc.generateRequest(car, forceinitial);
	print("Request: " + req);
	print(req.getASN1());

	var msgid = null;
	
	if (async) {
		msgid = this.crypto.generateRandom(2).toString(HEX);
	}

	var sr = new ServiceRequest(msgid, this.myURL, req);
	this.addOutboundRequest(sr);
	
	var certlist = this.requestCertificateFromDVCA(sr);
	
	if (certlist.length > 0) {
		sr.setFinalStatusInfo("" + certlist.length + " certificates received");
	}
	
	var list = this.tcc.importCertificates(certlist);

	if (list.length > 0) {
		print("Warning: Could not import the following certificates");
		for (var i = 0; i < list.length; i++) {
			print(list[i]);
		}
	}
}



/**
 * Import certificates
 *
 * @param {CVC[]} certlist the list of certificates
 *
 */
TCCService.prototype.importCertificates = function(certlist) {

	var list = this.tcc.importCertificates(certlist);

	if (list.length > 0) {
		print("Warning: Could not import the following certificates");
		for (var i = 0; i < list.length; i++) {
			print(list[i]);
		}
	}
}



/**
 * Obtain a list of certificates from the parent CA using a web service
 *
 * @param {ServiceRequest} serviceRequest the underlying request
 * @returns a list of certificates
 * @type CVC[]
 */
TCCService.prototype.getCACertificatesFromDVCA = function(sr) {

	var soapConnection = new SOAPConnection();

	var ns = new Namespace("uri:EAC-PKI-DV-Protocol/1.0");
	var ns1 = new Namespace("uri:eacBT/1.0");

	var request =
		<ns:GetCACertificates xmlns:ns={ns} xmlns:ns1={ns1}>
			<callbackIndicator>callback_not_possible</callbackIndicator>
			<messageID>
			</messageID>
			<responseURL>
			</responseURL>
		</ns:GetCACertificates>;

	if (sr.getMessageID()) {
		request.callbackIndicator = "callback_possible";
		request.messageID.ns1::messageID = sr.getMessageID();
		request.responseURL.ns1::string = sr.getResponseURL();
	}
	
	var response = soapConnection.call(this.parentURL, request);
	
	sr.setStatusInfo(response.Result.ns1::returnCode.toString());
	var certlist = [];

	if (response.Result.ns1::returnCode.toString() == ServiceRequest.OK_CERT_AVAILABLE) {
		GPSystem.trace("Received certificates from DVCA:");
		for each (var c in response.Result.ns1::certificateSeq.ns1::certificate) {
			var cvc = new CVC(new ByteString(c, BASE64));
			certlist.push(cvc);
			GPSystem.trace(cvc);
		}
	}

	return certlist;
}



/**
 * Request a certificate from the parent CA using a web service
 *
 * @param {ServiceRequest} serviceRequest the underlying request
 * @returns the new certificates
 * @type CVC[]
 */
TCCService.prototype.requestCertificateFromDVCA = function(sr) {

	var soapConnection = new SOAPConnection();

	var ns = new Namespace("uri:EAC-PKI-DV-Protocol/1.0");
	var ns1 = new Namespace("uri:eacBT/1.0");

	var request =
		<ns:RequestCertificate xmlns:ns={ns} xmlns:ns1={ns1}>
			<callbackIndicator>callback_not_possible</callbackIndicator>
			<messageID>
			</messageID>
			<responseURL>
			</responseURL>
			<certReq>{sr.getCertificateRequest().getBytes().toString(BASE64)}</certReq>
		</ns:RequestCertificate>

	if (sr.getMessageID()) {
		request.callbackIndicator = "callback_possible";
		request.messageID.ns1::messageID = sr.getMessageID();
		request.responseURL.ns1::string = sr.getResponseURL();
	}
		
	try	{
		var response = soapConnection.call(this.parentURL, request);
	}
	catch(e) {
		GPSystem.trace("SOAP call to " + this.parentURL + " failed : " + e);
		throw new GPError("TCCService", GPError.DEVICE_ERROR, 0, "RequestCertificate failed with : " + e);
	}
	
	sr.setStatusInfo(response.Result.ns1::returnCode.toString());
	var certlist = [];

	if (response.Result.ns1::returnCode.substr(0, 3) == "ok_") {
		GPSystem.trace("Received certificates from DVCA:");
		for each (var c in response.Result.ns1::certificateSeq.ns1::certificate) {
			var cvc = new CVC(new ByteString(c, BASE64));
			certlist.push(cvc);
			GPSystem.trace(cvc);
		}
	}

	return certlist;
}



/**
 * Webservice that receives certificates from parent CA
 * 
 * @param {XML} soapBody the body of the SOAP message
 * @returns the soapBody of the response
 * @type XML
 */
TCCService.prototype.SendCertificates = function(soapBody) {
	
	var ns = new Namespace("uri:EAC-PKI-TermContr-Protocol/1.0");
	var ns1 = new Namespace("uri:eacBT/1.0");

	var statusInfo = soapBody.statusInfo.toString();
	var msgid = soapBody.messageID.toString();
	
	var sr = this.outqueuemap[msgid];
	if (sr) {
		sr.setStatusInfo(statusInfo);
		var returnCode = ServiceRequest.OK_RECEIVED_CORRECTLY;

		if (returnCode.substr(0, 3) == "ok_") {
			var certlist = [];
			GPSystem.trace("Received certificates from DVCA:");
			for each (var c in soapBody.certificateSeq.ns1::certificate) {
				try	{
					var cvc = new CVC(new ByteString(c, BASE64));
				}
				catch(e) {
					GPSystem.trace("Error decoding certificate: " + e);
					var returnCode = ServiceRequest.FAILURE_SYNTAX;
					break;
				}
				certlist.push(cvc);
				GPSystem.trace(cvc);
			}

			this.importCertificates(certlist);
		}
		sr.setFinalStatusInfo(returnCode);
	} else {
		returnCode = ServiceRequest.FAILURE_MESSAGEID_UNKNOWN;
	}
	
	var response =
		<ns:SendCertificatesResponse xmlns:ns={ns} xmlns:ns1={ns1}>
			<Result>
				<ns1:returnCode>{returnCode}</ns1:returnCode>
			</Result>
		</ns:SendCertificatesResponse>

	return response;
}



/**
 * Webservice that returns a list of certificates that resemble a valid certificate chain
 * starting with a certificate issued by the trust anchor's public key reference provided
 * a argument to the service invocation.
 * 
 * @param {XML} soapBody the body of the SOAP message
 * @returns the soapBody of the response
 * @type XML
 */
TCCService.prototype.GetCertificateChain = function(soapBody) {

	// Create empty response
	var ns = new Namespace("uri:EAC-PKI-TermContr-Protocol/1.0");
	var ns1 = new Namespace("uri:eacBT/1.0");

	var chrstr = soapBody.keyNameMRTD;
	
	var returnCode = ServiceRequest.OK_CERT_AVAILABLE;
	var certlist = [];
	
	try	{
		var chrbin = new ByteString(chrstr, BASE64);
		var chr = new PublicKeyReference(chrbin);
	}
	catch(e) {
		GPSystem.trace("Error decoding requests CHR : " + chrstr);
		var returnCode = ServiceRequest.FAILURE_SYNTAX;
	}
	
	if (returnCode == ServiceRequest.OK_CERT_AVAILABLE) {
		var cl = this.tcc.getCertificateList(chr);
		if (cl == null) {
			var returnCode = ServiceRequest.FAILURE_CAR_UNKNOWN;
		} else {
			certlist = cl;
		}
	}
	
	var response =
		<ns:GetCertificateChain xmlns:ns={ns} xmlns:ns1={ns1}>
			<Result>
				<ns1:returnCode>{returnCode}</ns1:returnCode>
				<!--Optional:-->
				<ns1:certificateSeq>
					<!--Zero or more repetitions:-->
				</ns1:certificateSeq>
			</Result>
		</ns:GetCertificateChain>
	
	var list = response.Result.ns1::certificateSeq;

	for (var i = 0; i < certlist.length; i++) {
		var cvc = certlist[i];
		list.certificate += <ns1:certificate xmlns:ns1={ns1}>{cvc.getBytes().toString(BASE64)}</ns1:certificate>
	}

	return response;
}



/**
 * Webservice that signs a block of data or a hash to generate a signature suitable for
 * external authentication against an MRTD
 * 
 * @param {XML} soapBody the body of the SOAP message
 * @returns the soapBody of the response
 * @type XML
 */
TCCService.prototype.GetTASignature = function(soapBody) {

	// Create empty response
	var ns = new Namespace("uri:EAC-PKI-TermContr-Protocol/1.0");
	var ns1 = new Namespace("uri:eacBT/1.0");

	var returnCode = ServiceRequest.OK_SIGNATURE_AVAILABLE;
	
	var chrstr = soapBody.keyCHR.toString();
	
	try	{
		var chrbin = new ByteString(chrstr, BASE64);
		var chr = new PublicKeyReference(chrbin);
	}
	catch(e) {
		GPSystem.trace("Error decoding requests CHR : " + chrstr);
		var returnCode = ServiceRequest.FAILURE_SYNTAX;
	}
	
	var hashstr = soapBody.hashTBS.ns1::binary.toString();
	try	{
		var hashbin = new ByteString(hashstr, BASE64);
		assert(hashbin.length > 0);
	}
	catch(e) {
		GPSystem.trace("Error decoding requests hashTBS : " + hashstr);
		var returnCode = ServiceRequest.FAILURE_SYNTAX;
	}

	if (returnCode == ServiceRequest.OK_SIGNATURE_AVAILABLE) {
		var prk = this.tcc.certstore.getPrivateKey(this.path, chr);
		if (prk == null) {
			var returnCode = ServiceRequest.FAILURE_CHR_UNKNOWN;
		} else {
			var cvc = this.tcc.certstore.getCertificate(this.path, chr);
			
			// ToDo: Check expiration of certificate
			
			var mech = CVC.getSignatureMech(cvc.getPublicKeyOID());
			
			var signature = this.crypto.sign(prk, Crypto.ECDSA, hashbin);
			
			var keylen = prk.getComponent(Key.ECC_P).length;
			
			var signature = ECCUtils.unwrapSignature(signature, keylen);
		}
	}
	
	var response =
		<ns:GetTASignature xmlns:ns={ns} xmlns:ns1={ns1}>
			<Result>
				<ns1:returnCode>{returnCode}</ns1:returnCode>
				<ns1:Signature></ns1:Signature>
			</Result>
		</ns:GetTASignature>
	
	if (returnCode == ServiceRequest.OK_SIGNATURE_AVAILABLE) {
		response.Result.ns1::Signature =  <ns1:Signature xmlns:ns1={ns1}>{signature.toString(BASE64)}</ns1:Signature>
	}
	
	return response;
}
