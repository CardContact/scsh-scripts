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
 * @fileoverview A simple CVCA web service implementing TR-03129
 */



/**
 * Create a CVCA web service
 * 
 * @class Class implementing a CVCA web service according to TR-03129
 * @constructor
 * @param {path} path the file system path on the server containing the certificate store
 * @param {name} name the holder name for this CA
 */
function CVCAService(path, name) {
	this.name = name;
	var crypto = new Crypto();
	
	this.ss = new CVCertificateStore(path);
	this.cvca = new CVCCA(crypto, this.ss, name, name);
	this.queue = [];
}



/**
 * Sets the key specification for generating requests
 *
 * @param {Key} keyparam a key object containing key parameters (e.g. EC Curve)
 * @param {ByteString} algorithm the terminal authentication algorithm object identifier
 */
CVCAService.prototype.setKeySpec = function(keyparam, algorithm) {
	this.cvca.setKeySpec(keyparam, algorithm);
}



/**
 * Sets the policy for issuing the root and link certificates
 *
 * @param {Object} policy policy object as defined for CVCCA.prototype.generateCertificate()
 */
CVCAService.prototype.setLinkCertificatePolicy = function(policy) {
	this.linkCertificatePolicy = policy;
}



/**
 * Sets the policy for issuing document verifier certificates
 *
 * @param {Object} policy policy object as defined for CVCCA.prototype.generateCertificate()
 */
CVCAService.prototype.setDVCertificatePolicy = function(policy) {
	this.dVCertificatePolicy = policy;
}



/**
 * Issue an initial root certificate or a new link certificate
 * 
 * @param {boolean} withDP true to include domain parameter in certificate
 */
CVCAService.prototype.generateLinkCertificate = function(withDP) {
	// Create a new request
	var req = this.cvca.generateRequest();
	print("Link certificate request: " + req);
	print(req.getASN1());
	
	this.linkCertificatePolicy.includeDomainParameter = withDP;

	// Create self-signed or link certificate based on request
	var cert = this.cvca.generateCertificate(req, this.linkCertificatePolicy);
	print("Certificate: " + cert);
	print(cert.getASN1());

	// Import certificate into store, making it the most current certificate
	this.cvca.importCertificate(cert);
}



/**
 * Issue certificate for subordinate CA
 *
 * @param {CVC} req the request
 * @returns the certificate
 * @type CVC
 */
CVCAService.prototype.issueCertificate = function(req) {

	var cert = this.cvca.generateCertificate(req, this.dVCertificatePolicy);
	
	this.cvca.importCertificates([ cert ]);

	GPSystem.trace("CVCAService - Issued certificate: ");
	GPSystem.trace(cert.getASN1());
	return cert;
}



/**
 * Enumerate all pending service requests
 *
 * @returns the pending service requests
 * @type ServiceRequest[]
 */
CVCAService.prototype.listRequests = function() {
	return this.queue;
}



/**
 * Gets the indexed request
 *
 * @param {Number} index the index into the work queue identifying the request
 * @returns the indexed request
 * @type ServiceRequest
 */
CVCAService.prototype.getRequest = function(index) {
	return this.queue[index];
}



/**
 * Process request and send certificates
 *
 * @param {Number} index the index into the work queue identifying the request
 */
CVCAService.prototype.processRequest = function(index) {
	var sr = this.queue[index];
	
	certlist = this.cvca.getCertificateList();
	
	if (sr.isCertificateRequest()) {
		var cert = this.issueCertificate(sr.getCertificateRequest());
		certlist.push(cert);
	}
	
	this.sendCertificates(sr, certlist);
}



/**
 * Delete a request from the work queue
 *
 * @param {Number} index the index into the work queue
 */
CVCAService.prototype.deleteRequest = function(index) {
	this.queue.splice(index, 1);
}



/**
 * Send certificates using a webservice call
 *
 * @param {ServiceRequest} serviceRequest the underlying request
 * @param {CVC[]} certificates the list of certificates to send
 */
CVCAService.prototype.sendCertificates = function(serviceRequest, certificates) {

	var soapConnection = new SOAPConnection();

	var ns = new Namespace("uri:EAC-PKI-DV-Protocol/1.0");
	var ns1 = new Namespace("uri:eacBT/1.0");

	var request =
		<ns:SendCertificates xmlns:ns={ns} xmlns:ns1={ns1}>
			<messageID>{serviceRequest.getMessageID()}</messageID>
			<statusInfo>{serviceRequest.getStatusInfo()}</statusInfo>
			<certificateSeq>
			</certificateSeq>
		</ns:SendCertificates>;

	var list = request.certificateSeq;

	for (var i = 0; i < certificates.length; i++) {
		var cvc = certificates[i];
		list.certificate += <ns1:certificate xmlns:ns1={ns1}>{cvc.getBytes().toString(BASE64)}</ns1:certificate>
	}

	GPSystem.trace(request);
	
	var response = soapConnection.call(serviceRequest.getResponseURL(), request);
	
	if (response.Result.ns1::returnCode.substr(0, 3) != "ok_") {
		GPSystem.trace("SendCertificates failed:");
		GPSystem.trace(response);
		throw new GPError("CVCAService", GPError.DEVICE_ERROR, 0, "SendCertificates failed with returnCode " + response.Result.ns1::returnCode);
	}
}



/**
 * Webservice that returns the list of certificates for this CA
 * 
 * @param {XML} soapBody the body of the SOAP message
 * @returns the soapBody of the response
 * @type XML
 */
CVCAService.prototype.GetCACertificates = function(soapBody) {

	// Create empty response
	var ns = new Namespace("uri:EAC-PKI-CVCA-Protocol/1.0");
	var ns1 = new Namespace("uri:eacBT/1.0");

	var callback = soapBody.callbackIndicator;
	
	var certlist = [];
	var response = "ok_cert_available";
	
	if (callback == "callback_possible") {
		var asyncreq = new ServiceRequest(
							soapBody.messageID.ns1::messageID,
							soapBody.responseURL.ns1::string);

//		var asyncreq = {
//			msgid: soapBody.messageID.ns1::messageID.toString(),
//			url: soapBody.responseURL.ns1::string.toString()
//		};
		this.queue.push(asyncreq);
		var response = "ok_syntax";
	} else {
		// Add certificate list to response
		certlist = this.cvca.getCertificateList();
	}
	
	var response =
		<ns:GetCACertificatesResult xmlns:ns={ns} xmlns:ns1={ns1}>
			<Result>
				<ns1:returnCode>{response}</ns1:returnCode>
				<!--Optional:-->
				<ns1:certificateSeq>
					<!--Zero or more repetitions:-->
				</ns1:certificateSeq>
			</Result>
		</ns:GetCACertificatesResult>
	
	var list = response.Result.ns1::certificateSeq;

	for (var i = 0; i < certlist.length; i++) {
		var cvc = certlist[i];
		list.certificate += <ns1:certificate xmlns:ns1={ns1}>{cvc.getBytes().toString(BASE64)}</ns1:certificate>
	}

	return response;
	
}



/**
 * Webservice that issues a new certificate for the submitted request
 * 
 * @param {XML} soapBody the body of the SOAP message
 * @returns the soapBody of the response
 * @type XML
 */
CVCAService.prototype.RequestCertificate = function(soapBody) {
	
	var ns = new Namespace("uri:EAC-PKI-CVCA-Protocol/1.0");
	var ns1 = new Namespace("uri:eacBT/1.0");
	
	var reqbin = new ByteString(soapBody.certReq, BASE64);
	var req = new CVC(reqbin);
	
	GPSystem.trace("CVCAService - Received certificate request: ");
	GPSystem.trace(req);
	
	var callback = soapBody.callbackIndicator;
	
	var certlist = [];
	var response = "ok_cert_available";
	
	if (callback == "callback_possible") {
		var asyncreq = new ServiceRequest(
							soapBody.messageID.ns1::messageID,
							soapBody.responseURL.ns1::string,
							req);

//		var asyncreq = {
//			msgid: soapBody.messageID.ns1::messageID.toString(),
//			url: soapBody.responseURL.ns1::string.toString(),
//			request: req
//		};
		this.queue.push(asyncreq);
		var response = "ok_syntax";
	} else {
		var cert = this.issueCertificate(req);
	
		// Add certificate list to response
		certlist = this.cvca.getCertificateList();
		certlist.push(cert);
	}

	var response =
		<ns:RequestCertificateResponse xmlns:ns={ns} xmlns:ns1={ns1}>
			<Result>
				<ns1:returnCode>{response}</ns1:returnCode>
				<!--Optional:-->
				<ns1:certificateSeq>
					<!--Zero or more repetitions:-->
				</ns1:certificateSeq>
			</Result>
		</ns:RequestCertificateResponse>
	
	var list = response.Result.ns1::certificateSeq;

	for (var i = 0; i < certlist.length; i++) {
		var cvc = certlist[i];
		list.certificate += <ns1:certificate xmlns:ns1={ns1}>{cvc.getBytes().toString(BASE64)}</ns1:certificate>
	}

	return response;
}
