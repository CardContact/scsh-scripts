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
	this.type = "CVCA";

	this.crypto = new Crypto();
	
	this.ss = new CVCertificateStore(path);
	this.cvca = new CVCCA(this.crypto, this.ss, name, name);
	this.path = this.cvca.path;
	this.queue = [];
	this.dVCertificatePolicies = [];
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
 * Sets the policy for issuing root certificates
 *
 * @param {Object} policy policy object as defined for CVCCA.prototype.generateCertificate()
 */
CVCAService.prototype.setRootCertificatePolicy = function(policy) {
	this.rootCertificatePolicy = policy;
}



/**
 * Sets the policy for issuing the link certificates
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
 * @param {Regex} chrregex a regular expression that the CHR must match in order to use this rule
 */
CVCAService.prototype.setDVCertificatePolicy = function(policy, chrregex) {
	if (typeof(chrregex) != "undefined") {
		this.dVCertificatePolicies.push( { regex: chrregex, policy: policy } );
	} else {
		this.dVCertificatePolicy = policy;
	}
}



/**
 * Returns the policy to apply for a given CHR
 *
 * @param {PublicKeyReference} chr the certificate holder reference
 * @returns a matching policy or the default policy
 * @type Object
 */
CVCAService.prototype.getDVCertificatePolicyForCHR = function(chr) {
	for (var i = 0; i < this.dVCertificatePolicies.length; i++) {
		var p = this.dVCertificatePolicies[i];
		if (chr.toString().match(p.regex)) {
			return p.policy;
		}
	}
	return this.dVCertificatePolicy;
}



/**
 * Issue an initial root certificate or a new link certificate
 * 
 * @param {boolean} withDP true to include domain parameter in certificate
 */
CVCAService.prototype.generateLinkCertificate = function(withDP) {
	// Create a new request
	var req = this.cvca.generateRequest(null, false);
	print("Link/Root certificate request: " + req);
	print(req.getASN1());
	
	if (this.cvca.isOperational()) {
		this.linkCertificatePolicy.includeDomainParameter = withDP;

		// Create link certificate based on request
		var cert = this.cvca.generateCertificate(req, this.linkCertificatePolicy);
		print("Link certificate: " + cert);
		print(cert.getASN1());

		// Import certificate into store, making it the most current certificate
		this.cvca.importCertificate(cert);
	}
	
	// Create root certificate based on request
	var cert = this.cvca.generateCertificate(req, this.rootCertificatePolicy);
	print("Root certificate: " + cert);
	print(cert.getASN1());

	// Import certificate into store, making it the most current certificate
	this.cvca.importCertificate(cert);
}



/**
 * Check certificate request syntax
 *
 * @param {ByteString} req the request in binary format
 * @returns the decoded request or null in case of error
 * @type CVC
 */
CVCAService.prototype.checkRequestSyntax = function(reqbin) {
	try	{
		var reqtlv = new ASN1(reqbin);
		var req = new CVC(reqtlv);
	}
	catch(e) {
		GPSystem.trace("Error decoding ASN1 structure of request: " + e);
		return null;
	}
	
	return req;
}



/**
 * Check certificate request semantic
 *
 * @param {CVC} req the request
 * @returns one of the ServiceRequest status results (ok_cert_available if successful).
 * @type String
 */
CVCAService.prototype.checkRequestSemantics = function(req) {
	// Check inner signature
	try	{
		var puk = req.getPublicKey();
	}
	catch(e) {
		GPSystem.trace("Error checking request semantics in " + e.fileName + "#" + e.lineNumber + " : " + e);
		return ServiceRequest.FAILURE_SYNTAX;
	}
	
	if (!req.verifyWith(this.crypto, puk)) {
		GPSystem.trace("Error verifying inner signature");
		return ServiceRequest.FAILURE_INNER_SIGNATURE;
	}
	
	// Check that request key algorithm matches the algorithm for the current certificate
	var chr = this.ss.getCurrentCHR(this.path);
	var cvc = this.ss.getCertificate(this.path, chr);
	var oid = cvc.getPublicKeyOID();
	var reqoid = req.getPublicKeyOID();
	
	if (!reqoid.equals(oid)) {
		GPSystem.trace("Public key algorithm " + reqoid.toString(OID) + " in request does not match current public key algorithm " + oid.toString(OID));
		return ServiceRequest.FAILURE_SYNTAX;
	}
	
	// Check that request key domain parameter match current domain parameter
	var dp = this.ss.getDomainParameter(this.path, chr);
	
	if (!puk.getComponent(Key.ECC_P).equals(dp.getComponent(Key.ECC_P)) ||
		!puk.getComponent(Key.ECC_A).equals(dp.getComponent(Key.ECC_A)) ||
		!puk.getComponent(Key.ECC_B).equals(dp.getComponent(Key.ECC_B)) ||
		!puk.getComponent(Key.ECC_GX).equals(dp.getComponent(Key.ECC_GX)) ||
		!puk.getComponent(Key.ECC_GY).equals(dp.getComponent(Key.ECC_GY)) ||
		!puk.getComponent(Key.ECC_N).equals(dp.getComponent(Key.ECC_N)) ||
		!puk.getComponent(Key.ECC_H).equals(dp.getComponent(Key.ECC_H))) {
		GPSystem.trace("Domain parameter in request do not match current domain parameter");
		return ServiceRequest.FAILURE_DOMAIN_PARAMETER;
	}
	
	if (req.isAuthenticatedRequest()) {
		var puk = this.cvca.getAuthenticPublicKey(req.getOuterCAR());
		if (puk) {
			if (!req.verifyATWith(this.crypto, puk)) {
				GPSystem.trace("Error verifying outer signature");
				return ServiceRequest.FAILURE_OUTER_SIGNATURE;
			}
		} else {
			GPSystem.trace("No public key found for authenticated request");
			return ServiceRequest.FAILURE_OUTER_SIGNATURE;
		}
	}
	
	return ServiceRequest.OK_CERT_AVAILABLE;
}



/**
 * Check certificate request against policy
 *
 * @param {CVC} req the request
 * @param {String} returnCode the proposed response string
 * @param {Boolean} callback the indicator if a call-back is possible
 * @returns one of the ServiceRequest status results (ok_cert_available if successful).
 * @type String
 */
CVCAService.prototype.checkPolicy = function(req, returnCode, callback) {
	if (returnCode != ServiceRequest.OK_CERT_AVAILABLE) {
		return returnCode;
	}
	
	var policy = this.getDVCertificatePolicyForCHR(req.getCHR());
	
	if (req.isAuthenticatedRequest()) {
		var cvc = this.cvca.getIssuedCertificate(req.getOuterCAR());
		var now = new Date();
		now.setHours(12, 0, 0, 0);
		if (now.valueOf() > cvc.getCXD().valueOf()) {
			GPSystem.trace("Certificate " + cvc.toString() + " is expired");
			if (policy.declineExpiredAuthenticatedRequest) {
				return ServiceRequest.FAILURE_EXPIRED;
			}
		} else {
			if (policy.authenticatedRequestsApproved) {
				return ServiceRequest.OK_CERT_AVAILABLE;
			}
		}
	} else {
		if (policy.initialRequestsApproved) {
			return ServiceRequest.OK_CERT_AVAILABLE;
		}
	}
	
	return callback ? ServiceRequest.OK_SYNTAX : ServiceRequest.FAILURE_SYNCHRONOUS_PROCESSING_NOT_POSSIBLE;
}



/**
 * Issue certificate for subordinate CA
 *
 * @param {CVC} req the request
 * @returns the certificate
 * @type CVC
 */
CVCAService.prototype.issueCertificate = function(req) {

	var policy = this.getDVCertificatePolicyForCHR(req.getCHR());
	var cert = this.cvca.generateCertificate(req, policy);

	this.cvca.storeCertificate(cert);

	GPSystem.trace("CVCAService - Issued certificate: ");
	GPSystem.trace(cert.getASN1());
	return cert;
}



/**
 * Determine the list of certificates to send to the client as part of the certificate request response
 *
 * @param {CVC} req the request
 * @returns the certificate list
 * @type CVC[]
 */
CVCAService.prototype.determineCertificateList = function(req) {
	var car = req.getCAR();
	var chr = this.ss.getCurrentCHR(this.path);
	
	if ((car != null) && car.equals(chr)) {
		return [];
	}
	
	return this.cvca.getCertificateList();
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

	var certlist = [];
	
	if (sr.isCertificateRequest()) {		// RequestCertificate
		if (sr.getStatusInfo() == ServiceRequest.OK_CERT_AVAILABLE) {
			var req = sr.getCertificateRequest();
			var response = this.checkRequestSemantics(req);	// Check request a second time

			if (response == ServiceRequest.OK_CERT_AVAILABLE) {		// Still valid
				certlist = this.determineCertificateList(req);
				var cert = this.issueCertificate(req);
				certlist.push(cert);
			} else {
				GPSystem.trace("Request " + req + " failed secondary check");
				sr.setStatusInfo(response);
			}
		}
	} else {								// GetCertificates
		if (sr.getStatusInfo().substr(0, 3) == "ok_") {
			certlist = this.cvca.getCertificateList();
		}
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

	var soapConnection = new SOAPConnection(SOAPConnection.SOAP11);

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
	
	try	{
		var response = soapConnection.call(serviceRequest.getResponseURL(), request);
	}
	catch(e) {
		GPSystem.trace("SOAP call to " + serviceRequest.getResponseURL() + " failed : " + e);
		throw new GPError("CVCAService", GPError.DEVICE_ERROR, 0, "SendCertificates failed with : " + e);
	}
	
	var result = response.Result.ns1::returnCode.toString();
	
	serviceRequest.setFinalStatusInfo(result);
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
	var response = ServiceRequest.OK_CERT_AVAILABLE;
	
	if (callback == "callback_possible") {
		var asyncreq = new ServiceRequest(
							soapBody.messageID.ns1::messageID,
							soapBody.responseURL.ns1::string);

		this.queue.push(asyncreq);
		var response = ServiceRequest.OK_SYNTAX;
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

	var certlist = [];

	try	{
		var reqbin = new ByteString(soapBody.certReq, BASE64);

		var req = this.checkRequestSyntax(reqbin);

		if (req == null) {
			var returnCode = ServiceRequest.FAILURE_SYNTAX;
		} else {
			GPSystem.trace("CVCAService - Received certificate request: ");
			GPSystem.trace(req);

			var returnCode = this.checkRequestSemantics(req);

			var callback = soapBody.callbackIndicator;
			var returnCode = this.checkPolicy(req, returnCode, (callback == "callback_possible"));

			if (returnCode == ServiceRequest.OK_SYNTAX) {
				var asyncreq = new ServiceRequest(
								soapBody.messageID.ns1::messageID,
								soapBody.responseURL.ns1::string,
								req);

				asyncreq.setStatusInfo(returnCode);
				this.queue.push(asyncreq);
			} else {
				if (returnCode == ServiceRequest.OK_CERT_AVAILABLE) {
					certlist = this.determineCertificateList(req);

					var cert = this.issueCertificate(req);
					// Add certificate list to response
					certlist.push(cert);
				}
			}
		}
	}
	catch(e) {
		GPSystem.trace("CVCAService - Error decoding request in " + e.fileName + "#" + e.lineNumber + " : " + e);
		var returnCode = ServiceRequest.FAILURE_SYNTAX;
	}

	var response =
		<ns:RequestCertificateResponse xmlns:ns={ns} xmlns:ns1={ns1}>
			<Result>
				<ns1:returnCode>{returnCode}</ns1:returnCode>
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
