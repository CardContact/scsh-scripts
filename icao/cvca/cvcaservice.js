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
	this.outqueue = [];
	this.outqueuemap = [];
	this.dVCertificatePolicies = [];
	this.version = "1.1";
	this.changeKeySpecification("brainpoolP256r1withSHA256");
	this.spoclist = [];
	this.spocmap = [];
}



CVCAService.KeySpecification = [
	{ id: "brainpoolP192r1withSHA1", name: "brainpoolP192r1 with SHA-1", oid: CVC.id_TA_ECDSA_SHA_1  , curve: new ByteString("brainpoolP192r1", OID), keysize: 0 },
	{ id: "brainpoolP224r1withSHA224", name: "brainpoolP224r1 with SHA-224", oid: CVC.id_TA_ECDSA_SHA_224, curve: new ByteString("brainpoolP224r1", OID), keysize: 0 },
	{ id: "brainpoolP256r1withSHA256", name: "brainpoolP256r1 with SHA-256", oid: CVC.id_TA_ECDSA_SHA_256, curve: new ByteString("brainpoolP256r1", OID), keysize: 0 },
	{ id: "brainpoolP384r1withSHA384", name: "brainpoolP384r1 with SHA-384", oid: CVC.id_TA_ECDSA_SHA_384, curve: new ByteString("brainpoolP384r1", OID), keysize: 0 },
	{ id: "brainpoolP512r1withSHA512", name: "brainpoolP512r1 with SHA-512", oid: CVC.id_TA_ECDSA_SHA_512, curve: new ByteString("brainpoolP512r1", OID), keysize: 0 },
	{ id: "RSA2048V15withSHA1", name: "RSA 2048 PKCS#1 V1.5 with SHA-1", oid: CVC.id_TA_RSA_v1_5_SHA_1  , curve: null, keysize: 2048 },
	{ id: "RSA2048V15withSHA256", name: "RSA 2048 PKCS#1 V1.5 with SHA-256", oid: CVC.id_TA_RSA_v1_5_SHA_256, curve: null, keysize: 2048 },
//	{ id: "RSA2048V15withSHA512", name: "RSA 2048 PKCS#1 V1.5 with SHA-512", oid: CVC.id_TA_RSA_v1_5_SHA_512, curve: null, keysize: 2048 },
	{ id: "RSA2048PSSwithSHA1", name: "RSA 2048 PSS with SHA-1", oid: CVC.id_TA_RSA_PSS_SHA_1   , curve: null, keysize: 2048 },
	{ id: "RSA2048PSSwithSHA256", name: "RSA 2048 PSS with SHA-1", oid: CVC.id_TA_RSA_PSS_SHA_256 , curve: null, keysize: 2048 },
//	{ id: "RSA2048PSSwithSHA512", name: "RSA 2048 PSS with SHA-1", oid: CVC.id_TA_RSA_PSS_SHA_512 , curve: null, keysize: 2048 },
];

CVCAService.KeySpecificationMap = [];
for (var i = 0; i < CVCAService.KeySpecification.length; i++) {
	CVCAService.KeySpecificationMap[CVCAService.KeySpecification[i].id] = CVCAService.KeySpecification[i];
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
 * Change the key specification for generating requests
 *
 * @param {String} newSpec id from CVCAService.KeySpecification
 */
CVCAService.prototype.changeKeySpecification = function(newSpec) {
	this.currentKeySpec = newSpec;
	var s = CVCAService.KeySpecificationMap[newSpec];
	
	var key = new Key();
	if (CVC.isECDSA(s.oid)) {
		key.setComponent(Key.ECC_CURVE_OID, s.curve);
	} else {
		key.setSize(s.keysize);
	}

	this.cvca.setKeySpec(key, s.oid);
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
 * Obtain a service port for TR-03129 service calls
 * 
 * @type Object
 * @return the service port that can be registered with the SOAP Server
 */
CVCAService.prototype.getTR3129ServicePort = function() {
	return new TR3129ServicePort(this);
}



/**
 * Obtain a service port for SPOC service calls
 * 
 * @type Object
 * @return the service port that can be registered with the SOAP Server
 */
CVCAService.prototype.getSPOCServicePort = function() {
	return new SPOCServicePort(this);
}



/**
 * Add a SPOC to the list of SPOCs
 *
 * @param {String} country the 2 letter ISO 3166-1 ALPHA-2 country code
 * @param {String} name a verbose name of the SPOC
 * @param {String} url the URL of the SPOC
 */
CVCAService.prototype.addSPOC = function(spoc) {
	this.spoclist.push(spoc);
	this.spocmap[spoc.country] = spoc;
}



/**
 * Return SPOC configuration for given country
 *
 * @param {String} country the 2 letter ISO 3166-1 ALPHA-2 country code
 * @type Object
 * @return the SPOC configuration
 */
CVCAService.prototype.getSPOC = function(country) {
	return this.spocmap[country];
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
	
	if (CVC.isECDSA(oid)) {
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
	}
	
	if (req.isAuthenticatedRequest()) {
		var puk = this.cvca.getAuthenticPublicKey(req.getOuterCAR());
		if (puk) {
			var oid = this.cvca.getIssuedCertificate(req.getOuterCAR()).getPublicKeyOID();
			if (!req.verifyATWith(this.crypto, puk, oid)) {
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
 * Compile a list of relevant CA certificates for GetCACertificates()
 *
 * @param {Boolean} ouronly true if this list only contains our own certificates but no certificate of other CVCAs
 * @type CVC[]
 * @return the list of CVC certificates
 */
CVCAService.prototype.compileCertificateList = function(ouronly) {
	var certlist = this.cvca.getCertificateList();
	if (!ouronly) {
		for each (var spoc in this.spoclist) {
			for each (var holderId in spoc.holderIDs) {
				var path = "/" + holderId;
				print("HolderID: " + holderId);
				var chr = this.ss.getCurrentCHR(path);
				print("Current chr: " + chr);
				if (chr != null) {
					certlist = certlist.concat(this.ss.getCertificateChain(path, chr));
				}
			}
		}
	}
	return certlist;
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
			// Only return our own certificate to the other SPOC
			certlist = this.compileCertificateList(sr.getType() == "SPOC");
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
 * Enumerate all pending service requests to superior systems
 *
 * @returns the pending service requests
 * @type ServiceRequest[]
 */
CVCAService.prototype.listOutboundRequests = function() {
	return this.outqueue;
}



/**
 * Gets the indexed request
 *
 * @param {Number} index the index into the work queue identifying the request
 * @returns the indexed request
 * @type ServiceRequest
 */
CVCAService.prototype.getOutboundRequest = function(index) {
	return this.outqueue[index];
}



/**
 * Adds an outbound request to the internal queue, removing the oldest entry if more than
 * 10 entries are contained
 *
 * @param {ServiceRequest} sr the service request
 */
CVCAService.prototype.addOutboundRequest = function(sr) {
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
 * Send certificates using a webservice call
 *
 * @param {ServiceRequest} serviceRequest the underlying request
 * @param {CVC[]} certificates the list of certificates to send
 */
CVCAService.prototype.sendCertificates = function(serviceRequest, certificates) {
	if (serviceRequest.getType() == "SPOC") {
		var con = new SPOCConnection(serviceRequest.getResponseURL());
		var callerID = this.name.substr(0, 2);
		var result = con.sendCertificates(certificates, callerID, serviceRequest.getMessageID(), serviceRequest.getStatusInfo());
		serviceRequest.setFinalStatusInfo(result);
	} else {
		var soapConnection = new SOAPConnection(SOAPConnection.SOAP11);

		var ns = new Namespace("uri:EAC-PKI-DV-Protocol/" + this.version);
		var ns1 = new Namespace("uri:eacBT/" + this.version);

		if (this.version == "1.0") {
			var request =
				<ns:SendCertificates xmlns:ns={ns} xmlns:ns1={ns1}>
					<messageID>{serviceRequest.getMessageID()}</messageID>
					<statusInfo>{serviceRequest.getStatusInfo()}</statusInfo>
					<certificateSeq>
					</certificateSeq>
				</ns:SendCertificates>;
		} else {
			var request =
				<ns:SendCertificates xmlns:ns={ns} xmlns:ns1={ns1}>
					<messageID>
						<ns1:messageID>{serviceRequest.getMessageID()}</ns1:messageID>
					</messageID>
					<statusInfo>{serviceRequest.getStatusInfo()}</statusInfo>
					<certificateSeq>
					</certificateSeq>
				</ns:SendCertificates>;
		}
	
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
}



CVCAService.prototype.getCACertificatesFromSPOCs = function() {
	for (var i = 0; i < this.spoclist.length; i++) {
		this.getCACertificatesFromSPOC(this.spoclist[i].country);
	}
}



CVCAService.prototype.getCACertificatesFromSPOC = function(country) {
	var spoc = this.spocmap[country];
	
	msgid = this.crypto.generateRandom(2).toString(HEX);

	var sr = new ServiceRequest(msgid, spoc.url);
	this.addOutboundRequest(sr);
	
	var con = new SPOCConnection(spoc.url);
	var callerID = this.name.substr(0, 2);
	var list = con.getCACertificates(callerID, msgid);
	con.close();
	
	var certlist = [];
	
	if (!list) {
		sr.setStatusInfo(con.getLastError());
	} else {
		sr.setStatusInfo(ServiceRequest.OK_CERT_AVAILABLE);
		for (var i = 0; i < list.length; i++) {
			var cvc = new CVC(list[i]);
			certlist.push(cvc);
			GPSystem.trace(cvc);
		}
	}

	var list = this.cvca.importCertificates(certlist);

	if (list.length > 0) {
		print("Warning: Could not import the following certificates");
		for (var i = 0; i < list.length; i++) {
			print(list[i]);
		}
	}
}



// --- WebServices

/**
 * Webservice that returns the list of certificates for this CA
 * 
 * @param {XML} soapBody the body of the SOAP message
 * @returns the soapBody of the response
 * @type XML
 */
CVCAService.prototype.GetCACertificates = function(soapBody) {

	// Create empty response
	var ns = new Namespace("uri:EAC-PKI-CVCA-Protocol/" + this.version);
	var ns1 = new Namespace("uri:eacBT/" + this.version);

	var callback = soapBody.callbackIndicator;
	
	var certlist = [];
	var response = ServiceRequest.OK_CERT_AVAILABLE;
	
	if (callback == "callback_possible") {
		var asyncreq = new ServiceRequest(
							soapBody.messageID.ns1::messageID,
							soapBody.responseURL.ns1::string);

		asyncreq.setType("DVCA");
		this.queue.push(asyncreq);
		var response = ServiceRequest.OK_SYNTAX;
	} else {
		// Add certificate list to response
		certlist = this.compileCertificateList(false);
	}
	
	var response =
		<ns:GetCACertificatesResponse xmlns:ns={ns} xmlns:ns1={ns1}>
			<Result>
				<ns1:returnCode>{response}</ns1:returnCode>
				<!--Optional:-->
				<ns1:certificateSeq>
					<!--Zero or more repetitions:-->
				</ns1:certificateSeq>
			</Result>
		</ns:GetCACertificatesResponse>
	
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
	
	var ns = new Namespace("uri:EAC-PKI-CVCA-Protocol/" + this.version);
	var ns1 = new Namespace("uri:eacBT/" + this.version);

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



/**
 * The TR-03129 Service port class
 */
function TR3129ServicePort(service) {
	this.service = service;
}

TR3129ServicePort.prototype.GetCACertificates = function(soapBody) {
	return this.service.GetCACertificates(soapBody);
}

TR3129ServicePort.prototype.RequestCertificate = function(soapBody) {
	return this.service.RequestCertificate(soapBody);
}


/**
 * The SPOC Service port class
 */
function SPOCServicePort(service) {
	this.service = service;
}

SPOCServicePort.prototype.GeneralMessage = function(soapBody) {
	print(soapBody.toXMLString());
	throw new Error("Not implemented");
}



SPOCServicePort.prototype.GetCACertificatesRequest = function(soapBody) {

	var ns = new Namespace("http://namespaces.unmz.cz/csn369791");

	var callerID = soapBody.ns::callerID.toString();
	var messageID = soapBody.ns::messageID.toString();

	var certlist = [];

	var spoc = this.service.getSPOC(callerID);
	if (!spoc) {
		var result = ServiceRequest.FAILURE_REQUEST_NOT_ACCEPTED;
	} else {
		var result = ServiceRequest.OK_CERT_AVAILABLE;
	
		if (spoc.async) {
			var asyncreq = new ServiceRequest(
							messageID,
							spoc.url);
			asyncreq.setType("SPOC");
			
			this.service.queue.push(asyncreq);
			var result = ServiceRequest.OK_RECEPTION_ACK;
		} else {
			// Add certificate list to response
			certlist = this.service.compileCertificateList(true);
		}
	}
	
	if (certlist.length > 0) {
		var response =
			<csn:GetCACertificatesResponse xmlns:csn={ns}>
				<!--Optional:-->
				<csn:certificateSequence>
				</csn:certificateSequence>
				<csn:result>{result}</csn:result>
			</csn:GetCACertificatesResponse>
	
		var list = response.ns::certificateSequence;

		for (var i = 0; i < certlist.length; i++) {
			var cvc = certlist[i];
			list.ns::certificate += <cns:certificate xmlns:cns={ns}>{cvc.getBytes().toString(BASE64)}</cns:certificate>
		}
	} else {
		var response =
			<csn:GetCACertificatesResponse xmlns:csn={ns}>
				<csn:result>{result}</csn:result>
			</csn:GetCACertificatesResponse>
	}

	return response;
}



SPOCServicePort.prototype.RequestCertificate = function(soapBody) {
	print(soapBody.toXMLString());
	throw new Error("Not implemented");
}

SPOCServicePort.prototype.SendCertificatesRequest = function(soapBody) {

	var ns = new Namespace("http://namespaces.unmz.cz/csn369791");

	var callerID = soapBody.ns::callerID.toString();
	var statusInfo = soapBody.ns::statusInfo.toString();

	if (statusInfo == ServiceRequest.NEW_CERT_AVAILABLE_NOTIFICATION) {
		var sr = new ServiceRequest();
	} else {
		var msgid = soapBody.ns::messageID.toString();
		var sr = this.service.outqueuemap[msgid];
	}
	
	if (sr) {
		sr.setStatusInfo(statusInfo);
		var returnCode = ServiceRequest.OK_RECEIVED_CORRECTLY;

		if (statusInfo.substr(0, 3) == "ok_") {
			var certlist = [];
			GPSystem.trace("Received certificates from CVCA:");
			for each (var c in soapBody.ns::certificateSequence.ns::certificate) {
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

			this.service.cvca.importCertificates(certlist);
		}
		sr.setFinalStatusInfo(returnCode);
	} else {
		returnCode = ServiceRequest.FAILURE_MESSAGEID_UNKNOWN;
	}
	
	var response =
		<csn:SendCertificatesResponse xmlns:csn={ns}>
			<csn:result>{returnCode}</csn:result>
		</csn:SendCertificatesResponse>

	return response;
}
