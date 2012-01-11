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
 * @fileoverview A DVCA web service implementing TR-03129 service calls
 */



/**
 * Create a DVCA instance with web services
 *
 * @param {String} certstore the path to the certificate store or the certificate store itself
 * @param {String} path the PKI path for the domestic part of this service (e.g. "/UTCVCA/UTDVCA")
 * @param {String} parentURL the URL of the parent CA's webservice
 */ 
function DVCAService(certstore, path, parentURL) {
	BaseService.call(this);

	this.type = "DVCA";
	this.path = path;

	var pe = path.substr(1).split("/");
	assert(pe.length == 2);
	
	this.parent = pe[0];
	this.name = pe[1];
	
	this.parentURL = parentURL;
	
	if (typeof(certstore) == "string") {
		this.ss = new CVCertificateStore(certstore);
	} else {
		this.ss = certstore;
	}
	this.terminalCertificatePolicies = [];
	this.version = "1.1";
	this.rsaKeySize = 1536;
	this.namingscheme == DVCAService.CountryCodeAndSequence;
}

DVCAService.prototype = new BaseService();
DVCAService.constructor = DVCAService;

// The DVCA supports two different naming schemes for DVCA public key references using for foreign certifications.
DVCAService.MnemonicAndCountryCode = 1;		// Append the foreign country code to the holder mnemonic
DVCAService.CountryCodeAndSequence = 2;		// Place the country code in the first two digits of the sequence number (default)



// Configuration

/**
 * Sets the URL which is used to receive SendCertificate messages
 * 
 * @param {String} url
 */
DVCAService.prototype.setSendCertificateURL = function(url) {
	this.myURL = url;
}



/**
 * Sets the key size for certificate requests using RSA keys
 *
 * @param {Number} keysize the RSA key size i bits
 */
DVCAService.prototype.setRSAKeySize = function(keysize) {
	this.rsaKeySize = keysize;
}



/**
 * Sets the policy for issuing terminal certificates
 *
 * @param {Object} policy policy object as defined for CVCCA.prototype.generateCertificate()
 * @param {Regex} chrregex a regular expression that the CHR must match in order to use this rule
 */
DVCAService.prototype.setTerminalCertificatePolicy = function(policy, chrregex) {
	if (typeof(chrregex) != "undefined") {
		this.terminalCertificatePolicies.push( { regex: chrregex, policy: policy } );
	} else {
		this.terminalCertificatePolicy = policy;
	}
}



/**
 * Sets the naming scheme to by used when requesting foreign certificates.
 *
 * <p>With DVCAService.MnemonicAndCountryCode the country code of the foreign CVCA is appended to the holder mnemonic.</p>
 * <p>With DVCAService.CountryCodeAndSequence the country code is stored in the first two digits of the sequence number.</p>
 */
DVCAService.prototype.setNamingScheme = function(namingscheme) {
	this.namingscheme = namingscheme;
}



/**
 * Obtain a service port for TR-03129 service calls
 * 
 * @type Object
 * @return the service port that can be registered with the SOAP Server
 */
DVCAService.prototype.getTR3129ServicePort = function() {
	return new DVCATR3129ServicePort(this);
}



// Processing logic

/**
 * Determine if DVCA is operational for the given CVCA
 *
 * @type boolen
 * @return true if operational
 */
DVCAService.prototype.isOperational = function(cvca) {
	var cvcca = this.getCVCCA(cvca);
	return cvcca.isOperational();
}



/**
 * Gets the URL of the associated CVCA
 *
 * @type String
 * @return the URL or null or undefined
 */
DVCAService.prototype.getCVCAURL = function() {
	return this.parentURL;
}



/**
 * Returns a list of CVCAs supported by this DVCA. The domestic CVCA is always first in the list.
 *
 * @type String[]
 * @return the list of CVCA holderIDs
 */
DVCAService.prototype.getCVCAList = function() {
	var cvcas = [];
	cvcas.push(this.parent);
	var holders = this.ss.listHolders("/");
	for each (var holder in holders) {
		if (holder != this.parent) {
			cvcas.push(holder);
		}
	}
	return cvcas;
}



/**
 * Returns the path for a given CVCA
 *
 * @param {String} cvcaHolderId the holder ID of the requested CVCA
 * @type String
 * @return the path or null if no such CVCA known
 */
DVCAService.prototype.getPathFor = function(cvcaHolderId) {
	var name = this.name;
	
	if ((cvcaHolderId != this.parent) && (this.namingscheme == DVCAService.MnemonicAndCountryCode)) {
		name += cvcaHolderId.substr(0, 2);
	}

	return "/" + cvcaHolderId + "/" + name;
}



/**
 * Return a CVC-CA for the given path
 *
 * @param {String} path full path of the CVCCA instance
 * @type CVCCA
 * @return the CVCCA object
 */
DVCAService.prototype.getCVCCAForPath = function(path) {
	var cvcca = new CVCCA(this.ss.getCrypto(), this.ss, null, null, path);
	return cvcca;
}



/**
 * Return a CVC-CA associated with the given CVCA
 *
 * @param {String} cvcaHolderID the holderID of the supported CVCA
 * @type CVCCA
 * @return the CVCCA object
 */
DVCAService.prototype.getCVCCA = function(cvcaHolderID) {
	var path = this.getPathFor(cvcaHolderID);
	var cvcca = this.getCVCCAForPath(path);
	if ((cvcaHolderID != this.parent) && (this.namingscheme != DVCAService.MnemonicAndCountryCode)) {
		cvcca.setCountryCodeForSequence(cvcaHolderID.substr(0, 2));
	}
	return cvcca;
}



/**
 * Returns the path for a given DVCA public key reference based on the naming scheme
 *
 * @param {PublicKeyReference} chr the certificate holder reference
 * @type String
 * @return the path or null if no such DVCA known
 */
DVCAService.prototype.resolvePathForDVCA = function(chr) {
	var cvcas = this.getCVCAList();
	
	// Determine country based on naming scheme
	if (this.namingscheme == DVCAService.MnemonicAndCountryCode) {
		var country = chr.getHolder().substr(-2);
	} else {
		var country = chr.getSequenceNo().substr(0, 2);
	}
	
	// Locate CVCA for requested country
	for (var i = 1; i < cvcas.length; i++) {
		if (cvcas[i].substr(0, 2) == country) {
			break;
		}
	}
	
	// Country no found, assume domestic DVCA
	if (i >= cvcas.length) {
		i = 0;
	}
	
	return "/" + cvcas[i] + "/" + chr.getHolder();
}



/**
 * Returns the policy to apply for a given CHR
 *
 * @param {PublicKeyReference} chr the certificate holder reference
 * @returns a matching policy or the default policy
 * @type Object
 */
DVCAService.prototype.getTerminalCertificatePolicyForCHR = function(chr) {
	for (var i = 0; i < this.terminalCertificatePolicies.length; i++) {
		var p = this.terminalCertificatePolicies[i];
		if (chr.toString().match(p.regex)) {
			return p.policy;
		}
	}
	return this.terminalCertificatePolicy;
}



/**
 * Check certificate request parameter
 *
 * @param {ServiceRequest} sr the service request
 * @returns true if all checks passed or false and update in statusInfo
 * @type boolean
 */
DVCAService.prototype.checkRequestParameter = function(sr) {
	var req = sr.getCertificateRequest();

	var chr = req.getCAR();
	var path = this.path;
	
	if (chr) {
		var path = this.resolvePathForDVCA(chr);
		if (!path) {
			sr.addMessage("FAILED - Could not locate the DVCA requested in the inner CAR of the certificate request");
			sr.setStatusInfo(ServiceRequest.FAILURE_SYNTAX);
			return false;
		}
	} else {
		sr.addMessage("Info - Request without inner CAR routed to domestic DVCA instance");
	}
	
	// Check that request key algorithm matches the algorithm for the current certificate

	var chr = this.ss.getCurrentCHR(path);
	if (!chr) {
		sr.addMessage("Internal error - could not find current DVCA certficate");
		sr.setStatusInfo(ServiceRequest.FAILURE_INTERNAL_ERROR);
		return false;
	}
	
	var cvc = this.ss.getCertificate(path, chr);

	if (!cvc) {
		sr.addMessage("Internal error - could not find DVCA certficate with CHR " + chr);
		sr.setStatusInfo(ServiceRequest.FAILURE_INTERNAL_ERROR);
		return false;
	}

	var oid = cvc.getPublicKeyOID();
	var reqoid = req.getPublicKeyOID();
	
	if (!reqoid.equals(oid)) {
		sr.addMessage("FAILED - Public key algorithm " + reqoid.toString(OID) + " in request does not match current public key algorithm " + oid.toString(OID));
		sr.setStatusInfo(ServiceRequest.FAILURE_SYNTAX);
		return false;
	}
	sr.addMessage("Passed - Public key algorithm in request matches current public key algorithm of CA");
	
	if (CVC.isECDSA(oid)) {
		// Check that request key domain parameter match current domain parameter
		var dp = this.ss.getDomainParameter(path, chr);
	
		var puk = req.getPublicKey();

		if (!puk.getComponent(Key.ECC_P).equals(dp.getComponent(Key.ECC_P)) ||
			!puk.getComponent(Key.ECC_A).equals(dp.getComponent(Key.ECC_A)) ||
			!puk.getComponent(Key.ECC_B).equals(dp.getComponent(Key.ECC_B)) ||
			!puk.getComponent(Key.ECC_GX).equals(dp.getComponent(Key.ECC_GX)) ||
			!puk.getComponent(Key.ECC_GY).equals(dp.getComponent(Key.ECC_GY)) ||
			!puk.getComponent(Key.ECC_N).equals(dp.getComponent(Key.ECC_N)) ||
			!puk.getComponent(Key.ECC_H).equals(dp.getComponent(Key.ECC_H))) {
			sr.addMessage("FAILED - Public key domain parameter in request do not match current domain parameter used by CA");
			sr.setStatusInfo(ServiceRequest.FAILURE_DOMAIN_PARAMETER);
		return false;
		}
		sr.addMessage("Passed - Public key domain parameters match current domain parameters used by CA");
	}
	return true;
}



/**
 * Check certificate request outer signature
 *
 * <p>The method first determines the certificate that verifies the outer signature.
 *    This is either a previously issued certificate for this entity or a CVCA
 *    certificate if it is a countersigned request.</p>
 *
 * @param {ServiceRequest} sr the service request
 * @returns true if all checks passed or false and update in statusInfo
 * @type boolean
 */
DVCAService.prototype.checkRequestOuterSignature = function(sr) {
	var req = sr.getCertificateRequest();

	if (!req.isAuthenticatedRequest()) {
		return true;
	}
	
	var chr = req.getCAR();
	var path = this.path;
	
	if (chr) {
		var path = this.resolvePathForDVCA(chr);
	}
	path += "/" + req.getCHR().getHolder();
	
	var outerCAR = req.getOuterCAR();
	
	var cvc = this.ss.getCertificate(path, outerCAR);
	
	if (!cvc) {
		sr.addMessage("FAILED - Could not locate certificate " + outerCAR + " issued by " + path + " to verify outer signature");
		sr.setStatusInfo(ServiceRequest.FAILURE_OUTER_SIGNATURE);
		return false;
	}
		
	if (CVC.isECDSA(cvc.getPublicKeyOID())) {
		var dp = this.ss.getDomainParameter(path, outerCAR);
	} else {
		var dp = null;
	}
		
	if (!req.verifyATWith(this.crypto, cvc.getPublicKey(dp), cvc.getPublicKeyOID())) {
		sr.addMessage("FAILED - Outer signature invalid or content tampered");
		sr.setStatusInfo(ServiceRequest.FAILURE_OUTER_SIGNATURE);
		return false;
	}
	sr.addMessage("Passed - Outer signature provided by " + outerCAR + " is valid");
		
	var now = new Date();
	now.setHours(12, 0, 0, 0);
	if (now.valueOf() > cvc.getCXD().valueOf()) {
		sr.addMessage("FAILED - Certificate " + outerCAR +" for verification of outer signature is expired");
		sr.setStatusInfo(ServiceRequest.FAILURE_EXPIRED);
		return false;
	}

	return true;
}



/**
 * Check certificate request semantic
 *
 * @param {ServiceRequest} sr the service request
 * @returns true if all checks passed or false and update in statusInfo
 * @type boolean
 */
DVCAService.prototype.checkRequestSemantics = function(sr) {
	
	if (!this.checkRequestInnerSignature(sr)) {
		return false;
	}
	
	if (!this.checkRequestParameter(sr)) {
		return false;
	}
	
	if (!this.checkRequestOuterSignature(sr)) {
		return false;
	}

	sr.setStatusInfo(ServiceRequest.OK_SYNTAX);
	return true;
}



/**
 * Check certificate request against policy
 *
 * @param {ServiceRequest} sr the service request
 * @returns true if all checks passed or false and update in statusInfo
 * @param {Boolean} callback the indicator if a call-back is possible
 * @returns true if request is approved based on policy
 * @type String
 */
DVCAService.prototype.checkPolicy = function(sr, callback) {

	var req = sr.getCertificateRequest();
	
	var policy = this.getTerminalCertificatePolicyForCHR(req.getCHR());
	
	if ((sr.getStatusInfo() == ServiceRequest.FAILURE_EXPIRED) && !policy.declineExpiredAuthenticatedRequest) {
		sr.addMessage("Overwrite - Expired certificate for outer signature accepted due to policy overwrite");
		sr.setStatusInfo(ServiceRequest.OK_SYNTAX);
	}

	if (sr.getStatusInfo() != ServiceRequest.OK_SYNTAX) {
		return false;
	}
	
	if (req.isAuthenticatedRequest()) {
		if (req.isCountersignedRequest()) {
			if (policy.countersignedRequestsApproved) {
				sr.addMessage("Overwrite - Countersigned request automatically approved by policy");
				sr.setStatusInfo(ServiceRequest.OK_CERT_AVAILABLE);
				return true;
			}
		} else {
			if (policy.authenticatedRequestsApproved) {
				sr.addMessage("Overwrite - Authenticated request automatically approved by policy");
				sr.setStatusInfo(ServiceRequest.OK_CERT_AVAILABLE);
				return true;
			}
		}
	} else {
		if (policy.initialRequestsApproved) {
			sr.addMessage("Overwrite - Initial request approved automatically approved by policy");
			sr.setStatusInfo(ServiceRequest.OK_CERT_AVAILABLE);
			return true;
		}
	}
	
	if (!callback) {
		sr.addMessage("FAILED - No callback available and request can not be completed synchronously");
		sr.setStatusInfo(ServiceRequest.FAILURE_SYNCHRONOUS_PROCESSING_NOT_POSSIBLE);
	}
	
	return false;
}



/**
 * Issue certificate for subordinate terminal
 *
 * @param {CVC} req the request
 * @returns the certificate and the list of missing certificates unless the CAR in the request matches the current CHR of the CA
 * @type CVC
 */
DVCAService.prototype.issueCertificate = function(req) {

	var policy = this.getTerminalCertificatePolicyForCHR(req.getCHR());

	var car = req.getCAR();
	var path = this.path;
	
	if (car) {
		var path = this.resolvePathForDVCA(car);
	}

	var cvcca = this.getCVCCAForPath(path);
	if (!cvcca.isOperational()) {
		throw new GPError("DVCAService", GPError.INVALID_DATA, 0, "DVCA is not operational");
	}
	
	var cert = cvcca.generateCertificate(req, policy);

	cvcca.storeCertificate(cert);

	var certlist = [];
	
	var chr = this.ss.getCurrentCHR(path);

	if ((car == null) || !car.equals(chr)) {
		certlist = this.getCACertificateList();
	}
	
	certlist.push(cert);
	return certlist;
}



/**
 * Return the current certificate list for the DVCA instance related to the requested CVCA
 *
 * @type CVC[]
 * @return the list of CV certificates from the self-signed root to the DV
 */
DVCAService.prototype.getCACertificateList = function() {
	var cvcas = this.getCVCAList();
	var certlist = [];
	for each (var cvca in cvcas) {
		var cvcca = this.getCVCCA(cvca);
		if (cvcca.isOperational()) {
			certlist = certlist.concat(cvcca.getCertificateList());
		}
	}
	return certlist;
}



// UI Interface operations

/**
 * Return the current certificate list for the DVCA instance related to the requested CVCA
 *
 * @param {String} cvcaHolderId holder ID of the CVCA in question
 * @type CVC[]
 * @return the list of CV certificates from the self-signed root to the DV
 */
DVCAService.prototype.getCertificateList = function(cvcaHolderId) {
	var cvcca = this.getCVCCA(cvcaHolderId);
	return cvcca.getCertificateList();
}



/**
 * Process request and send certificates
 *
 * @param {Number} index the index into the work queue identifying the request
 */
DVCAService.prototype.processRequest = function(index) {
	var sr = this.getInboundRequest(index);

	if (sr.isCertificateRequest()) {		// RequestCertificate
		if (sr.getStatusInfo() == ServiceRequest.OK_CERT_AVAILABLE) {
			var req = sr.getCertificateRequest();
			
			sr.addMessage("Starting secondary check");
			if (this.checkRequestSemantics(sr)) {		// Still valid
				var certlist = this.issueCertificate(req);
				sr.setCertificateList(certlist);
			} else {
				GPSystem.trace("Request " + req + " failed secondary check");
			}
		}
	} else {								// GetCertificates
		if (sr.getStatusInfo().substr(0, 3) == "ok_") {
			sr.setCertificateList(this.getCACertificateList());
		}
	}

	this.sendCertificates(sr);
	
	return sr.getFinalStatusInfo();
}



/**
 * Process list of certificates received from CVCA
 *
 * @param {ServiceRequest} sr the service request
 * @param {ByteString[]} list the certificate list
 * @type String
 * @return The return code received from the other side
 */
DVCAService.prototype.processCertificateList = function(sr, list) {
	var certlist = [];
	
	if (list) {
		for (var i = 0; i < list.length; i++) {
			var cvc = new CVC(list[i]);
			certlist.push(cvc);
			GPSystem.trace(cvc);
		}
		sr.setCertificateList(certlist);
	}

	var list = this.ss.insertCertificates2(this.crypto, certlist, true, this.path);

	if (list.length > 0) {
		var str = "Warning: Could not import the following certificates:\n";
		for (var i = 0; i < list.length; i++) {
			str += list[i].toString() + "\n";
		}
		sr.addMessage(str);
	}
}



/**
 * Update certificate list from parent CA
 *
 * @type String
 * @return The return code received from the other side
 */
DVCAService.prototype.updateCACertificates = function(async) {

	var msgid = null;
	
	if (async) {
		msgid = this.newMessageID();
	}

	var sr = new ServiceRequest(msgid, this.myURL);
	sr.setType(ServiceRequest.DVCA_GET_CA_CERTIFICATES);
	this.addOutboundRequest(sr);

	var con = new TAConnection(this.parentURL, true);
	
	if (async) {
		var list = con.getCACertificates(sr.getMessageID(), sr.getResponseURL());
	} else {
		var list = con.getCACertificates();
	}

	con.close();

	sr.setStatusInfo(con.getLastReturnCode());
	
	this.processCertificateList(sr, list);
	
	return sr.getStatusInfo();
}



/**
 * Renew certificate through parent or foreign CA (GUI call)
 *
 * @param {boolean} async true to process call asynchronously
 * @param {boolean} forceinitial force request to be an initial request
 * @param {String} cvca the holderID of the CVCA the request shall be directed at
 * @type String
 * @return The return code received from the other side
 */
DVCAService.prototype.renewCertificate = function(async, forceinitial, cvca) {

	var path = this.getPathFor(cvca);
	assert(path != null);
	
	var algo = this.ss.getDefaultPublicKeyOID(path);
	if (CVC.isECDSA(algo)) {
		var keyspec = this.ss.getDefaultDomainParameter(path);
	} else {
		var keyspec = new Key();
		keyspec.setType(Key.PUBLIC);
		keyspec.setSize(this.rsaKeySize);
	}
	
	var car = this.ss.getCurrentCHR(CVCertificateStore.parentPathOf(path));

	var cvcca = this.getCVCCA(cvca);
	
	cvcca.setKeySpec(keyspec, algo);
	
	// Create a new request
	var req = cvcca.generateRequest(car, forceinitial);
	print("Request: " + req);
	print(req.getASN1());

	var msgid = null;

	if (async) {
		msgid = this.newMessageID();
	}

	var sr = new ServiceRequest(msgid, this.myURL, req);
	sr.setType(ServiceRequest.DVCA_REQUEST_CERTIFICATE);
	this.addOutboundRequest(sr);

	if (this.parentURL) {
		if (cvcca.parentId == this.parent) {
			var list = this.requestCertificateFromCVCA(sr);
		} else {
			sr.setForeignCAR(car.toString());
			var list = this.requestCertificateFromForeignCVCA(sr);
		}

		this.processCertificateList(sr, list);
	} else {
		sr.setStatusInfo("Local request");
	}
	
	return sr.getStatusInfo();
}



/**
 * Handle a manually submitted certificate request
 *
 * @param {String} forCVCA the CVCA holder id this request is directed at
 * @param {ByteString} req the binary certicate request
 * @type String
 * @return the result processing the request
 */
DVCAService.prototype.processUploadedCertificateRequest = function(forCVCA, req) {
	var sr = new ServiceRequest();
	
	sr.setType(ServiceRequest.TERM_REQUEST_CERTIFICATE);
	sr.setRawCertificateRequest(req);
	
	this.processRequestCertificate(sr, true);
	return sr.getStatusInfo();
}



/**
 * Handle a manually submitted certificate
 *
 * @param {String} forCVCA the CVCA holder id this certificate is most likely for
 * @param {ByteString} cert the binary certicate
 * @type String
 * @return the result processing the request
 */
DVCAService.prototype.processUploadedCertificate = function(forCVCA, cert) {
	var sr = new ServiceRequest();
	sr.setType(ServiceRequest.CVCA_SEND_CERTIFICATE);
	this.addInboundRequest(sr);
	
	try	{
		var cvc = new CVC(cert);
	}
	catch(e) {
		GPSystem.trace("Error decoding certificate: " + e);
		sr.addMessage("Error decoding certificate: " + e);
		sr.setStatusInfo(ServiceRequest.FAILURE_SYNTAX);
		return sr.getStatusInfo();
	}

	var certlist = [cvc];
	sr.setCertificateList(certlist);
	var cvcca = this.getCVCCA(forCVCA);
	var unprocessed = cvcca.importCertificates(certlist);		// Store locally
	if (unprocessed.length > 0) {
		sr.addMessage("FAILED - The following certificates could not be processed:");
		for each (var cvc in unprocessed) {
			sr.addMessage(cvc.toString());
		}
	}
	
	sr.setStatusInfo(ServiceRequest.OK);
	return sr.getStatusInfo();
}



// Outbound webservices

/**
 * Send certificates using a webservice call
 *
 * @param {ServiceRequest} serviceRequest the underlying request
 */
DVCAService.prototype.sendCertificates = function(serviceRequest) {
	if (serviceRequest.getResponseURL()) {
		var con = new TAConnection(serviceRequest.getResponseURL(), true);
		con.version = this.version;
		var list = TAConnection.fromCVCList(serviceRequest.getCertificateList());
		var result = con.sendCertificates(list, serviceRequest.getMessageID(), serviceRequest.getStatusInfo());
		serviceRequest.setSOAPRequest(con.getLastRequest());
		serviceRequest.setSOAPResponse(con.getLastResponse());
		serviceRequest.setFinalStatusInfo(result);
	} else {
		serviceRequest.addMessage("Could not send certificate due to missing response URL");
	}
	
	serviceRequest.addMessage("Completed");
}



/**
 * Request a certificate from the parent CA using a web service
 *
 * @param {ServiceRequest} serviceRequest the underlying request
 * @returns the new certificates
 * @type ByteString[]
 */
DVCAService.prototype.requestCertificateFromCVCA = function(sr) {
	var con = new TAConnection(this.parentURL, true);
	
	if (sr.getMessageID()) {
		var certlist = con.requestCertificate(sr.getCertificateRequest().getBytes(), sr.getMessageID(), sr.getResponseURL());
	} else {
		var certlist = con.requestCertificate(sr.getCertificateRequest().getBytes());
	}

	sr.setSOAPRequest(con.getLastRequest());
	sr.setSOAPResponse(con.getLastResponse());

	con.close();

	sr.setStatusInfo(con.getLastReturnCode());
	print(con.getLastReturnCode());
	return certlist;
}



/**
 * Request a certificate from a foreign CA using a web service
 *
 * @param {ServiceRequest} serviceRequest the underlying request
 * @returns the new certificates
 * @type ByteString[]
 */
DVCAService.prototype.requestCertificateFromForeignCVCA = function(sr) {
	var con = new TAConnection(this.parentURL, true);
	
	if (sr.getMessageID()) {
		var certlist = con.requestForeignCertificate(sr.getCertificateRequest().getBytes(), sr.getForeignCAR(), sr.getMessageID(), sr.getResponseURL());
	} else {
		var certlist = con.requestForeignCertificate(sr.getCertificateRequest().getBytes(), sr.getForeignCAR());
	}

	sr.setSOAPRequest(con.getLastRequest());
	sr.setSOAPResponse(con.getLastResponse());

	con.close();

	sr.setStatusInfo(con.getLastReturnCode());
	print(con.getLastReturnCode());
	return certlist;
}



// Inbound Webservices

// ---- WebService handling ---------------------------------------------------

/**
 * Process a request from a terminal to return current CA certificates
 *
 * @param {ServiceRequest} sr the service request
 * @param {boolean} callback true if callback is possible
 */
DVCAService.prototype.processGetCACertificates = function(sr, callback) {

	this.addInboundRequest(sr);

	if (callback) {
		sr.setStatusInfo(ServiceRequest.OK_SYNTAX);
	} else {
		sr.setCertificateList(this.getCACertificateList());
		sr.setStatusInfo(ServiceRequest.OK_CERT_AVAILABLE);
	}
}



/**
 * Process a request to issue a terminal certificate
 *
 * @param {ServiceRequest} sr the service request
 * @param {boolean} callback true if callback is possible
 */
DVCAService.prototype.processRequestCertificate = function(sr, callback) {

	this.addInboundRequest(sr);

	var req = this.checkRequestSyntax(sr.getRawCertificateRequest());
	if (!req) {
		sr.setStatusInfo(ServiceRequest.FAILURE_SYNTAX);
		sr.setMessage("Certificate request is not a valid ASN.1 structure: " + sr.getRawCertificateRequest().toString(HEX));
		return;
	}
	
	sr.setCertificateRequest(req);

	GPSystem.trace("DVCAService - Received certificate request: ");
	GPSystem.trace(req);

	// Check basic semantics of request
	this.checkRequestSemantics(sr);
	if (this.checkPolicy(sr, callback)) {						// Synchronous processing approved by policy ?
		var certlist = this.issueCertificate(req);
		sr.setCertificateList(certlist);
		sr.setFinalStatusInfo(sr.getStatusInfo());		// Nothing else will happen
		sr.addMessage("Completed");
	}
}



// ---- TR-03129 Service ------------------------------------------------------

/**
 * The TR-03129 Service port class
 * 
 * <p>See BSI-TR-03129 at www.bsi.bund.de for the specification of the DVCA web service</p>
 */
function DVCATR3129ServicePort(service) {
	this.service = service;
	this.version = "1.1";
}



/**
 * Compile the response message using the returnCode and certificate list from the completed service request
 *
 * @param {String} type the response type name
 * @param {ServiceRequest} sr the completed service request
 * @type XML
 * @return the complete SOAP response body
 */
DVCATR3129ServicePort.prototype.generateResponse = function(type, sr) {
	var ns = new Namespace("uri:EAC-PKI-DV-Protocol/" + this.version);
	var ns1 = new Namespace("uri:eacBT/" + this.version);

	var certlist = sr.getCertificateList();
	if (certlist && (certlist.length > 0)) {
		var response =
			<ns:{type} xmlns:ns={ns} xmlns:ns1={ns1}>
				<Result>
					<ns1:returnCode>{sr.getStatusInfo()}</ns1:returnCode>
					<!--Optional:-->
					<ns1:certificateSeq>
						<!--Zero or more repetitions:-->
					</ns1:certificateSeq>
				</Result>
			</ns:{type}>
		
		var list = response.Result.ns1::certificateSeq;

		for each (var cvc in certlist) {
			list.certificate += <ns1:certificate xmlns:ns1={ns1}>{cvc.getBytes().toString(BASE64)}</ns1:certificate>
		}
	} else {
		var response =
			<ns:{type} xmlns:ns={ns} xmlns:ns1={ns1}>
				<Result>
					<ns1:returnCode>{sr.getStatusInfo()}</ns1:returnCode>
				</Result>
			</ns:{type}>
	}
	return response;
}



/**
 * Implements GetCACertificates from TR-03129, chapter 4.2.3
 *
 * <p>Either respond synchronously with all known certificate chains or schedule an asychronous response</p>
 *
 * @param {XML} soapBody the SOAP request body
 * @type XML
 * @return the SOAP response body
 */
DVCATR3129ServicePort.prototype.GetCACertificates = function(soapBody) {
	var ns = new Namespace("uri:EAC-PKI-DV-Protocol/" + this.version);
	var ns1 = new Namespace("uri:eacBT/" + this.version);

	var messageID = soapBody.messageID.ns1::messageID;
	var sr = new ServiceRequest(messageID);
	sr.setType(ServiceRequest.TERM_GET_CA_CERTIFICATES);
	sr.setSOAPRequest(soapBody);

	var callback = soapBody.callbackIndicator.toString() == "callback_possible";
	if (callback) {
		sr.setResponseURL(soapBody.responseURL.ns1::string.toString());
	}

	this.service.processGetCACertificates(sr, callback);

	var response = this.generateResponse("GetCACertificatesResponse", sr);
	
	sr.setSOAPResponse(response);
	return response;
}



/**
 * Implements RequestCertificates from TR-03129, chapter 4.2.1
 *
 * <p>Check request and either respond with new certificate or schedule an asychronous response</p>
 *
 * @param {XML} soapBody the SOAP request body
 * @type XML
 * @return the SOAP response body
 */
DVCATR3129ServicePort.prototype.RequestCertificate = function(soapBody) {
	var ns = new Namespace("uri:EAC-PKI-DV-Protocol/" + this.version);
	var ns1 = new Namespace("uri:eacBT/" + this.version);

	var messageID = soapBody.messageID.ns1::messageID;
	var sr = new ServiceRequest(messageID);
	sr.setType(ServiceRequest.TERM_REQUEST_CERTIFICATE);
	sr.setSOAPRequest(soapBody);

	sr.setRawCertificateRequest(new ByteString(soapBody.certReq, BASE64));
	
	var callback = soapBody.callbackIndicator.toString() == "callback_possible";
	if (callback) {
		sr.setResponseURL(soapBody.responseURL.ns1::string.toString());
	}

	this.service.processRequestCertificate(sr, callback);

	var response = this.generateResponse("RequestCertificateResponse", sr);

	sr.setSOAPResponse(response);
	return response;
}



/**
 * Implements RequestCertificates from TR-03129, chapter 4.2.1
 *
 * <p>Check request and either respond with new certificate or schedule an asychronous response</p>
 *
 * @param {XML} soapBody the SOAP request body
 * @type XML
 * @return the SOAP response body
 */
DVCATR3129ServicePort.prototype.SendCertificates = function(soapBody) {
	
	var ns = new Namespace("uri:EAC-PKI-DV-Protocol/" + this.version);
	var ns1 = new Namespace("uri:eacBT/" + this.version);

	var statusInfo = soapBody.statusInfo.toString();

	if (this.version == "1.0") {
		var msgid = soapBody.messageID.toString();
	} else {
		var msgid = soapBody.messageID.ns1::messageID.toString();
	}
	
	if (msgid == "Synchronous") {		// Special handling for posts from the command line
		var sr = new ServiceRequest();
		sr.setType(ServiceRequest.CVCA_SEND_CERTIFICATE);
		this.service.addInboundRequest(sr);
	} else {
		var sr = this.service.getOutboundRequestByMessageId(msgid);
	}
	
	if (sr) {
		sr.setStatusInfo(statusInfo);
		var returnCode = ServiceRequest.OK_RECEIVED_CORRECTLY;

		if (statusInfo.substr(0, 3) == "ok_") {
			var certlist = [];
			GPSystem.trace("Received certificates from CVCA:");
			for each (var c in soapBody.certificateSeq.ns1::certificate) {
				try	{
					var cvc = new ByteString(c, BASE64);
				}
				catch(e) {
					GPSystem.trace("Error decoding certificate: " + e);
					var returnCode = ServiceRequest.FAILURE_SYNTAX;
					break;
				}
				certlist.push(cvc);
				GPSystem.trace(cvc);
			}

			this.service.processCertificateList(sr, certlist);
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
 * Return the WSDL and referenced XSD structures
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 */
DVCATR3129ServicePort.prototype.GetWSDL = function(req, res) {
	switch(req.queryString) {
	case "wsdl":
		var xml = 
		<definitions
			name="EAC-PKI-DV"
			targetNamespace="uri:EAC-PKI-DV-Protocol/1.1"
			xmlns:tns="uri:EAC-PKI-DV-Protocol/1.1"

			xmlns:ns="uri:eacBT/1.1"

			xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
			xsi:schemaLocation="http://schemas.xmlsoap.org/wsdl/ http://schemas.xmlsoap.org/wsdl/2003-02-11.xsd"

			xmlns:xsd="http://www.w3.org/2001/XMLSchema"
			xmlns:SOAP="http://schemas.xmlsoap.org/wsdl/soap/"
			xmlns="http://schemas.xmlsoap.org/wsdl/"
		>

			<types>
				<schema xmlns="http://www.w3.org/2001/XMLSchema">
					<import namespace="http://www.w3.org/2001/XMLSchema"/>
					<import namespace="uri:eacBT/1.0" schemaLocation="dvca?xsd=./BasicTypes_DV_TerminalAuth.xsd"/>
				</schema> 
			</types>
	
			<!-- Definition of the messages of the protocol -->
			<!-- message RequestCertificate -->
			<message name="RequestCertificate_Req">
				<part name="callbackIndicator" type="ns:CallbackIndicatorType"/>
				<part name="messageID" type="ns:OptionalMessageIDType"/>
				<part name="responseURL" type="ns:OptionalStringType"/>
				<part name="certReq" type="xsd:base64Binary"/>
			</message>
			<message name="RequestCertificate_Res">
				<part name="Result" type="ns:RequestCertificateResult"/>
			</message>
			<!-- message GetCACertificates -->
			<message name="GetCACertificates_Req">
				<part name="callbackIndicator" type="ns:CallbackIndicatorType"/>		
				<part name="messageID" type="ns:OptionalMessageIDType"/>
				<part name="responseURL" type="ns:OptionalStringType"/>
			</message>
			<message name="GetCACertificates_Res">
				<part name="Result" type="ns:GetCACertificatesResult"/>
			</message>
			<!-- message SendCertificates -->
			<message name="SendCertificates_Req">
				<part name="messageID" type="ns:OptionalMessageIDType"/>
				<part name="statusInfo" type="ns:SendCertificates_statusInfoType"/>
				<part name="certificateSeq" type="ns:CertificateSeqType"/>
			</message>
			<message name="SendCertificates_Res">
				<part name="Result" type="ns:SendCertificatesResult"/>
			</message>

			<!-- Definition of the port types -->
			<portType name="EAC-PKI-DV-ProtocolType">
				<!-- port type for message RequestCertificate -->
				<operation name="RequestCertificate">
					<input message="tns:RequestCertificate_Req"/>
					<output message="tns:RequestCertificate_Res"/>
				</operation>
				<!-- port type for message GetCACertificates -->
				<operation name="GetCACertificates">
					<input message="tns:GetCACertificates_Req"/>
					<output message="tns:GetCACertificates_Res"/>
				</operation>
				<!-- port type for message SendCertificates -->
				<operation name="SendCertificates">
					<input message="tns:SendCertificates_Req"/>
					<output message="tns:SendCertificates_Res"/>
				</operation>
			</portType>

			<!-- Definition of the bindings -->
			<binding name="EAC-DV" type="tns:EAC-PKI-DV-ProtocolType">
				<SOAP:binding style="rpc" transport="http://schemas.xmlsoap.org/soap/http"/>
				<operation name="RequestCertificate">
					<SOAP:operation style="rpc" soapAction=""/>
					<input>
						<SOAP:body use="literal" namespace="uri:EAC-PKI-DV-Protocol/1.1" encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"/>
					</input>
					<output>
						<SOAP:body use="literal" namespace="uri:EAC-PKI-DV-Protocol/1.1" encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"/>
					</output>
				</operation>
				<operation name="GetCACertificates">
					<SOAP:operation style="rpc" soapAction=""/>
					<input>
						<SOAP:body use="literal" namespace="uri:EAC-PKI-DV-Protocol/1.1" encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"/>
					</input>
					<output>
						<SOAP:body use="literal" namespace="uri:EAC-PKI-DV-Protocol/1.1" encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"/>
					</output>
				</operation>
				<operation name="SendCertificates">
					<SOAP:operation style="rpc" soapAction=""/>
					<input>
						<SOAP:body use="literal" namespace="uri:EAC-PKI-DV-Protocol/1.1" encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"/>
					</input>
					<output>
						<SOAP:body use="literal" namespace="uri:EAC-PKI-DV-Protocol/1.1" encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"/>
					</output>
				</operation>		
			</binding>
		</definitions>

		break;

	case "xsd=./BasicTypes_DV_TerminalAuth.xsd":
		var xml =
		<xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:nsBT="uri:eacBT/1.1" targetNamespace="uri:eacBT/1.1" elementFormDefault="qualified">
			<!-- this scheme is based on the document 
			PKIs for Machine Readable Travel Documents - Protocols for the Management of Certififcates and CRLs
			Version 1.1, Date 30.06.2010
			-->
			<!-- Definition of the type for a message ID -->
			<xsd:simpleType name="MessageIDType">
				<xsd:restriction base="xsd:string"/>
			</xsd:simpleType>
			<!-- Definition of the type for a callbackIndicator -->
			<xsd:simpleType name="CallbackIndicatorType">
				<xsd:restriction base="xsd:string">
					<xsd:enumeration value="callback_possible"/>
					<xsd:enumeration value="callback_not_possible"/>
				</xsd:restriction>
			</xsd:simpleType>
			<!-- Definition of the type of an optional messageID parameter -->
			<xsd:complexType name="OptionalMessageIDType">
				<xsd:sequence>
					<xsd:element name="messageID" type="nsBT:MessageIDType" minOccurs="0"/>
				</xsd:sequence>
			</xsd:complexType>
			<!-- Definition of the type of an optional string parameter -->
			<xsd:complexType name="OptionalStringType">
				<xsd:sequence>
					<xsd:element name="string" type="xsd:string" minOccurs="0"/>
				</xsd:sequence>
			</xsd:complexType>
			<!-- Definition of the complex type for a sequence of certificates -->
			<xsd:complexType name="CertificateSeqType">
				<xsd:sequence>
					<xsd:element name="certificate" type="xsd:base64Binary" minOccurs="0" maxOccurs="unbounded"/>
				</xsd:sequence>
			</xsd:complexType>
			<!-- Definition of the types of the status codes for the messages SendCertificates -->
			<xsd:simpleType name="SendCertificates_statusInfoType">
				<xsd:restriction base="xsd:string">
					<xsd:enumeration value="ok_cert_available"/>
					<xsd:enumeration value="failure_inner_signature"/>
					<xsd:enumeration value="failure_outer_signature"/>
					<xsd:enumeration value="failure_expired"/>
					<xsd:enumeration value="failure_domain_parameters"/>
					<xsd:enumeration value="failure_request_not_accepted"/>
					<xsd:enumeration value="failure_foreignCAR_unknown"/>
					<xsd:enumeration value="failure_not_forwarded"/>
					<xsd:enumeration value="failure_request_not_accepted_foreign"/>
					<xsd:enumeration value="failure_syntax"/>
					<xsd:enumeration value="failure_internal_error"/>
				</xsd:restriction>
			</xsd:simpleType>

			<!-- ==================== -->
			<!-- Definition of the types of the return codes for the different messages -->
			<xsd:simpleType name="RequestCertificate_returnCodeType">
				<xsd:restriction base="xsd:string">
					<xsd:enumeration value="ok_cert_available"/>
					<xsd:enumeration value="ok_syntax"/>
					<xsd:enumeration value="ok_reception_ack"/>
					<xsd:enumeration value="failure_inner_signature"/>
					<xsd:enumeration value="failure_outer_signature"/>
					<xsd:enumeration value="failure_expired"/>
					<xsd:enumeration value="failure_domain_parameters"/>
					<xsd:enumeration value="failure_request_not_accepted"/>
					<xsd:enumeration value="failure_syntax"/>
					<xsd:enumeration value="failure_synchronous_processing_not_possible"/>
					<xsd:enumeration value="failure_internal_error"/>
				</xsd:restriction>
			</xsd:simpleType>
			<xsd:simpleType name="GetCACertificates_returnCodeType">
				<xsd:restriction base="xsd:string">
					<xsd:enumeration value="ok_cert_available"/>
					<xsd:enumeration value="ok_syntax"/>
					<xsd:enumeration value="ok_reception_ack"/>
					<xsd:enumeration value="failure_syntax"/>
					<xsd:enumeration value="failure_request_not_accepted"/>
					<xsd:enumeration value="failure_synchronous_processing_not_possible"/>
					<xsd:enumeration value="failure_internal_error"/>
				</xsd:restriction>
			</xsd:simpleType>
			<xsd:simpleType name="SendCertificates_returnCodeType">
				<xsd:restriction base="xsd:string">
					<xsd:enumeration value="ok_received_correctly"/>
					<xsd:enumeration value="failure_syntax"/>
					<xsd:enumeration value="failure_messageID_unknown"/>
					<xsd:enumeration value="failure_internal_error"/>
				</xsd:restriction>
			</xsd:simpleType>

			<!-- ==================== -->
			<!-- Definition of the types of the result for the different messages -->
			<xsd:complexType name="RequestCertificateResult">
				<xsd:sequence>
					<xsd:element name="returnCode" type="nsBT:RequestCertificate_returnCodeType"/>
					<xsd:element name="certificateSeq" type="nsBT:CertificateSeqType" minOccurs="0"/>
				</xsd:sequence>
			</xsd:complexType>
			<xsd:complexType name="GetCACertificatesResult">
				<xsd:sequence>
					<xsd:element name="returnCode" type="nsBT:GetCACertificates_returnCodeType"/>
					<xsd:element name="certificateSeq" type="nsBT:CertificateSeqType" minOccurs="0"/>
				</xsd:sequence>
			</xsd:complexType>
			<xsd:complexType name="SendCertificatesResult">
				<xsd:sequence>
					<xsd:element name="returnCode" type="nsBT:SendCertificates_returnCodeType"/>
				</xsd:sequence>
			</xsd:complexType>
		</xsd:schema>
		
		break;
	default:
		throw new GPError("DVCAService", GPError.INVALID_DATA, 0, "Unknown WSDL artifact " + req.queryString);
	}
	
	res.setContentType("text/xml; charset=utf-8");
	res.println(xml.toXMLString());
}

