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
 * @fileoverview A CVCA web service implementing TR-03129 and CSN_369791
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
	BaseService.call(this);

	this.name = name;
	this.type = "CVCA";

	this.ss = new CVCertificateStore(path);
	this.cvca = new CVCCA(this.crypto, this.ss, name, name);
	this.path = this.cvca.path;
	this.dVCertificatePolicies = [];
	this.version = "1.1";
	this.changeKeySpecification("brainpoolP256r1withSHA256");
	this.spoclist = [];
	this.spocmap = [];
}

CVCAService.prototype = new BaseService();
CVCAService.constructor = CVCAService;


CVCAService.KeySpecification = [
	{ id: "brainpoolP192r1withSHA1", name: "brainpoolP192r1 with SHA-1", oid: CVC.id_TA_ECDSA_SHA_1, curve: new ByteString("brainpoolP192r1", OID), keysize: 0 },
	{ id: "brainpoolP224r1withSHA224", name: "brainpoolP224r1 with SHA-224", oid: CVC.id_TA_ECDSA_SHA_224, curve: new ByteString("brainpoolP224r1", OID), keysize: 0 },
	{ id: "brainpoolP256r1withSHA256", name: "brainpoolP256r1 with SHA-256", oid: CVC.id_TA_ECDSA_SHA_256, curve: new ByteString("brainpoolP256r1", OID), keysize: 0 },
	{ id: "brainpoolP384r1withSHA384", name: "brainpoolP384r1 with SHA-384", oid: CVC.id_TA_ECDSA_SHA_384, curve: new ByteString("brainpoolP384r1", OID), keysize: 0 },
	{ id: "brainpoolP512r1withSHA512", name: "brainpoolP512r1 with SHA-512", oid: CVC.id_TA_ECDSA_SHA_512, curve: new ByteString("brainpoolP512r1", OID), keysize: 0 },
	{ id: "RSA2048V15withSHA1", name: "RSA 2048 PKCS#1 V1.5 with SHA-1", oid: CVC.id_TA_RSA_v1_5_SHA_1, curve: null, keysize: 2048 },
	{ id: "RSA2048V15withSHA256", name: "RSA 2048 PKCS#1 V1.5 with SHA-256", oid: CVC.id_TA_RSA_v1_5_SHA_256, curve: null, keysize: 2048 },
//	{ id: "RSA2048V15withSHA512", name: "RSA 2048 PKCS#1 V1.5 with SHA-512", oid: CVC.id_TA_RSA_v1_5_SHA_512, curve: null, keysize: 2048 },
	{ id: "RSA2048PSSwithSHA1", name: "RSA 2048 PSS with SHA-1", oid: CVC.id_TA_RSA_PSS_SHA_1, curve: null, keysize: 2048 },
	{ id: "RSA2048PSSwithSHA256", name: "RSA 2048 PSS with SHA-256", oid: CVC.id_TA_RSA_PSS_SHA_256, curve: null, keysize: 2048 }
//	{ id: "RSA2048PSSwithSHA512", name: "RSA 2048 PSS with SHA-512", oid: CVC.id_TA_RSA_PSS_SHA_512, curve: null, keysize: 2048 },
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
	return new CVCATR3129ServicePort(this);
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
 * <p>The SPOC configuration object has the following properties:</p>
 * <ul>
 * <li>country - the two letter country code</li>
 * <li>name - human readable name</li>
 * <li>holderIDs - array of holder IDs for CVCAs accessible behind the SPOC</li>
 * <li>url - the URL at which the SPOC is available</li>
 * <li>async - true to serve this SPOC asynchronously</li>
 * </ul>
 * <p>Example:</p>
 * <pre>var spoc = { country: "FU", name: "Other country", holderIDs: ["FUCVCA"], url: "http://localhost:8080/se/spoc-fu", async: false };</pre>
 *
 * @param {Object} spoc the spoc configuration object
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
 * Return true if the holder is served by the SPOC identified by the country code
 *
 * @param {String} country the 2 letter ISO 3166-1 ALPHA-2 country code
 * @param {String} holderID the holderID to look for
 * @type boolean
 * @return The holderID is related to the SPOC
 */
CVCAService.prototype.isHolderIDofSPOC = function(country, holderID) {
	var spoc = this.spocmap[country];
	if (!spoc) {
		return false;
	}
	for each (var h in spoc.holderIDs) {
		if (holderID == h) {
			return true;
		}
	}
	return false;
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
 * Check certificate request parameter
 *
 * @param {ServiceRequest} sr the service request
 * @returns true if all checks passed or false and update in statusInfo
 * @type boolean
 */
CVCAService.prototype.checkRequestParameter = function(sr) {

	var requestedCAR = sr.getForeignCAR();
	if (typeof(requestedCAR) != "undefined") {
		var pkr = new PublicKeyReference(requestedCAR);
		var path = "/" + pkr.getHolder();
	} else {
		var path = this.path;
	}

	// Check that request key algorithm matches the algorithm for the current certificate

	var chr = this.ss.getCurrentCHR(path);
	if (!chr) {
		sr.addMessage("Internal error - could not find current CVCA certficate");
		sr.setStatusInfo(ServiceRequest.FAILURE_INTERNAL_ERROR);
		return false;
	}
	
	var cvc = this.ss.getCertificate(path, chr);

	if (!cvc) {
		sr.addMessage("Internal error - could not find CVCA certficate with CHR " + chr);
		sr.setStatusInfo(ServiceRequest.FAILURE_INTERNAL_ERROR);
		return false;
	}

	var req = sr.getCertificateRequest();

	// Check optional inner CAR
	var car = req.getCAR();
	if (car) {
		if (car.getHolder() != cvc.getCHR().getHolder()) {
			sr.addMessage("FAILED - Holder " + car.getHolder() + " in innerCAR of request does not match holder " + cvc.getCHR().getHolder() + " of requested CVCA" );
			sr.setStatusInfo(ServiceRequest.FAILURE_SYNTAX);
			return false;
		}
		sr.addMessage("Passed - CVCA requested in innerCAR matches CVCA the request is directed to" );
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
CVCAService.prototype.checkRequestOuterSignature = function(sr) {
	var req = sr.getCertificateRequest();
	
	if (req.isAuthenticatedRequest()) {
		var path = null;
		var outerCAR = req.getOuterCAR();
		
		if (req.isCountersignedRequest()) {
			if (sr.getType() != ServiceRequest.SPOC_REQUEST_CERTIFICATE) {
				sr.addMessage("FAILED - Outer signature for " + req.getCHR() + " not signed with previous key of entity, but " + outerCAR);
				sr.setStatusInfo(ServiceRequest.FAILURE_OUTER_SIGNATURE);
				return false;
			}
			
			var foreigncvca = req.getOuterCAR().getHolder();
			if (!this.isHolderIDofSPOC(sr.getCallerID(), foreigncvca)) {
				sr.addMessage("FAILED - Request received from SPOC " + sr.getCallerID() + " was not counter-signed by CVCA " + foreigncvca + " served by this SPOC");
				sr.setStatusInfo(ServiceRequest.FAILURE_OUTER_SIGNATURE);
				return false;
			}
			
			path = "/" + foreigncvca;
		} else {
			var requestedCAR = sr.getForeignCAR();
			var innerCAR = req.getCAR();
		
			if (typeof(requestedCAR) != "undefined") {				// RequestForeignCertificate
				var pkr = new PublicKeyReference(requestedCAR);
				path = "/" + pkr.getHolder();						// Path of foreign CVCA
			} else if (innerCAR) {
				path = "/" + innerCAR.getHolder();					// Path of CVCA indicated in innerCAR
			} else {
				path = "/" + this.name;								// Default this CVCA
			}
			path += "/" + req.getCHR().getHolder();
		}
		
		// Path is now the location where we should find the certificate that allows to verify the outer signature
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
CVCAService.prototype.checkRequestSemantics = function(sr) {
	
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
CVCAService.prototype.checkPolicy = function(sr, callback) {

	var req = sr.getCertificateRequest();
	
	var policy = this.getDVCertificatePolicyForCHR(req.getCHR());
	
	if ((sr.getStatusInfo() == ServiceRequest.FAILURE_EXPIRED) && !policy.declineExpiredAuthenticatedRequest) {
		sr.addMessage("Overwrite - Expired certificate for outer signature accepted due to policy overwrite");
		sr.setStatusInfo(ServiceRequest.OK_SYNTAX);
	}

	if (sr.getStatusInfo() != ServiceRequest.OK_SYNTAX) {
		return false;
	}
	
	if (req.isAuthenticatedRequest()) {
		if (sr.getType() == ServiceRequest.DVCA_REQUEST_FOREIGN_CERTIFICATE) {
			if (policy.authenticatedRequestsForwarded) {
				sr.addMessage("Overwrite - Authenticated request automatically forwarded by policy");
				sr.setStatusInfo(ServiceRequest.OK_REQUEST_FORWARDED);
				return true;
			}
		} else if (sr.getType() == ServiceRequest.SPOC_REQUEST_CERTIFICATE) {
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
 * Send certificates using a webservice call to the SPOC or DVCA
 *
 * @param {ServiceRequest} serviceRequest the underlying request
 */
CVCAService.prototype.sendCertificates = function(serviceRequest) {
	if (serviceRequest.getType().substr(0, 4) == "SPOC") {
		var con = new SPOCConnection(serviceRequest.getResponseURL());
		var callerID = this.name.substr(0, 2);
		var certbin = SPOCConnection.fromCVCList(serviceRequest.getCertificateList());
		var result = con.sendCertificates(certbin, callerID, serviceRequest.getMessageID(), serviceRequest.getStatusInfo());
		serviceRequest.setSOAPRequest(con.request);
		serviceRequest.setSOAPResponse(con.response);
	} else {
		var con = new TAConnection(serviceRequest.getResponseURL(), true);
		con.version = this.version;
		var certbin = TAConnection.fromCVCList(serviceRequest.getCertificateList());
		var result = con.sendCertificates(certbin, serviceRequest.getMessageID(), serviceRequest.getStatusInfo());
		serviceRequest.setSOAPRequest(con.request);
		serviceRequest.setSOAPResponse(con.response);
	}
	serviceRequest.setFinalStatusInfo(result);
	serviceRequest.addMessage("Completed");
}



/**
 * Request CA certificate from SPOC identified by the country code
 *
 * @param {String} country the two letter country code
 * @type String
 * @return the returnCode from the remote system
 */
CVCAService.prototype.getCACertificatesFromSPOC = function(country) {
	var spoc = this.spocmap[country];

	msgid = this.newMessageID();

	var sr = new ServiceRequest(msgid, spoc.url);
	sr.setType(ServiceRequest.SPOC_GET_CA_CERTIFICATES);
	this.addOutboundRequest(sr);
	
	var con = new SPOCConnection(spoc.url);
	var callerID = this.name.substr(0, 2);
	var list = con.getCACertificates(callerID, msgid);
	con.close();
	
	var certlist = [];
	
	if (!list) {
		sr.setStatusInfo(con.getLastReturnCode());
	} else {
		sr.setStatusInfo(ServiceRequest.OK_CERT_AVAILABLE);
		for (var i = 0; i < list.length; i++) {
			var cvc = new CVC(list[i]);
			certlist.push(cvc);
			GPSystem.trace(cvc);
		}
		sr.setCertificateList(certlist);
	}

	var list = this.cvca.importCertificates(certlist);

	if (list.length > 0) {
		var str = "Warning: Could not import the following certificates:\n";
		for (var i = 0; i < list.length; i++) {
			str += list[i].toString() + "\n";
		}
		sr.addMessage(str);
	}
	return sr.getStatusInfo();
}



// ---- WebService handling ---------------------------------------------------

/**
 * Process a request from a DVCA to return current CA certificates
 *
 * @param {ServiceRequest} sr the service request
 * @param {boolean} callback true if callback is possible
 */
CVCAService.prototype.processGetCACertificates = function(sr, callback) {

	this.addInboundRequest(sr);

	if (callback) {
		sr.setStatusInfo(ServiceRequest.OK_SYNTAX);
	} else {
		sr.setCertificateList(this.compileCertificateList(false));
		sr.setStatusInfo(ServiceRequest.OK_CERT_AVAILABLE);
	}
}



/**
 * Process a request via the SPOC to return current CA certificates
 *
 * @param {ServiceRequest} sr the service request
 */
CVCAService.prototype.processSPOCGetCACertificates = function(sr) {

	this.addInboundRequest(sr);

	var callerID = sr.getCallerID();		// Request via SPOC interface
	var spoc = this.getSPOC(callerID);
	if (!spoc) {
		sr.setStatusInfo(ServiceRequest.FAILURE_REQUEST_NOT_ACCEPTED);
		sr.setMessage("No SPOC for callerID " + callerID + " known");
		return;
	}
	sr.setResponseURL(spoc.url);

	if (spoc.async) {
		sr.setStatusInfo(ServiceRequest.OK_RECEPTION_ACK);
	} else {
		sr.setCertificateList(this.compileCertificateList(true));
		sr.setStatusInfo(ServiceRequest.OK_CERT_AVAILABLE);
	}
}



/**
 * Process a request to issue a domestic DV certificate
 *
 * @param {ServiceRequest} sr the service request
 * @param {boolean} callback true if callback is possible
 */
CVCAService.prototype.processRequestCertificate = function(sr, callback) {

	this.addInboundRequest(sr);

	var req = this.checkRequestSyntax(sr.getRawCertificateRequest());
	if (!req) {
		sr.setStatusInfo(ServiceRequest.FAILURE_SYNTAX);
		sr.setMessage("Certificate request is not a valid ASN.1 structure: " + sr.getRawCertificateRequest().toString(HEX));
		return;
	}
	
	sr.setCertificateRequest(req);

	GPSystem.trace("CVCAService - Received certificate request: ");
	GPSystem.trace(req);

	// Check basic semantics of request
	this.checkRequestSemantics(sr);
	if (this.checkPolicy(sr, callback)) {						// Synchronous processing approved by policy ?
		var certlist = this.determineCertificateList(req);

		var cert = this.issueCertificate(req);
		// Add certificate list to response
		certlist.push(cert);
		sr.setCertificateList(certlist);
		sr.setFinalStatusInfo(sr.getStatusInfo());		// Nothing else will happen
		sr.addMessage("Completed");
	}
}



/**
 * Forward DVCA certificate request to the SPOC identified by the country code
 *
 * @param {ServiceRequest} relatedsr the inbound service request 
 * @return the service request forwared to the SPOC
 */
CVCAService.prototype.forwardRequestToSPOC = function(relatedsr) {
	var country = relatedsr.getForeignCAR().substr(0, 2);
	var spoc = this.spocmap[country];

	msgid = this.newMessageID();

	var sr = new ServiceRequest(msgid, spoc.url, relatedsr.getCertificateRequest());
	sr.setType(ServiceRequest.SPOC_FORWARD_REQUEST_CERTIFICATE);
	sr.setRelatedServiceRequest(relatedsr);
	this.addOutboundRequest(sr);
	
	relatedsr.addMessage("Request - forwarded to SPOC (" + country + ") in message " + msgid);
	var con = new SPOCConnection(spoc.url);
	var callerID = this.name.substr(0, 2);
	var list = con.requestCertificate(sr.getCertificateRequest().getBytes(), callerID, sr.getMessageID());
	con.close();

	if (!list) {
		sr.addMessage("Response - No certificates received");
		sr.setStatusInfo(con.getLastReturnCode());
		relatedsr.setStatusInfo(con.getLastReturnCode());
	} else {
		sr.setStatusInfo(ServiceRequest.OK_CERT_AVAILABLE);
		var certlist = [];
		for (var i = 0; i < list.length; i++) {
			var cvc = new CVC(list[i]);
			certlist.push(cvc);
			GPSystem.trace(cvc);
		}
		sr.setCertificateList(certlist);
		sr.addMessage("Response - " + list.length + " certificates received and forwarded via message " + relatedsr.getMessageID());
		relatedsr.setCertificateList(certlist);
		relatedsr.setStatusInfo(ServiceRequest.OK_CERT_AVAILABLE);
		relatedsr.addMessage("Response - " + list.length + " certificates received from SPOC in synchronous message " + sr.getMessageID() + " and forwarded to DVCA synchronously");
	}

	return sr;
}



/**
 * Process a request to forward a certificate request to a foreign CVCA
 *
 * @param {ServiceRequest} sr the service request
 * @param {boolean} callback true if callback is possible
 */
CVCAService.prototype.processRequestForeignCertificate = function(sr, callback) {

	this.addInboundRequest(sr);

	var req = this.checkRequestSyntax(sr.getRawCertificateRequest());
	if (!req) {
		sr.setStatusInfo(ServiceRequest.FAILURE_SYNTAX);
		sr.setMessage("Certificate request is not a valid ASN.1 structure: " + sr.getRawCertificateRequest().toString(HEX));
		return;
	}
	
	sr.setCertificateRequest(req);

	GPSystem.trace("CVCAService - Received foreign certificate request: ");
	GPSystem.trace(req);

	// Check basic semantics of request
	this.checkRequestSemantics(sr);
	if (this.checkPolicy(sr, callback)) {
		this.forwardRequestToSPOC(sr);

		var certlist = sr.getCertificateList();
		if (certlist) {
			this.cvca.importCertificates(sr.getCertificateList());			// Keep local copy
		}

		if (sr.getStatusInfo() == ServiceRequest.OK_RECEPTION_ACK) {
			if (callback != "callback_possible") {
				// The SPOC accepted the request for asychronous processing, but the calling DVCA does not
				// support asynchronous callback. In this case the certificate request is lost the the foreign
				// CVCA.
				sr.addMessage("FAILED - SPOC can only process request asynchronously, but DVCA does not support asynchronous processing");
				sr.setStatusInfo(ServiceRequest.FAILURE_SYNCHRONOUS_PROCESSING_NOT_POSSIBLE);
				sr.setFinalStatusInfo(ServiceRequest.FAILURE_SYNCHRONOUS_PROCESSING_NOT_POSSIBLE);
			} else {
				// We did syntax checking, so return OK_SYNTAX rather than OK_RECEPTION_ACK
				sr.setStatusInfo(ServiceRequest.OK_SYNTAX);
			}
		} else {
			sr.setFinalStatusInfo(sr.getStatusInfo());		// Nothing else will happen
			sr.addMessage("Completed");
		}
	}
}



/*
/**
 * Process a request to issue a certificate received via the SPOC
 *
 * @param {ServiceRequest} sr the service request
 */
CVCAService.prototype.processSPOCRequestCertificate = function(sr) {

	this.addInboundRequest(sr);

	var spoc = this.getSPOC(sr.getCallerID());
	if (!spoc) {
		sr.setStatusInfo(ServiceRequest.FAILURE_REQUEST_NOT_ACCEPTED);
		sr.setMessage("Unknown callerID");
		return;
	}
	sr.setResponseURL(spoc.url);
	
	var req = this.checkRequestSyntax(sr.getRawCertificateRequest());
	if (!req) {
		sr.setStatusInfo(ServiceRequest.FAILURE_SYNTAX);
		sr.setMessage("Certificate request is not a valid ASN.1 structure: " + sr.getRawCertificateRequest().toString(HEX));
		return;
	}
	
	sr.setCertificateRequest(req);
	
	GPSystem.trace("SPOCService - Received certificate request: ");
	GPSystem.trace(req);

	// Check basic semantics of request
	this.checkRequestSemantics(sr);
	if (this.checkPolicy(sr, true)) {						// Synchronous processing approved by policy ?
		var certlist = this.determineCertificateList(req);

		var cert = this.issueCertificate(req);
		// Add certificate list to response
		certlist.push(cert);
		sr.setCertificateList(certlist);
		sr.setFinalStatusInfo(sr.getStatusInfo());		// Nothing else will happen
		sr.addMessage("Completed");
	} else {
		if (sr.getStatusInfo() == ServiceRequest.OK_SYNTAX) {
			sr.setStatusInfo(ServiceRequest.OK_RECEPTION_ACK);
		}
	}
}



// ---- GUI handling ----------------------------------------------------------

/**
 * Process request and send certificates
 *
 * @param {Number} index the index into the work queue identifying the request or -1 to return the last entry
 * @type String
 * @return the returnCode from the remote system
*/
CVCAService.prototype.processRequest = function(index) {
	var sr = this.getInboundRequest(index);

	sr.addMessage("User - Process request with status " + sr.getStatusInfo());
	
	if (sr.isCertificateRequest()) {		// RequestCertificate
		if (sr.getStatusInfo() == ServiceRequest.OK_CERT_AVAILABLE) {
			var req = sr.getCertificateRequest();

			sr.addMessage("Starting secondary check");
			if (this.checkRequestSemantics(sr)) {		// Still valid
				var certlist = this.determineCertificateList(req);
				var cert = this.issueCertificate(req);
				certlist.push(cert);
				sr.setCertificateList(certlist);
			} else {
				GPSystem.trace("Request " + req + " failed secondary check");
			}
		} else if (sr.getStatusInfo() == ServiceRequest.OK_REQUEST_FORWARDED) {
			if (this.cvca.isOperational() && !sr.getCertificateRequest().isAuthenticatedRequest()) {
				var req = this.cvca.counterSignRequest(sr.getCertificateRequest());
				sr.setCertificateRequest(req);
			}
			var forwardsr = this.forwardRequestToSPOC(sr);
			return forwardsr.getStatusInfo();
		}
	} else {								// GetCertificates
		if (sr.getStatusInfo().substr(0, 3) == "ok_") {
			// Only return our own certificate to the other SPOC
			sr.setCertificateList(this.compileCertificateList(sr.getType() == ServiceRequest.SPOC_GET_CA_CERTIFICATES));
		}
	}
	
	this.sendCertificates(sr);
	return sr.getFinalStatusInfo();
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
 * Request updated CA certificates from all registered SPOCs
 * @type String
 * @return the returnCode from the remote system
 */
CVCAService.prototype.getCACertificatesFromSPOCs = function() {
	for (var i = 0; i < this.spoclist.length; i++) {
		var result = this.getCACertificatesFromSPOC(this.spoclist[i].country);
	}
	return result;
}



// ---- TR-03129 Service ------------------------------------------------------

/**
 * The TR-03129 Service port class
 * 
 * <p>See BSI-TR-03129 at www.bsi.bund.de for the specification of the CVCA/SPOC web service</p>
 */
function CVCATR3129ServicePort(service) {
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
CVCATR3129ServicePort.prototype.generateResponse = function(type, sr) {
	var ns = new Namespace("uri:EAC-PKI-CVCA-Protocol/" + this.version);
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
CVCATR3129ServicePort.prototype.GetCACertificates = function(soapBody) {
	var ns = new Namespace("uri:EAC-PKI-CVCA-Protocol/" + this.version);
	var ns1 = new Namespace("uri:eacBT/" + this.version);

	var messageID = soapBody.messageID.ns1::messageID;
	var sr = new ServiceRequest(messageID);
	sr.setType(ServiceRequest.DVCA_GET_CA_CERTIFICATES);
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
CVCATR3129ServicePort.prototype.RequestCertificate = function(soapBody) {
	var ns = new Namespace("uri:EAC-PKI-CVCA-Protocol/" + this.version);
	var ns1 = new Namespace("uri:eacBT/" + this.version);

	var messageID = soapBody.messageID.ns1::messageID;
	var sr = new ServiceRequest(messageID);
	sr.setType(ServiceRequest.DVCA_REQUEST_CERTIFICATE);
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
 * Implements RequestForeignCertificates from TR-03129, chapter 4.2.2
 *
 * <p>Check request and forward to foreign SPOC/CVCA</p>
 *
 * @param {XML} soapBody the SOAP request body
 * @type XML
 * @return the SOAP response body
 */
CVCATR3129ServicePort.prototype.RequestForeignCertificate = function(soapBody) {
	var ns = new Namespace("uri:EAC-PKI-CVCA-Protocol/" + this.version);
	var ns1 = new Namespace("uri:eacBT/" + this.version);

	var messageID = soapBody.messageID.ns1::messageID;
	var sr = new ServiceRequest(messageID);
	sr.setType(ServiceRequest.DVCA_REQUEST_FOREIGN_CERTIFICATE);
	sr.setSOAPRequest(soapBody);

	sr.setRawCertificateRequest(new ByteString(soapBody.certReq, BASE64));
	sr.setForeignCAR(soapBody.foreignCAR.toString());
	
	var callback = soapBody.callbackIndicator.toString() == "callback_possible";
	if (callback) {
		sr.setResponseURL(soapBody.responseURL.ns1::string.toString());
	}

	this.service.processRequestForeignCertificate(sr, callback);

	var response = this.generateResponse("RequestForeignCertificateResponse", sr);

	sr.setSOAPResponse(response);
	return response;
}



// ---- SPOC Service ----------------------------------------------------------

/**
 * The SPOC service port class
 *
 * <p>See CSN_369791 for the specification of the SPOC web service</p>
 * <p>http://www.normservis.cz/download/view/csn/36/85000/85000_nahled.htm</p>
 * @param {CVCAService} the underlying CVCA service
 */
function SPOCServicePort(service) {
	this.service = service;
}



/**
 * Compile the response message using the returnCode and certificate list from the completed service request
 *
 * @param {String} type the response type name
 * @param {ServiceRequest} sr the completed service request
 * @type XML
 * @return the complete SOAP response body
 */
SPOCServicePort.prototype.generateResponse = function(type, sr) {

	var ns = new Namespace("http://namespaces.unmz.cz/csn369791");

	var certlist = sr.getCertificateList();
	if (certlist && (certlist.length > 0)) {
		var response =
			<csn:RequestCertificateResponse xmlns:csn={ns}>
				<!--Optional:-->
				<csn:certificateSequence>
				</csn:certificateSequence>
				<csn:result>{sr.getStatusInfo()}</csn:result>
			</csn:RequestCertificateResponse>
	
		var list = response.ns::certificateSequence;

		for (var i = 0; i < certlist.length; i++) {
			var cvc = certlist[i];
			list.ns::certificate += <cns:certificate xmlns:cns={ns}>{cvc.getBytes().toString(BASE64)}</cns:certificate>
		}
	} else {
		var response =
			<csn:RequestCertificateResponse xmlns:csn={ns}>
				<csn:result>{sr.getStatusInfo()}</csn:result>
			</csn:RequestCertificateResponse>
	}
	return response;
}



/**
 * Implements GeneralMessage from CSN_369791 (SPOC)
 *
 * <p>TBD</p>
 *
 * @param {XML} soapBody the SOAP request body
 * @type XML
 * @return the SOAP response body
 */
SPOCServicePort.prototype.GeneralMessage = function(soapBody) {
	print(soapBody.toXMLString());
	throw new Error("Not implemented");
}



/**
 * Implements GetCACertificates from CSN_369791 (SPOC)
 *
 * <p>Check caller and either respond synchronously with our certificate chain or schedule an asychronous response</p>
 *
 * @param {XML} soapBody the SOAP request body
 * @type XML
 * @return the SOAP response body
 */
SPOCServicePort.prototype.GetCACertificatesRequest = function(soapBody) {

	var ns = new Namespace("http://namespaces.unmz.cz/csn369791");

	var sr = new ServiceRequest(soapBody.ns::messageID.toString());
	sr.setType(ServiceRequest.SPOC_GET_CA_CERTIFICATES);
	sr.setSOAPRequest(soapBody);
	
	sr.setCallerID(soapBody.ns::callerID.toString());
	
	this.service.processSPOCGetCACertificates(sr);
	
	var response = this.generateResponse("GetCACertificatesResponse", sr);

	sr.setSOAPResponse(response);
	return response;
}



/**
 * Implements RequestCertificate from CSN_369791 (SPOC)
 *
 * @param {XML} soapBody the SOAP request body
 * @type XML
 * @return the SOAP response body
 */
SPOCServicePort.prototype.RequestCertificateRequest = function(soapBody) {

	var ns = new Namespace("http://namespaces.unmz.cz/csn369791");

	var sr = new ServiceRequest(soapBody.ns::messageID.toString());
	sr.setType(ServiceRequest.SPOC_REQUEST_CERTIFICATE);
	sr.setSOAPRequest(soapBody);
	
	sr.setCallerID(soapBody.ns::callerID.toString());
	sr.setRawCertificateRequest(new ByteString(soapBody.ns::certificateRequest, BASE64));
	
	this.service.processSPOCRequestCertificate(sr);
	
	var response = this.generateResponse("RequestCertificateResponse", sr);

	sr.setSOAPResponse(response);
	return response;
}



/**
 * Implements SendCertificates from CSN_369791 (SPOC)
 *
 * @param {XML} soapBody the SOAP request body
 * @type XML
 * @return the SOAP response body
 */
SPOCServicePort.prototype.SendCertificatesRequest = function(soapBody) {

	var ns = new Namespace("http://namespaces.unmz.cz/csn369791");

	var callerID = soapBody.ns::callerID.toString();
	var statusInfo = soapBody.ns::statusInfo.toString();

	if (statusInfo == ServiceRequest.NEW_CERT_AVAILABLE_NOTIFICATION) {
		var sr = new ServiceRequest();
		this.service.addInboundRequest(sr);
	} else {
		var msgid = soapBody.ns::messageID.toString();
		var sr = this.service.getOutboundRequestByMessageId(msgid);
	}

	if (sr) {
		sr.setStatusInfo(statusInfo);
		var returnCode = ServiceRequest.OK_RECEIVED_CORRECTLY;

		var certlist = [];
		if (statusInfo.substr(0, 3) == "ok_") {
			GPSystem.trace("Received certificates from SPOC:");
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

			sr.addMessage("SendCertificates - Received " + certlist.length + " certificates from SPOC");
			sr.setCertificateList(certlist);
			var unprocessed = this.service.cvca.importCertificates(certlist);		// Store locally
			if (unprocessed.length > 0) {
				sr.addMessage("FAILED - The following certificates could not be processed:");
				for each (var cvc in unprocessed) {
					sr.addMessage(cvc.toString());
				}
			}
		}
		if (sr.getType() == ServiceRequest.SPOC_FORWARD_REQUEST_CERTIFICATE) {
			var relatedsr = sr.getRelatedServiceRequest();
			relatedsr.setCertificateList(certlist);
			relatedsr.setStatusInfo(sr.getStatusInfo());
			sr.addMessage("SendCertificates - Forwarding " + certlist.length + " certificates from SPOC in response to DVCA message " + relatedsr.getMessageID());
			relatedsr.addMessage("SendCertificates - Forwarding to DVCA " + certlist.length + " certificates from SPOC (" + callerID + ") in response to message " + sr.getMessageID());
			this.service.sendCertificates(relatedsr);
			returnCode = relatedsr.getFinalStatusInfo();
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
