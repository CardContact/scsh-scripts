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



/**
 * Create a terminal control center (TCC) instance with web services
 *
 * @param {String} certstore the path to the certificate store or the store itself
 * @param {String} path the PKI path for the domestic part of this service (e.g. "/UTCVCA/UTDVCA/UTTERM")
 * @param {String} parentURL the URL of the parent CA's webservice
 */ 
function TCCService(certstore, path, parentURL) {
	BaseService.call(this);

	this.type = "TCC";
	this.path = path;

	var pe = path.substr(1).split("/");
	assert(pe.length == 3);

	this.root = pe[0];
	this.parent = pe[1];
	this.name = pe[2];
	this.parentURL = parentURL;
	
	this.crypto = new Crypto();
	
	if (typeof(certstore) == "string") {
		this.ss = new CVCertificateStore(certstore);
	} else {
		this.ss = certstore;
	}
	this.version = "1.1";
	this.rsaKeySize = 1024;
	this.namingscheme = TCCService.CountryCodeAndSequence;
}

TCCService.prototype = new BaseService();
TCCService.constructor = TCCService;

// The TCC supports three different naming schemes for DVCA public key references using for foreign certifications.
TCCService.ForeignCountryCode = 1;			// Place the foreign country code in the designated country code field of the CHR
TCCService.CountryCodeAndSequence = 2;		// Place the country code in the first two digits of the sequence number (default)



/**
 * Sets the URL which is used to receive SendCertificate messages
 * 
 * @param {String} url
 */
TCCService.prototype.setSendCertificateURL = function(url) {
	this.myURL = url;
}



/**
 * Sets the key size for certificate requests using RSA keys
 *
 * @param {Number} keysize the RSA key size in bits
 */
TCCService.prototype.setRSAKeySize = function(keysize) {
	this.rsaKeySize = keysize;
}



/**
 * Obtain a service port for TR-03129 service calls
 * 
 * @type Object
 * @return the service port that can be registered with the SOAP Server
 */
TCCService.prototype.getTR3129ServicePort = function() {
	return new TCCTR3129ServicePort(this);
}



/**
 * Get current holderId
 * 
 * @type String
 * @return the current holderId
 */
TCCService.prototype.getHolderID = function() {
	return this.name;
}



/**
 * Set current holderId
 * 
 * @param {String} holderID the new HolderID
 */
TCCService.prototype.setHolderID = function(name) {
	this.name = name;
}



/**
 * Determine if TCC is operational for the given CVCA
 *
 * @param {String} cvcaHolderId the holder ID of the requested CVCA
 * @type boolean
 * @return true if operational
 */
TCCService.prototype.isOperational = function(cvcaHolderId) {
	var cvcca = this.getCVCCA(cvcaHolderId, this.name);
	return cvcca.isOperational();
}



/**
 * Returns a list of TCCs supported by this DVCA. The domestic CVCA is always first in the list.
 *
 * @type String[]
 * @return the list of CVCA holderIDs
 */
TCCService.prototype.getCVCAList = function() {
	var cvcas = [];
	cvcas.push(this.root);
	var holders = this.ss.listHolders("/");
	for each (var holder in holders) {
		if (holder != this.root) {
			cvcas.push(holder);
		}
	}
	return cvcas;
}



/**
 * Sets the naming scheme to by used when requesting foreign certificates.
 *
 * <p>With TCCService.CountryCodeAndSequence the country code is stored in the first two digits of the sequence number.</p>
 * <p>With TCCService.ForeignCountryCode the country code is stored in the first two digits of the holder ID.</p>
 *
 * @param {String} namingscheme the selected namingscheme for foreign terminal certificates
 */
TCCService.prototype.setNamingScheme = function(namingscheme) {
	this.namingscheme = namingscheme;
}



/**
 * Returns the path for a given CVCA and terminal
 *
 * @param {String} cvcaHolderId the holder ID of the requested CVCA
 * @param {String} termHolderID the holderID of the terminal
 * @type String
 * @return the path or null if no such CVCA known
 */
TCCService.prototype.getPathFor = function(cvcaHolderId, termHolderId) {
	if ((cvcaHolderId != this.root) && (this.namingscheme == TCCService.ForeignCountryCode)) {
		termHolderId = cvcaHolderId.substr(0, 2) + this.termHolderId.substr(2);
	}

	return "/" + cvcaHolderId + "/" + this.parent + "/" + termHolderId;
}



/**
 * Return a CVCCA associated with the given CVCA
 *
 * @param {String} cvcaHolderID the holderID of the supported CVCA
 * @param {String} termHolderID the holderID of the terminal
 * @type CVCCA
 * @return the CVCCA object
 */
TCCService.prototype.getCVCCA = function(cvcaHolderID, termHolderID) {
	var path = this.getPathFor(cvcaHolderID, termHolderID);

	var cvcca = new CVCCA(this.ss.getCrypto(), this.ss, null, null, path);

	if ((cvcaHolderID != this.root) && (this.namingscheme == TCCService.CountryCodeAndSequence)) {
		cvcca.setCountryCodeForSequence(cvcaHolderID.substr(0, 2));
	}
	return cvcca;
}



// UI Interface operations

/**
 * Return the current certificate list for the DVCA instance related to the requested CVCA
 *
 * @param {String} cvcaHolderId holder ID of the CVCA in question
 * @type CVC[]
 * @return the list of CV certificates from the self-signed root to the DV
 */
TCCService.prototype.getCertificateList = function(cvcaHolderId) {
	var cvcca = this.getCVCCA(cvcaHolderId, this.name);
	return cvcca.getCertificateList();
}



/**
 * Update certificate list from parent CA
 *
 * @type String
 * @return The return code received from the other side
 */
TCCService.prototype.updateCACertificates = function(async) {

	var msgid = null;
	
	if (async) {
		msgid = this.newMessageID();
	}

	var sr = new ServiceRequest(msgid, this.myURL);
	sr.setType(ServiceRequest.TERM_GET_CA_CERTIFICATES);
	this.addOutboundRequest(sr);

	var con = new TAConnection(this.parentURL, false);
	
	if (async) {
		var list = con.getCACertificates(sr.getMessageID(), sr.getResponseURL());
	} else {
		var list = con.getCACertificates();
	}

	sr.setSOAPRequest(con.getLastRequest());
	sr.setSOAPResponse(con.getLastResponse());
	
	con.close();

	sr.setStatusInfo(con.getLastReturnCode());
	
	this.processCertificateList(sr, list);
	
	return sr.getStatusInfo();
}



/**
 * Renew certificate through parent CA
 *
 * @param {Boolean} async request asynchronous processing
 * @param {Boolean} forceinitial force request to be an initial request
 * @param {String} cvcaHolderId the holder ID of the requested CVCA
 * @param {String} termHolderID the holderID of the terminal
 * @type String
 * @return The return code received from the other side
 */
TCCService.prototype.renewCertificate = function(async, forceinitial, cvcaHolderId, termHolderId) {

	var path = this.getPathFor(cvcaHolderId, termHolderId);
	
	var algo = this.ss.getDefaultPublicKeyOID(path);
	if (CVC.isECDSA(algo)) {
		var keyspec = this.ss.getDefaultDomainParameter(path);
	} else {
		var keyspec = new Key();
		keyspec.setType(Key.PUBLIC);
		keyspec.setSize(this.rsaKeySize);
	}
	
	var car = this.ss.getCurrentCHR(CVCertificateStore.parentPathOf(path));
	
	var cvcca = this.getCVCCA(cvcaHolderId, termHolderId);
	cvcca.setKeySpec(keyspec, algo);

	// Create a new request
	var req = cvcca.generateRequest(car, forceinitial);

	var msgid = null;
	
	if (async) {
		msgid = this.newMessageID();
	}

	var sr = new ServiceRequest(msgid, this.myURL, req);
	sr.setType(ServiceRequest.TERM_REQUEST_CERTIFICATE);
	sr.setRequestingNodePath(path);
	this.addOutboundRequest(sr);
	
	if (this.parentURL) {
		var certlist = this.requestCertificateFromDVCA(sr);
		
		this.processCertificateList(sr, certlist);
	} else {
		sr.setStatusInfo("Local request");
	}

	return sr.getStatusInfo();
}



/**
 * Process list of certificates received from CVCA
 *
 * @param {ServiceRequest} sr the service request
 * @param {ByteString[]} list the certificate list
 * @type String
 * @return The return code received from the other side
 */
TCCService.prototype.processCertificateList = function(sr, list) {
	var certlist = [];
	
	if (list) {
		for (var i = 0; i < list.length; i++) {
			var cvc = new CVC(list[i]);
			certlist.push(cvc);
			GPSystem.trace(cvc);
		}
		sr.setCertificateList(certlist);
	}

	var path = sr.getRequestingNodePath();
	if (!path) {
		path = this.path;
	}
	var list = this.ss.insertCertificates2(this.crypto, certlist, true, path);

	if (list.length > 0) {
		var str = "Warning: Could not import the following certificates:\n";
		for (var i = 0; i < list.length; i++) {
			str += list[i].toString() + "\n";
		}
		sr.addMessage(str);
	}
}



/**
 * Request a certificate from the parent CA using a web service
 *
 * @param {ServiceRequest} serviceRequest the underlying request
 * @returns the new certificates
 * @type CVC[]
 */
TCCService.prototype.requestCertificateFromDVCA = function(sr) {

	var con = new TAConnection(this.parentURL, false);
	
	if (sr.getMessageID()) {
		var certlist = con.requestCertificate(sr.getCertificateRequest().getBytes(), sr.getMessageID(), sr.getResponseURL());
	} else {
		var certlist = con.requestCertificate(sr.getCertificateRequest().getBytes());
	}

	sr.setSOAPRequest(con.getLastRequest());
	sr.setSOAPResponse(con.getLastResponse());

	con.close();

	sr.setStatusInfo(con.getLastReturnCode());
	return certlist;
}



/**
 * Handle a manually submitted certificate
 *
 * @param {String} forCVCA the CVCA holder id this certificate is most likely for
 * @param {ByteString} cert the binary certicate
 * @type String
 * @return the result processing the request
 */
TCCService.prototype.processUploadedCertificate = function(forCVCA, cert) {
	var sr = new ServiceRequest();
	sr.setType(ServiceRequest.DVCA_SEND_CERTIFICATE);
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

	var unprocessed = this.ss.insertCertificates2(this.crypto, certlist, true, "/" + forCVCA);
	if (unprocessed.length > 0) {
		sr.addMessage("FAILED - The following certificates could not be processed:");
		for each (var cvc in unprocessed) {
			sr.addMessage(cvc.toString());
		}
	}
	
	sr.setStatusInfo(ServiceRequest.OK);
	return sr.getStatusInfo();
}



// ---- TR-03129 Service ------------------------------------------------------

/**
 * The TR-03129 Service port class
 * 
 * <p>See BSI-TR-03129 at www.bsi.bund.de for the specification of the TCC web service</p>
 */
function TCCTR3129ServicePort(service) {
	this.service = service;
	this.version = "1.1";
}



/**
 * Webservice that receives certificates from parent CA
 * 
 * @param {XML} soapBody the body of the SOAP message
 * @returns the soapBody of the response
 * @type XML
 */
TCCTR3129ServicePort.prototype.SendCertificates = function(soapBody) {
	
	var ns = new Namespace("uri:EAC-PKI-TermContr-Protocol/" + this.version);
	var ns1 = new Namespace("uri:eacBT/" + this.version);

	var statusInfo = soapBody.statusInfo.toString();

	if (this.version == "1.0") {
		var msgid = soapBody.messageID.toString();
	} else {
		var msgid = soapBody.messageID.ns1::messageID.toString();
	}
	
	var sr = this.service.getOutboundRequestByMessageId(msgid);
	if (sr) {
		sr.setStatusInfo(statusInfo);
		var returnCode = ServiceRequest.OK_RECEIVED_CORRECTLY;

		if (returnCode.substr(0, 3) == "ok_") {
			var certlist = [];
			GPSystem.trace("Received certificates from DVCA:");
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
 * Webservice that returns a list of certificates that resemble a valid certificate chain
 * starting with a certificate issued by the trust anchor's public key reference provided
 * a argument to the service invocation.
 * 
 * @param {XML} soapBody the body of the SOAP message
 * @returns the soapBody of the response
 * @type XML
 */
TCCTR3129ServicePort.prototype.GetCertificateChain = function(soapBody) {

	// Create empty response
	var ns = new Namespace("uri:EAC-PKI-TermContr-Protocol/" + this.version);
	var ns1 = new Namespace("uri:eacBT/" + this.version);

	if (this.version == "1.0") {
		var chrstr = soapBody.keyNameMRTD;
	} else {
		var chrstr = soapBody.keyCAR;
	}
	
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
		var cl = this.service.tcc.getCertificateList(chr);
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
TCCTR3129ServicePort.prototype.GetTASignature = function(soapBody) {

	// Create empty response
	var ns = new Namespace("uri:EAC-PKI-TermContr-Protocol/" + this.version);
	var ns1 = new Namespace("uri:eacBT/" + this.version);

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
		var prk = this.service.tcc.certstore.getPrivateKey(this.path, chr);
		if (prk == null) {
			var returnCode = ServiceRequest.FAILURE_CHR_UNKNOWN;
		} else {
			var cvc = this.service.tcc.certstore.getCertificate(this.path, chr);
			
			// ToDo: Check expiration of certificate
			
			var oid = cvc.getPublicKeyOID();
			if (CVC.isECDSA(oid)) {
				var signature = this.crypto.sign(prk, Crypto.ECDSA, hashbin);
			
				var keylen = prk.getComponent(Key.ECC_P).length;
			
				var signature = ECCUtils.unwrapSignature(signature, keylen);
			} else {
				var mech = CVC.getSignatureMech(cvc.getPublicKeyOID());
				var signature = this.crypto.sign(prk, mech, hashbin);
			}
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
