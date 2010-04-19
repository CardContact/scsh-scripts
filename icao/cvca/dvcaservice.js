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
 * @fileoverview A simple DVCA web service implementing TR-03129 web services
 */



/**
 * Create a DVCA instance with web services
 *
 * @param {String} path the path to the certificate store
 * @param {String} name the holder name (Country code plus holder mnemonic) for this instance
 * @param {String} parent the holder name of the parent CA
 * @param {String} parentURL the URL of the parent CA's webservice
 */ 
function DVCAService(path, name, parent, parentURL) {
	this.name = name;
	this.type = "DVCA";
	
	this.parent = parent;
	this.parentURL = parentURL;
	
	this.crypto = new Crypto();
	
	this.ss = new CVCertificateStore(path);
	this.dvca = new CVCCA(this.crypto, this.ss, name, parent);
	this.path = this.dvca.path;
	this.inqueue = [];
	this.outqueue = [];
	this.outqueuemap = [];
}



/**
 * Sets the URL which is used to receive SendCertificate messages
 * 
 * @param {String} url
 */
DVCAService.prototype.setSendCertificateURL = function(url) {
	this.myURL = url;
}



/**
 * Sets the key specification for generating requests
 *
 * @param {Key} keyparam a key object containing key parameters (e.g. EC Curve)
 * @param {ByteString} algorithm the terminal authentication algorithm object identifier
 */
DVCAService.prototype.setKeySpec = function(keyparam, algorithm) {
	this.cvca.setKeySpec(keyparam, algorithm);
}



/**
 * Enumerate all pending service requests from subordinate systems
 *
 * @returns the pending service requests
 * @type ServiceRequest[]
 */
DVCAService.prototype.listInboundRequests = function() {
	return this.inqueue;
}



/**
 * Gets the indexed request
 *
 * @param {Number} index the index into the work queue identifying the request
 * @returns the indexed request
 * @type ServiceRequest
 */
DVCAService.prototype.getInboundRequest = function(index) {
	return this.inqueue[index];
}



/**
 * Enumerate all pending service requests to superior systems
 *
 * @returns the pending service requests
 * @type ServiceRequest[]
 */
DVCAService.prototype.listOutboundRequests = function() {
	return this.outqueue;
}



/**
 * Gets the indexed request
 *
 * @param {Number} index the index into the work queue identifying the request
 * @returns the indexed request
 * @type ServiceRequest
 */
DVCAService.prototype.getOutboundRequest = function(index) {
	return this.outqueue[index];
}



/**
 * Adds an outbound request to the internal queue, removing the oldest entry if more than
 * 10 entries are contained
 *
 * @param {ServiceRequest} sr the service request
 */
DVCAService.prototype.addOutboundRequest = function(sr) {
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
DVCAService.prototype.updateCACertificates = function(async) {

	var msgid = null;
	
	if (async) {
		msgid = this.crypto.generateRandom(2).toString(HEX);
	}

	var sr = new ServiceRequest(msgid, this.myURL);
	this.addOutboundRequest(sr);
	
	var certlist = this.getCACertificatesFromCVCA(sr);
	var list = this.dvca.importCertificates(certlist);

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
DVCAService.prototype.renewCertificate = function(async, forceinitial) {

	var dp = this.ss.getDefaultDomainParameter(this.parent);
	var algo = this.ss.getDefaultPublicKeyOID(this.parent);
	
	this.dvca.setKeySpec(dp, algo);
	
	// Create a new request
	var req = this.dvca.generateRequest(forceinitial);
	print("Request: " + req);
	print(req.getASN1());

	var msgid = null;
	
	if (async) {
		msgid = this.crypto.generateRandom(2).toString(HEX);
	}

	var sr = new ServiceRequest(msgid, this.myURL, req);
	this.addOutboundRequest(sr);
	
	var certlist = this.requestCertificateFromCVCA(sr);
	
	var list = this.dvca.importCertificates(certlist);

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
DVCAService.prototype.importCertificates = function(certlist) {

	var list = this.dvca.importCertificates(certlist);

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
DVCAService.prototype.getCACertificatesFromCVCA = function(sr) {

	var soapConnection = new SOAPConnection();

	var ns = new Namespace("uri:EAC-PKI-CVCA-Protocol/1.0");
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
		GPSystem.trace("Received certificates from CVCA:");
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
DVCAService.prototype.requestCertificateFromCVCA = function(sr) {

	var soapConnection = new SOAPConnection();

	var ns = new Namespace("uri:EAC-PKI-CVCA-Protocol/1.0");
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
		throw new GPError("DVCAService", GPError.DEVICE_ERROR, 0, "RequestCertificate failed with : " + e);
	}
	
	sr.setStatusInfo(response.Result.ns1::returnCode.toString());
	var certlist = [];

	if (response.Result.ns1::returnCode.substr(0, 3) == "ok_") {
		GPSystem.trace("Received certificates from CVCA:");
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
DVCAService.prototype.SendCertificates = function(soapBody) {
	
	var ns = new Namespace("uri:EAC-PKI-DV-Protocol/1.0");
	var ns1 = new Namespace("uri:eacBT/1.0");

	var statusInfo = soapBody.statusInfo.toString();
	var msgid = soapBody.messageID.toString();
	
	var sr = this.outqueuemap[msgid];
	if (sr) {
		sr.setStatusInfo(statusInfo);
		var returnCode = ServiceRequest.OK_RECEIVED_CORRECTLY;

		if (returnCode.substr(0, 3) == "ok_") {
			var certlist = [];
			GPSystem.trace("Received certificates from CVCA:");
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
