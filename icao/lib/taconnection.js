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
 * @fileoverview Connector implementing a web service interface to a CVCA/DVCA for the
 * distribution of card verifiable certificates used for terminal authentication as defined in TR-03129
 */



/**
 * Creates a web service connector to access services of a CVCA/DVCA as defined in TR-03129
 *
 * @class Class implementing a CVCA/DVCA web service connector
 * @constructor
 * @param {String} url the web service endpoint
 * @param {Boolean} isCVCA true if connection is made to CVCA instead of DVCA
 */
function TAConnection(url, isCVCA) {
	this.url = url;
	this.soapcon = new SOAPConnection(SOAPConnection.SOAP11);
	this.verbose = true;
	this.lastReturnCode = null;
	this.version = "1.1";
	this.isCVCA = isCVCA;
}



/**
 * Sets the version of the WSDL to use
 *
 * @param {String} version the version to use
 */
TAConnection.prototype.setVersion = function(version) {
	this.version = version;
}



/**
 * Get the last error return code (Deprecated: Use getLastReturnCode() instead)
 *
 * @returns the last error return code received or null if none defined
 * @type String
 */
TAConnection.prototype.getLastError = function() {
	return this.lastReturnCode;
}



/**
 * Get the last return code
 *
 * @returns the last return code received or null if none defined
 * @type String
 */
TAConnection.prototype.getLastReturnCode = function() {
	return this.lastReturnCode;
}



/**
 * Gets the last request
 *
 * @returns the last request
 * @type XML
 */
TAConnection.prototype.getLastRequest = function() {
	return this.request;
}



/**
 * Gets the last response
 *
 * @returns the last response
 * @type XML
 */
TAConnection.prototype.getLastResponse = function() {
	return this.response;
}



/**
 * Close the connector and release allocated resources
 */
TAConnection.prototype.close = function() {
	this.soapcon.close();
}



/**
 * Obtain a list of certificates from the CVCA or DVCA
 *
 * @param {String} messageID the messageID for asynchronous requests (optional)
 * @param {String} responseURL the URL to which the asynchronous response is send (optional)
 * @returns a lists of card verifiable certificates from the DVCA or null in case of error
 * @type ByteString[]
 */
TAConnection.prototype.getCACertificates = function(messageID, responseURL) {

	this.lastReturnCode = null;

	if (this.isCVCA) {
		var ns = new Namespace("uri:EAC-PKI-CVCA-Protocol/" + this.version);
	} else {
		var ns = new Namespace("uri:EAC-PKI-DV-Protocol/" + this.version);
	}

	var ns1 = new Namespace("uri:eacBT/" + this.version);

	var request =
		<ns:GetCACertificates xmlns:ns={ns} xmlns:ns1={ns1}>
			<callbackIndicator>callback_not_possible</callbackIndicator>
			<messageID>
			</messageID>
			<responseURL>
			</responseURL>
		</ns:GetCACertificates>;

	if (typeof(messageID) != "undefined") {
		request.callbackIndicator = "callback_possible";
		request.messageID.ns1::messageID = messageID;
		request.responseURL.ns1::string = responseURL;
	}

	if (this.verbose) {
		GPSystem.trace(request.toXMLString());
	}

	this.request = request;

	try	 {
		var response = this.soapcon.call(this.url, request);
		if (this.verbose) {
			GPSystem.trace(response.toXMLString());
		}
	}
	catch(e) {
		GPSystem.trace("SOAP call to " + this.url + " failed : " + e);
		throw new GPError("TAConnection", GPError.DEVICE_ERROR, 0, "getCACertificates failed with : " + e);
	}
	
	this.response = response;

	var certlist = [];

	this.lastReturnCode = response.Result.ns1::returnCode.toString();

	if (this.lastReturnCode == "ok_cert_available") {
		for each (var c in response.Result.ns1::certificateSeq.ns1::certificate) {
			var cvc = new ByteString(c, BASE64);
			certlist.push(cvc);
			GPSystem.trace(cvc);
		}
	} else {
		return null;
	}

	return certlist;
}



/**
 * Request a certificate from the parent CA using a web service
 *
 * @param {ByteString} certreq the certificate request
 * @param {String} messageID the messageID for asynchronous requests (optional)
 * @param {String} responseURL the URL to which the asynchronous response is send (optional)
 * @returns the new certificates
 * @type ByteString[]
 */
TAConnection.prototype.requestCertificate = function(certreq, messageID, responseURL) {

	this.lastReturnCode = null;

	var soapConnection = new SOAPConnection();

	if (this.isCVCA) {
		var ns = new Namespace("uri:EAC-PKI-CVCA-Protocol/" + this.version);
	} else {
		var ns = new Namespace("uri:EAC-PKI-DV-Protocol/" + this.version);
	}

	var ns1 = new Namespace("uri:eacBT/" + this.version);

	var request =
		<ns:RequestCertificate xmlns:ns={ns} xmlns:ns1={ns1}>
			<callbackIndicator>callback_not_possible</callbackIndicator>
			<messageID>
			</messageID>
			<responseURL>
			</responseURL>
			<certReq>{certreq.toString(BASE64)}</certReq>
		</ns:RequestCertificate>

	if (typeof(messageID) != "undefined") {
		request.callbackIndicator = "callback_possible";
		request.messageID.ns1::messageID = messageID;
		request.responseURL.ns1::string = responseURL;
	}

	if (this.verbose) {
		GPSystem.trace(request.toXMLString());
	}

	this.request = request;

	try	{
		var response = this.soapcon.call(this.url, request);
		if (this.verbose) {
			GPSystem.trace(response.toXMLString());
		}
	}
	catch(e) {
		GPSystem.trace("SOAP call to " + this.url + " failed : " + e);
		throw new GPError("TAConnection", GPError.DEVICE_ERROR, 0, "RequestCertificate failed with : " + e);
	}
	
	this.response = response;

	var certlist = [];

	this.lastReturnCode = response.Result.ns1::returnCode.toString();
	
	if (this.lastReturnCode.substr(0, 3) == "ok_") {
		GPSystem.trace("Received certificates from DVCA:");
		for each (var c in response.Result.ns1::certificateSeq.ns1::certificate) {
			var cvc = new ByteString(c, BASE64);
			certlist.push(cvc);
			GPSystem.trace(cvc);
		}
	} else {
		return null;
	}

	return certlist;
}



/**
 * Request a certificate from the parent CA using a web service
 *
 * @param {ByteString} certreq the certificate request
 * @param {String} foreignCAR the CAR of the foreign CVCA
 * @param {String} messageID the messageID for asynchronous requests (optional)
 * @param {String} responseURL the URL to which the asynchronous response is send (optional)
 * @returns the new certificates
 * @type ByteString[]
 */
TAConnection.prototype.requestForeignCertificate = function(certreq, foreignCAR, messageID, responseURL) {

	this.lastReturnCode = null;

	var soapConnection = new SOAPConnection();

	if (this.isCVCA) {
		var ns = new Namespace("uri:EAC-PKI-CVCA-Protocol/" + this.version);
	} else {
		var ns = new Namespace("uri:EAC-PKI-DV-Protocol/" + this.version);
	}

	var ns1 = new Namespace("uri:eacBT/" + this.version);

	var request =
		<ns:RequestForeignCertificate xmlns:ns={ns} xmlns:ns1={ns1}>
			<callbackIndicator>callback_not_possible</callbackIndicator>
			<messageID/>
			<responseURL/>
			<foreignCAR>{foreignCAR}</foreignCAR>
			<certReq>{certreq.toString(BASE64)}</certReq>
		</ns:RequestForeignCertificate>

	if (typeof(messageID) != "undefined") {
		request.callbackIndicator = "callback_possible";
		request.messageID.ns1::messageID = messageID;
		request.responseURL.ns1::string = responseURL;
	}
	
	if (this.verbose) {
		GPSystem.trace(request.toXMLString());
	}

	this.request = request;

	try	{
		var response = this.soapcon.call(this.url, request);
		if (this.verbose) {
			GPSystem.trace(response.toXMLString());
		}
	}
	catch(e) {
		GPSystem.trace("SOAP call to " + this.url + " failed : " + e);
		throw new GPError("TAConnection", GPError.DEVICE_ERROR, 0, "RequestForeignCertificate failed with : " + e);
	}
	
	this.response = response;

	var certlist = [];

	this.lastReturnCode = response.Result.ns1::returnCode.toString();

	if (this.lastReturnCode.substr(0, 3) == "ok_") {
		GPSystem.trace("Received certificates from DVCA:");
		for each (var c in response.Result.ns1::certificateSeq.ns1::certificate) {
			var cvc = new ByteString(c, BASE64);
			certlist.push(cvc);
			GPSystem.trace(cvc);
		}
	} else {
		return null;
	}

	return certlist;
}



/**
 * Send a certificate to the DVCA
 *
 * @param {ByteString[]} certificates the list of certificates to post or null
 * @param {String} messageID the messageID for asynchronous requests (optional)
 * @param {String} statusInfo the statusInfo field of the message
 * @type String
 * @return the returnCode
 */
TAConnection.prototype.sendCertificates = function(certificates, messageID, statusInfo) {

	var soapConnection = new SOAPConnection();

	if (this.isCVCA) {
		var ns = new Namespace("uri:EAC-PKI-DV-Protocol/" + this.version);
	} else {
		var ns = new Namespace("uri:EAC-PKI-TermContr-Protocol/" + this.version);
	}

	var ns1 = new Namespace("uri:eacBT/" + this.version);

	if (this.version == "1.0") {
		var request =
			<ns:SendCertificates xmlns:ns={ns} xmlns:ns1={ns1}>
				<messageID>{messageID}</messageID>
				<statusInfo>{statusInfo}</statusInfo>
				<certificateSeq>
				</certificateSeq>
			</ns:SendCertificates>;
	} else {
		var request =
			<ns:SendCertificates xmlns:ns={ns} xmlns:ns1={ns1}>
				<messageID>
					<ns1:messageID>{messageID}</ns1:messageID>
				</messageID>
				<statusInfo>{statusInfo}</statusInfo>
				<certificateSeq>
				</certificateSeq>
			</ns:SendCertificates>;
	}

	var list = request.certificateSeq;

	if (certificates) {
		for (var i = 0; i < certificates.length; i++) {
			var cvc = certificates[i];
			list.certificate += <ns1:certificate xmlns:ns1={ns1}>{cvc.toString(BASE64)}</ns1:certificate>
		}
	}

	if (this.verbose) {
		GPSystem.trace(request.toXMLString());
	}

	this.request = request;

	try	{
		var response = this.soapcon.call(this.url, request);
		if (this.verbose) {
			GPSystem.trace(response.toXMLString());
		}
	}
	catch(e) {
		GPSystem.trace("SOAP call to " + this.url + " failed : " + e);
		throw new GPError("TAConnection", GPError.DEVICE_ERROR, 0, "SendCertificates failed with : " + e);
	}

	this.response = response;

	this.lastReturnCode = response.Result.ns1::returnCode.toString();
	return this.lastReturnCode;
}



/**
 * Convert a list of certificates in binary format to a list of CVC objects
 *
 * @param {ByteString[]} certlist the list of certificates
 * @type CVC[]
 * @return the list of certificate objects
 */
TAConnection.toCVCList = function(certlist) {
	var certs = [];
	for each (var cvcbin in certlist) {
		certs.push(new CVC(cvcbin));
	}
	return certs;
}



/**
 * Convert a list of certificate objects into a list of certificates in binary format
 *
 * @param {CVC[]} certlist the list of certificate objects
 * @type ByteString[]
 * @return the list of certificates
 */
TAConnection.fromCVCList = function(certlist) {
	var certs = [];
	for each (var cvc in certlist) {
		certs.push(cvc.getBytes());
	}
	return certs;
}



TAConnection.test = function() {
	var c = new TAConnection("http://localhost:8080/se/dvca");
	c.verbose = true;
	var certlist = c.getCACertificates();
}
