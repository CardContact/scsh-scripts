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
 * @fileoverview Connector implementing a web service interface to a SPOC for the
 * distribution of card verifiable certificates used for terminal authentication as defined in CSN 36 9791
 */



/**
 * Creates a web service connector to access services of a SPOC as defined in CSN 36 9791
 *
 * @class Class implementing a SPOC web service connector
 * @constructor
 * @param {String} url the web service endpoint
 */
function SPOCConnection(url) {
	this.url = url;
	this.soapcon = new SOAPConnection(SOAPConnection.SOAP11);
	this.verbose = true;
	this.lastError = null;
}



/**
 * Get the last error return code
 *
 * @returns the last error return code received or null if none defined
 * @type String
 */
SPOCConnection.prototype.getLastError = function() {
	return this.lastError;
}



/**
 * Close the connector and release allocated resources
 */
SPOCConnection.prototype.close = function() {
	this.soapcon.close();
}



/**
 * Obtain a list of certificates from the DVCA
 *
 * @returns a lists of card verifiable certificates from the DVCA or null in case of error
 * @type CVC[]
 */
SPOCConnection.prototype.getCACertificates = function(callerID, messageID) {

	this.lastError = null;

	var ns = new Namespace("http://namespaces.unmz.cz/csn369791");

	var request =
		<csn:GetCACertificatesRequest xmlns:csn={ns}>
			<csn:callerID>{callerID}</csn:callerID>
			<csn:messageID>{messageID}</csn:messageID>
		</csn:GetCACertificatesRequest>

	if (this.verbose) {
		GPSystem.trace(request.toXMLString());
	}

	try	 {
		var response = this.soapcon.call(this.url, request);
		if (this.verbose) {
			GPSystem.trace(response.toXMLString());
		}
	}
	catch(e) {
		GPSystem.trace("SOAP call to " + this.url + " failed : " + e);
		throw new GPError("SPOCConnection", GPError.DEVICE_ERROR, 0, "getCACertificates failed with : " + e);
	}
	
	var certlist = [];

	if (response.ns::result.toString() == "ok_cert_available") {
		for each (var c in response.ns::certificateSequence.ns::certificate) {
			var cvc = new ByteString(c, BASE64);
			certlist.push(cvc);
			GPSystem.trace(cvc);
		}
	} else {
		this.lastError = response.ns::result.toString();
		return null;
	}

	return certlist;
}



/**
 * Request a certificate from the parent CA using a web service
 *
 * @param {CVC} certreq the certificate request
 * @returns the new certificates
 * @type CVC[]
 */
SPOCConnection.prototype.requestCertificate = function(certreq) {

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
			<certReq>{certreq.getBytes().toString(BASE64)}</certReq>
		</ns:RequestCertificate>

	if (this.verbose) {
		GPSystem.trace(request.toXMLString());
	}

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
	
	var certlist = [];

	if (response.Result.ns1::returnCode.substr(0, 3) == "ok_") {
		GPSystem.trace("Received certificates from DVCA:");
		for each (var c in response.Result.ns1::certificateSeq.ns1::certificate) {
			var cvc = new CVC(new ByteString(c, BASE64));
			certlist.push(cvc);
			GPSystem.trace(cvc);
		}
	} else {
		this.lastError = response.Result.ns1::returnCode.toString();
		return null;
	}

	return certlist;
}



/**
 * Send a certificate to the DVCA
 *
 * @param {CVC[]} cert the list of certificates to post
 */
SPOCConnection.prototype.sendCertificates = function(certificates, callerID, messageID, statusInfo) {

	var soapConnection = new SOAPConnection();

	var ns = new Namespace("http://namespaces.unmz.cz/csn369791");

	var request =
			<csn:SendCertificatesRequest xmlns:csn={ns}>
				<csn:callerID>{callerID}</csn:callerID>
				<!--Optional:-->
				<csn:messageID>{messageID}</csn:messageID>
				<!--Optional:-->
				<csn:certificateSequence>
				</csn:certificateSequence>
				<csn:statusInfo>{statusInfo}</csn:statusInfo>
			</csn:SendCertificatesRequest>

	var list = request.ns::certificateSequence;

	for (var i = 0; i < certificates.length; i++) {
		var cvc = certificates[i];
		list.ns::certificate += <ns:certificate xmlns:ns={ns}>{cvc.getBytes().toString(BASE64)}</ns:certificate>
	}

	if (this.verbose) {
		GPSystem.trace(request.toXMLString());
	}

	try	{
		var response = this.soapcon.call(this.url, request);
		if (this.verbose) {
			GPSystem.trace(response.toXMLString());
		}
	}
	catch(e) {
		GPSystem.trace("SOAP call to " + this.url + " failed : " + e);
		throw new GPError("SPOCConnection", GPError.DEVICE_ERROR, 0, "SendCertificates failed with : " + e);
	}

	var result = response.ns::result.toString();
	if (result.substr(0, 3) != "ok_") {
		this.lastError = result;
	}
	
	return result;
}



SPOCConnection.test = function() {
	var c = new SPOCConnection("http://localhost:8080/se/spoc");
	c.verbose = true;
	var certlist = c.getCACertificates("UT", "4711");
	for (var i = 0; i < certlist.length; i++) {
		print(certlist[i]);
	}
}
