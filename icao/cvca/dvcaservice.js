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
	this.crypto = new Crypto();
	
	this.ss = new CVCertificateStore(path);
	this.dvca = new CVCCA(this.crypto, this.ss, name, parent);
	this.parentURL = parentURL;
	this.queue = [];
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
 * Update certificate list from parent CA
 *
 */
DVCAService.prototype.updateCACertificates = function(async) {

	var msgid = null;
	
	if (async) {
		msgid = this.crypto.generateRandom(2).toString(HEX);
	}

	var certlist = this.getCACertificatesFromCVCA(msgid, this.myURL);
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
DVCAService.prototype.renewCertificate = function(async) {

	// Create a new request
	var req = this.dvca.generateRequest();
	print("Request: " + req);
	print(req.getASN1());

	var msgid = null;
	
	if (async) {
		msgid = this.crypto.generateRandom(2).toString(HEX);
	}

	var certlist = this.requestCertificateFromCVCA(req, msgid, this.myURL);
	
	var list = this.dvca.importCertificates(certlist);

	if (list.length > 0) {
		print("Warning: Could not import the following certificates");
		for (var i = 0; i < list.length; i++) {
			print(list[i]);
		}
	}
}



/**
 * Import certificate
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
 * @returns a list of certificates
 * @type CVC[]
 */
DVCAService.prototype.getCACertificatesFromCVCA = function(messageID, responseURL) {

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

	if (messageID) {
		request.callbackIndicator = "callback_possible";
		request.messageID.ns1::messageID = messageID;
		request.responseURL.ns1::string = responseURL;
	}
	
	var response = soapConnection.call(this.parentURL, request);
	
	if (response.Result.ns1::returnCode.substr(0, 3) != "ok_") {
		GPSystem.trace("GetCACertificates failed:");
		GPSystem.trace(response);
		throw new GPError("DVCAService", GPError.DEVICE_ERROR, 0, "GetCACertificates failed with returnCode " + response.Result.ns1::returnCode);
	}
	
	var certlist = [];
	GPSystem.trace("Received certificates from CVCA:");
	for each (var c in response.Result.ns1::certificateSeq.ns1::certificate) {
		var cvc = new CVC(new ByteString(c, BASE64));
		certlist.push(cvc);
		GPSystem.trace(cvc);
	}

	return certlist;
}



/**
 * Request a certificate from the parent CA using a web service
 *
 * @returns the new certificate
 * @type CVC[]
 */
DVCAService.prototype.requestCertificateFromCVCA = function(request, messageID, responseURL) {

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
			<certReq>{request.getBytes().toString(BASE64)}</certReq>
		</ns:RequestCertificate>

	if (messageID) {
		request.callbackIndicator = "callback_possible";
		request.messageID.ns1::messageID = messageID;
		request.responseURL.ns1::string = responseURL;
	}
		
	try	{
		var response = soapConnection.call(this.parentURL, request);
	}
	catch(e) {
		GPSystem.trace("SOAP call at " + this.parentURL + " failed : " + e);
		throw new GPError("DVCAService", GPError.DEVICE_ERROR, 0, "RequestCertificates failed with : " + e);
	}
	
	if (response.Result.ns1::returnCode.substr(0, 3) != "ok_") {
		GPSystem.trace("RequestCertificates failed:");
		GPSystem.trace(response);
		throw new GPError("DVCAService", GPError.DEVICE_ERROR, 0, "RequestCertificates failed with returnCode " + response.Result.ns1::returnCode);
	}
	
	var certlist = [];
	GPSystem.trace("Received certificates from CVCA:");
	for each (var c in response.Result.ns1::certificateSeq.ns1::certificate) {
		var cvc = new CVC(new ByteString(c, BASE64));
		certlist.push(cvc);
		GPSystem.trace(cvc);
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
	
	var response = "ok_received_correctly";

	var certlist = [];
	GPSystem.trace("Received certificates from CVCA:");
	for each (var c in soapBody.certificateSeq.ns1::certificate) {
		var cvc = new CVC(new ByteString(c, BASE64));
		certlist.push(cvc);
		GPSystem.trace(cvc);
	}

	this.importCertificates(certlist);

	var response =
		<ns:SendCertificatesResponse xmlns:ns={ns} xmlns:ns1={ns1}>
			<Result>
				<ns1:returnCode>{response}</ns1:returnCode>
			</Result>
		</ns:SendCertificatesResponse>

	return response;
}



/**
 * Serves a simple certificate details page.
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String} the CHR for the requested certificate
 */
DVCAService.prototype.handleCertificateDetails = function(req, res, chr) {

	var cert = this.ss.getCertificate(this.name, chr);
	cert.decorate();
	
	var page = 
	
		<html>
			<head>
				<title>Certificate details</title>
			</head>
			<body>
				<p>{cert.toString()}</p>
				<ul>
				</ul>
				<pre>
					{cert.getASN1().toString()}
				</pre>
			</body>
		</html>

	var l = page.body.ul;
	var rights = cert.getRightsAsList();
	for (var i = 0; i < rights.length; i++) {
		l.li = <li>{rights[i]}</li>
	}
	
	res.print(page.toXMLString());
	return;
}



/**
 * Serves a simple status page.
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 */
DVCAService.prototype.handleInquiry = function(req, res) {
	var url = req.pathInfo.split("/");

	// Handle details
	if (url.length > 2) {
		return this.handleCertificateDetails(req, res, url[2]);
	}

	var operation = req.queryString;
	var refresh = false;
	
	switch(operation) {
	case "update":
		this.updateCACertificates(false);
		var refresh = true;
		break;
	case "updateasync":
		this.updateCACertificates(true);
		var refresh = true;
		break;
	case "renew":
		this.renewCertificate(false);
		var refresh = true;
		break;
	case "renewasync":
		this.renewCertificate(true);
		var refresh = true;
		break;
	}

	if (refresh) {
		var page = 
		<html>
			<head>
				<meta http-equiv="Refresh" content={"1; url=" + url[1]}/>
				<title>DVCA operation complete</title>
				
			</head>
			<body>
				<p>OK - <a href={url[1]}>Back to overview</a></p>
			</body>
		</html>
		res.print(page.toXMLString());
		return;
	}

	var status = this.dvca.isOperational() ? "operational" : "not operational";
	var page =
		<html>
			<head>
				<title>DVCA</title>
			</head>
			<body>
				<p>DVCA Services {status}</p>
				<p>Certificate chain for this DVCA:</p>
				<ol>
				</ol>
				<p>Pending requests:</p>
				<ol>
				</ol>
				<p>Possible actions:</p>
				<ul>
					<li><a href="?update">Update CVCA certificates synchronously</a></li>
					<li><a href="?updateasync">Update CVCA certificates asynchronously</a></li>
					<li><a href="?renew">Renew certificate synchronously</a></li>
					<li><a href="?renewasync">Renew certificate asychronously</a></li>
				</ul>
			</body>
		</html>;
	
	var certlist = this.dvca.getCertificateList();

	var l = page.body.ol[0];
	for (var i = 0; i < certlist.length; i++) {
		var cvc = certlist[i];
		l.li += <li>{cvc.toString()}</li>;
	}
	
	var l = page.body.ol[1];
	for (var i = 0; i < this.queue.length; i++) {
		var entry = this.queue[i];

		if (entry.request) {
			var cvc = entry.request;
			var refurl = url[1] + "/" + "_R" + i;
			l.li += <li><a href={refurl}>i</a> {entry.msgid + " " + cvc.toString() + " " + entry.url}</li>;
		} else {
			var refurl = url[1] + "/" + "_Q" + i;
			l.li += <li><a href={refurl}>i</a> {entry.msgid + " " + entry.url}</li>;
		}
	}
	res.print(page.toXMLString());
}
