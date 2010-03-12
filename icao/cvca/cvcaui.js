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
 * @fileoverview A simple CVCA web GUI
 */



/**
 * Create a CVCA web GUI
 * 
 * @class Class implementing a simple CVCA web user interface
 * @constructor
 * @param {CVCAService} service the service to which the GUI is attached
 */
function CVCAUI(service) {
	this.service = service;
}



/**
 * Serves a simple certificate details page.
 *
 * <p>The URL processed has the format <caname>/cvc/<cert.chr></p>
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url array of URL path elements
 */
CVCAUI.prototype.handleCertificateDetails = function(req, res, url) {

	// ToDo: Refactor to getter
	
	var chr = url[2];
	var ss = url.indexOf(".selfsigned");
	
	if (ss >= 0) {
		chr = chr.substring(0, ss);
	}
	
	var cert = this.service.ss.getCertificate(this.service.name, chr, ss >= 0);
	cert.decorate();
	
	var page = 
		<html>
			<head>
				<title>Certificate details</title>
				<link rel="stylesheet" type="text/css" href="../../../css/style.css"/>
				
			</head>
			<body>
				<div align="left"><a href="http://www.cardcontact.de"><img src="../../../images/banner.jpg" width="750" height="80" border="0"/></a></div>
				<br/>
				<h1>Certificate Details</h1>
				<p>{cert.toString()}</p>
				<ul>
				</ul>
				<pre>
					{cert.getASN1().toString()}
				</pre>
			</body>
		</html>;

	var l = page.body.ul;
	var rights = cert.getRightsAsList();

	for (var i = 0; i < rights.length; i++) {
		l.li += <li>{rights[i]}</li>
	}
	
	res.print(page.toXMLString());
	return;
}



/**
 * Serves a details page for pending GetCertifcate requests.
 *
 * <p>The URL processed has the format <caname>/getcert/<queueindex></p>
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url array of URL path elements
 */
CVCAUI.prototype.handleGetCertificateRequestDetails = function(req, res, url) {

	var index = parseInt(url[2]);
	var sr = this.service.getRequest(index);
	
	// Handle operations
	var operation = req.queryString;

	if (operation != null) {
		if (operation == "delete") {
			this.service.deleteRequest(index);
			this.serveRefreshPage(req, res, "../../" + url[0]);
		} else {
			sr.setStatusInfo(operation);
			this.service.processRequest(index);
			this.serveRefreshPage(req, res, "../../" + url[0]);
		}
	} else {
		var page = 
			<html>
				<head>
					<title>GetCertificate request details</title>
					<link rel="stylesheet" type="text/css" href="../../../css/style.css"/>
				</head>
				<body>
					<div align="left"><a href="http://www.cardcontact.de"><img src="../../../images/banner.jpg" width="750" height="80" border="0"/></a></div>
					<br/>
					<h1>Pending GetCertificates request</h1>
					<p>  MessageID: {sr.getMessageID()}</p>
					<p>  ResponseURL: {sr.getResponseURL()}</p>
					<h2>Possible actions:</h2>
					<ul>
						<li><a href="?ok_cert_available">Respond</a> with "ok_cert_available"</li>
						<li><a href="?failure_syntax">Respond</a> with "failure_syntax"</li>
						<li><a href="?failure_request_not_accepted">Respond</a> with "failure_request_not_accepted"</li>
						<li><a href="?delete">Delete</a> request without a response</li>
					</ul>
				</body>
			</html>;

		res.print(page.toXMLString());
	}
}



/**
 * Serves a details page for pending RequestCertifcate requests.
 *
 * <p>The URL processed has the format <caname>/request/<queueindex></p>
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url array of URL path elements
 */
CVCAUI.prototype.handleRequestCertificateRequestDetails = function(req, res, url) {

	var index = parseInt(url[2]);
	var sr = this.service.getRequest(index);
	
	var certreq = sr.getCertificateRequest();
	certreq.decorate();
	
	// Handle operations
	var operation = req.queryString;

	if (operation != null) {
		if (operation == "delete") {
			this.service.deleteRequest(index);
			this.serveRefreshPage(req, res, "../../" + url[0]);
		} else {
			sr.setStatusInfo(operation);
			this.service.processRequest(index);
			this.serveRefreshPage(req, res, "../../" + url[0]);
		}
	} else {
		var page = 
			<html>
				<head>
					<title>RequestCertificate request details</title>
					<link rel="stylesheet" type="text/css" href="../../../css/style.css"/>
				</head>
				<body>
					<div align="left"><a href="http://www.cardcontact.de"><img src="../../../images/banner.jpg" width="750" height="80" border="0"/></a></div>
					<br/>
					<h1>Pending RequestCertificate request</h1>
					<p>  MessageID: {sr.getMessageID()}</p>
					<p>  ResponseURL: {sr.getResponseURL()}</p>
					<h2>Possible actions:</h2>
					<ul>
						<li><a href="?ok_cert_available">Respond</a> with "ok_cert_available"</li>
						<li><a href="?failure_syntax">Respond</a> with "failure_syntax"</li>
						<li><a href="?failure_inner_signature">Respond</a> with "failure_inner_signature"</li>
						<li><a href="?failure_outer_signature">Respond</a> with "failure_outer_signature"</li>
						<li><a href="?failure_request_not_accepted">Respond</a> with "failure_request_not_accepted"</li>
						<li><a href="?delete">Delete</a> request without a reponse</li>
					</ul>
					<pre>{certreq.getASN1()}</pre>
				</body>
			</html>;

		res.print(page.toXMLString());
	}
}



/**
 * Serves a refresh page that redirects back to the given URL
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String} refreshUrl the redirect URL
 */
CVCAUI.prototype.serveRefreshPage = function(req, res, refreshUrl) {

	var page = 
		<html>
			<head>
				<meta http-equiv="Refresh" content={"1; url=" + refreshUrl}/>
				<link rel="stylesheet" type="text/css" href="../css/style.css"/>
				<title>Operation completed</title>
				
			</head>
			<body>
				<div align="left"><a href="http://www.cardcontact.de"><img src="../images/banner.jpg" width="750" height="80" border="0"/></a></div>
				<br/>
				<p>Operation completed - <a href={refreshUrl}>Back to overview</a></p>
			</body>
		</html>

	res.print(page.toXMLString());
	return;
}



/**
 * Serve the status page
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 */
CVCAUI.prototype.serveStatusPage = function(req, res, url) {

	// Handle status page
	// ToDo: Refactor to getter
	var status = this.service.cvca.isOperational() ? "operational" : "not operational";
	var page =
		<html>
			<head>
				<title>CVCA</title>
				<link rel="stylesheet" type="text/css" href="../css/style.css"/>
			</head>
			<body>
				<div align="left"><a href="http://www.cardcontact.de"><img src="../images/banner.jpg" width="750" height="80" border="0"/></a></div>
				<br/>
				<h1>CVCA Service {status}</h1>
				<h2>Active certificate chain:</h2>
				<ol>
				</ol>
				<h2>Pending requests:</h2>
				<ol>
				</ol>
				<h2>Possible actions:</h2>
				<ul>
				</ul>
			</body>
		</html>
	
	var l = page.body.ul;
	
	// ToDo: Refactor to getter
	if (this.service.cvca.isOperational()) {
//		l.li += <li><a href="?link">Generate link certificate without domain parameter</a></li>
		l.li += <li><a href="?linkdp">Generate link certificate with domain parameter</a></li>
	} else {
		l.li += <li><a href="?linkdp">Generate root certificate</a></li>
	}
	
	// ToDo: Refactor to getter
	var certlist = this.service.cvca.getCertificateList();
	
	// Certificate list
	var l = page.body.ol[0];
	for (var i = 0; i < certlist.length; i++) {
		var cvc = certlist[i];
		var postfix = (cvc.getCHR().equals(cvc.getCAR()) ? ".selfsigned" : "");
		var refurl = url[0] + "/cvc/" + cvc.getCHR().toString() + postfix;
		l.li += <li><a href={refurl}>{cvc.toString()}</a></li>;
	}
	
	// Pending requests list
	var l = page.body.ol[1];

	var queue = this.service.listRequests();
	
	for (var i = 0; i < queue.length; i++) {
		var sr = queue[i];

		if (sr.isCertificateRequest()) {
			var refurl = url[0] + "/request/" + i;
		} else {
			var refurl = url[0] + "/getcert/" + i;
		}
		l.li += <li><a href={refurl}>{sr.toString()}</a></li>;
	}
	res.print(page.toXMLString());
}



/**
 * Dispatch all GET inquiries
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 */
CVCAUI.prototype.handleInquiry = function(req, res) {
	// pathInfo always starts with an "/"
	var url = req.pathInfo.substr(1).split("/");

	// Handle details
	if (url.length > 2) {
		var detailsType = url[1];
		GPSystem.trace("Handle details for :" + detailsType);
		switch(detailsType) {
		case "cvc":
			this.handleCertificateDetails(req, res, url);
			break;
		case "getcert":
			this.handleGetCertificateRequestDetails(req, res, url);
			break;
		case "request":
			this.handleRequestCertificateRequestDetails(req, res, url);
			break;
		default:
			res.setStatus(HttpResponse.SC_NOT_FOUND);
		}
	} else {
		// Handle operations
		var operation = req.queryString;
	
		switch(operation) {
		case "link":
			this.service.generateLinkCertificate(false);
			this.serveRefreshPage(req, res, url[0]);
			break;
		case "linkdp":
			this.service.generateLinkCertificate(true);
			this.serveRefreshPage(req, res, url[0]);
			break;
		default:
			this.serveStatusPage(req, res, url);
		}
	}
}
