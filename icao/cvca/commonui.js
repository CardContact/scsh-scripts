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
 * @fileoverview Common UI elements
 */



/**
 * Create a Common UI web GUI
 * 
 * @class Class implementing a common UI operations
 * @constructor
 * @param {CVCAService} service the service to which the GUI is attached
 */
function CommonUI(service) {
	if (service) {
		this.service = service;
		this.certstorebrowser = new CertStoreBrowser(service.ss);
		this.bookmarks = [];
	}
}



/**
 * Create a date string for a given date object in the format YYYY-MM-DD
 *
 * @param {Date} date the date object
 * @type String
 * @return the date string
 */
CommonUI.dateString = function(date) {
	return date.getFullYear() + "-" + (date.getMonth() + 1) + "-" + date.getDate();
}



/**
 * Generate a HTML template
 *
 * @param {String[]} url the array of URL elements
 * @returns the HTML page template
 * @type XML
 */
CommonUI.prototype.generateTemplate = function(url) {

	var prefix = "";
	for (var i = 1; i < url.length; i++) {
		prefix += "../";
	}
	
	var pagetemplate = 
		<html>
			<head>
				<title>{this.service.type + " " + this.service.name}</title>
				<link rel="stylesheet" type="text/css" href={prefix + "../css/style.css"}/>
			</head>
			<body>
				<div align="left">
					<a href="http://www.cardcontact.de"><img src={prefix + "../images/banner.jpg"} width="750" height="80" border="0"/></a>
				</div>
				<div id="navigator">
					<p><b>{this.service.type}</b></p>
					<a href={prefix + url[0]}>Home</a><br/>
					<br/>
					<a href={prefix + url[0] + "/holderlist?path="}>Certificates</a><br/>
					<br/>
					<div id="bookmarks"/>
				</div>
				<div id="main">
					<div id="content"/>
					<p class="copyright">(c) Copyright 2003 - 2011 <a href="http://www.cardcontact.de">CardContact</a> Software &amp; System Consulting, Minden, Germany</p>
				</div>
			</body>
		</html>
	return pagetemplate;
}



/**
 * Send page after embedding in the HTML template
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url the array of URL elements
 * @param {XML} page the page contents
 */
CommonUI.prototype.sendPage = function(req, res, url, page) {
	var t = this.generateTemplate(url);
	var c = t..div.(@id == "content");
	c.div = page;
	
	var bml = <div/>;
	for (var i = 0; i < this.bookmarks.length; i++) {
		var bm = this.bookmarks[i];
		bml.appendChild(<a href={bm.url}>{bm.name}</a>);
		bml.appendChild(<br/>);
	}
	var c = t..div.(@id == "bookmarks");
	c.div = bml;
	
	res.setContentType("text/html");
	res.print('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">\n');
	res.print(t.toXMLString());
}



/**
 * Add a bookmark shown on the navigation panel
 *
 * @param {String} name the name to display
 * @param {String} url the URL for this bookmark
 */
CommonUI.prototype.addBookmark = function(name, url) {
	var m = { name: name, url: url };
	this.bookmarks.push(m);
}



/**
 * Serves a simple certificate details page.
 *
 * <p>The URL processed has the format <caname>/cvc?path=path&chr=chr&selfsigned=true|false</p>
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url array of URL path elements
 */
CommonUI.prototype.handleCertificateDetails = function(req, res, url) {

	var op = CertStoreBrowser.parseQueryString(req.queryString);
	
	var ss = false;
	if (typeof(op.selfsigned) != "undefined") {
		ss = op.selfsigned == "true";
	}
	
	var chr = new PublicKeyReference(op.chr);
	
	if (typeof(op.op) != "undefined") {
		var cert = this.service.ss.getCertificateBinary(op.path, chr, ss);
		res.setContentType("application/octet-stream");
		res.setContentLength(cert.length);
		var filename = op.chr + ".cvcert";
		// ToDo: Remove nativeResponse once addHeader is provided in host class
		res.nativeResponse.addHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
		res.write(cert);
	} else {
		var cert = this.service.ss.getCertificate(op.path, chr, ss);
		cert.decorate();
	
		var page = 
			<div>
				<h1>Certificate Details</h1>
				<a href={url[url.length - 1] + "?" + req.queryString + "&op=download"}>Download...</a>
				<p>{cert.toString()}</p>
				<ul/>
				<pre>
					{cert.getASN1().toString()}
				</pre>
			</div>;

		var l = page.ul;
		var rights = cert.getRightsAsList();
	
		for (var i = 0; i < rights.length; i++) {
			l.li += <li>{rights[i]}</li>
		}
	
		this.sendPage(req, res, url, page);
	}
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
CommonUI.prototype.handleGetCertificateRequestDetails = function(req, res, url) {

	var op = CertStoreBrowser.parseQueryString(req.queryString);
	
	var index = parseInt(op.index);
	var sr = this.service.getInboundRequest(index);
	
	if (typeof(op.action) != "undefined") {
		if (op.action == "delete") {
			this.service.deleteInboundRequest(index);
			this.serveRefreshPage(req, res, url);
		} else {
			sr.setStatusInfo(op.action);
			var status = this.service.processRequest(index);
			this.serveRefreshPage(req, res, url, status);
		}
	} else {
		var page = this.renderServiceRequestPage(sr);

		var actions = <ul/>
		
		if (sr.getMessageID()) {
			CommonUI.addAction(actions, "getcert", op.index, ServiceRequest.OK_CERT_AVAILABLE);
			CommonUI.addAction(actions, "getcert", op.index, ServiceRequest.FAILURE_SYNTAX);
			CommonUI.addAction(actions, "getcert", op.index, ServiceRequest.FAILURE_INTERNAL_ERROR);
		}

		actions.li += <li><a href={"getcert?index=" + op.index + "&action=delete"}>Delete</a> request</li>

		var div = page.div.(@id == "actions");
		div.h2 = <h2>Possible Actions</h2>
		div.h2 += actions;

		this.sendPage(req, res, url, page);
	}
}



/**
 * Render a basic details page for service requests
 *
 * @param {ServiceRequest} sr the service request
 * @type XML
 * @return the XML fragment for the page
 */
CommonUI.prototype.renderServiceRequestPage = function(sr) {

	var finalStatusInfo = sr.getFinalStatusInfo();
	status = finalStatusInfo ? "Completed" : "Pending";
	var page = 
		<div>
			<h1>{status} Request</h1>
			<table class="content">
				<colgroup><col width="20"/><col width="80"/></colgroup>
				<tr><td>Type</td><td>{sr.getType()}</td></tr>
				<tr><td>StatusInfo</td><td>{sr.getStatusInfo()}</td></tr>
			</table>
			<div id="message"/>
			<div id="actions"/>
			<div id="request"/>
			<div id="certificates"/>
			<div id="soaprequest"/>
			<div id="soapresponse"/>
		</div>;

	if (finalStatusInfo) {
		page.table.tr += <tr><td>FinalStatusInfo</td><td>{finalStatusInfo}</td></tr>
	}

	var callerID = sr.getCallerID();
	if (callerID) {
		page.table.tr += <tr><td>CallerID</td><td>{callerID}</td></tr>
	}

	var messageID = sr.getMessageID();
	if (messageID) {
		page.table.tr += <tr><td>MessageID</td><td>{messageID}</td></tr>
	}

	var responseURL = sr.getResponseURL();
	if (responseURL) {
		page.table.tr += <tr><td>URL</td><td>{responseURL}</td></tr>
	}
		
	var foreignCAR = sr.getForeignCAR();
	if (foreignCAR) {
		page.table.tr += <tr><td>Foreign CAR</td><td>{foreignCAR}</td></tr>
	}
		
	var message = sr.getMessage();
	if (message) {
		var div = page.div.(@id == "message");
		div.h2 = <h2>Message</h2>
		div.h2 += <pre>{message}</pre>;
	}
	
	if (sr.isCertificateRequest()) {
		var certreq = sr.getCertificateRequest();
		certreq.decorate();
		var div = page.div.(@id == "request");
		div.h2 = <h2>Certificate Request</h2>
		div.h2 += <pre>{certreq.getASN1()}</pre>
	}

	var certlist = sr.getCertificateList();
	if (certlist) {
		var div = page.div.(@id == "certificates");
		div.h2 = <h2>Certificate List</h2>
		
		var str = "";
		for each (var cvc in certlist) {
			str += cvc.toString() + "\n";
		}
		div.h2 += <pre>{str}</pre>;
	}
	
	var soapRequest = sr.getSOAPRequest();
	if (soapRequest) {
		var div = page.div.(@id == "soaprequest");
		div.h2 = <h2>SOAP Request</h2>
		div.h2 += <pre>{soapRequest.toXMLString()}</pre>
	}

	var soapResponse = sr.getSOAPResponse();
	if (soapResponse) {
		var div = page.div.(@id == "soapresponse");
		div.h2 = <h2>SOAP Response</h2>
		div.h2 += <pre>{soapResponse.toXMLString()}</pre>
	}

	return page;
}



/**
 * Render a list of service requests
 *
 * @param {ServiceRequest[]} srlist the service request list
 * @param {boolean} isout is the outbound queue
 * @param {String} url the base URL for generating links
 * @type XML
 * @return the XML fragment for the page
 */
CommonUI.prototype.renderServiceRequestListPage = function(srlist, isout, url) {
	var t = <table class="content"/>;

	t.tr += <tr><th width="20%">MessageID</th><th>Request</th><th>Status</th><th>Final Status</th></tr>;

	for (var i = 0; i < srlist.length; i++) {
		var sr = srlist[i];
		
		if (isout) {
			var refurl = url + "/outrequest?index=" + i;
		} else {
			if (sr.getType() == ServiceRequest.SPOC_GENERAL_MESSAGE) {
				var refurl = url + "/message?index=" + i;
			} else {
				if (sr.isCertificateRequest()) {
					var refurl = url + "/request?index=" + i;
				} else {
					var refurl = url + "/getcert?index=" + i;
				}
			}
		}
		
		var messageID = sr.getMessageID();
		if  (!messageID) {
			messageID = "Synchronous";
			finalStatus = "Completed";
		} else {
			var finalStatus = sr.getFinalStatusInfo();
			if (!finalStatus) {
				if (isout) {
					finalStatus = "Not yet received";
				} else {
					finalStatus = "Not yet send";
				}
			}
		}
			
		if (sr.isCertificateRequest()) {
			var reqstr = sr.getCertificateRequest().toString();
		} else {
			var reqstr = sr.getType();
			if (reqstr) {
				reqstr = reqstr.substr(0, 21);
			} else {
				reqstr = "Unknown";
			}
		}
		
		var status = sr.getStatusInfo();
		if (!status) {
			status = "Undefined";
		}
		
		t.tr += <tr>
					<td><a href={refurl}>{messageID.substr(0, 14)}</a></td>
					<td>{reqstr}</td>
					<td>{status.substr(0, 21)}</td>
					<td>{finalStatus.substr(0, 21)}</td>
				</tr>
	}
	
	return t;
}



/**
 * Serves a details page for outbound service requests.
 *
 * <p>The URL processed has the format <caname>/request/<queueindex></p>
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url array of URL path elements
 */
CommonUI.prototype.handleOutboundRequestDetails = function(req, res, url) {

	var op = CertStoreBrowser.parseQueryString(req.queryString);
	
	var index = parseInt(op.index);
	var sr = this.service.getOutboundRequest(index);

	var certreq = sr.getCertificateRequest();
	if (typeof(op.action) != "undefined") {
		var reqbin = certreq.getBytes();
		res.setContentType("application/octet-stream");
		res.setContentLength(reqbin.length);
		var filename = certreq.getCHR().toString() + ".cvreq";
		// ToDo: Remove nativeResponse once addHeader is provided in host class
		res.nativeResponse.addHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
		res.write(reqbin);
	} else {
		var page = this.renderServiceRequestPage(sr);

		if (certreq) {
			var div = page.div.(@id == "request");
			div.h2 += <a href={url[url.length - 1] + "?" + req.queryString + "&action=download"}>Download...</a>
		}
		
		this.sendPage(req, res, url, page);
	}
}



/**
 * Serves a simple certificate list page.
 *
 * <p>The URL processed has the format <caname>/certificates?path=path&start=start</p>
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url array of URL path elements
 */
CommonUI.prototype.handleCertificateList = function(req, res, url) {

	var page = 
		<div>
			<h1>Certificates</h1>
			<div/>
		</div>;

	page.div = this.certstorebrowser.generateCertificateList(req.queryString, "holderlist", "certlist", "cvc");
	
	this.sendPage(req, res, url, page);
}



/**
 * Serves a simple certificate holder list page.
 *
 * <p>The URL processed has the format <caname>/holder?path=path&start=start</p>
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url array of URL path elements
 */
CommonUI.prototype.handleCertificateHolderList = function(req, res, url) {

	var page = 
		<div>
			<h1>Certificate Holder</h1>
			<div/>
		</div>;

	page.div = this.certstorebrowser.generateCertificateHolderList(req.queryString, "holderlist", "certlist");
	
	this.sendPage(req, res, url, page);
}



/**
 * Serves a refresh page that redirects back to the given URL
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String} refreshUrl the redirect URL
 * @param {String} statusMessage the status message or undefined
 */
CommonUI.prototype.serveRefreshPage = function(req, res, url, statusMessage) {

	var prefix = "";
	for (var i = 1; i < url.length; i++) {
		prefix += "../";
	}

	var page = this.generateTemplate(url);
	
	if ((typeof(statusMessage) == "undefined") || (statusMessage == null)) {
		statusMessage = "Operation completed";
	}
	
	page.head.meta = <meta http-equiv="Refresh" content={"1; url=" + prefix + url[0]}/>;
	
	var c = page..div.(@id == "content");

	c.div = <p>{statusMessage}</p>
	
	res.setContentType("text/html");
	res.print('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">\n');
	res.print(page.toXMLString());
}



/**
 * Add an action entry to the list of possible actions
 *
 * @param {XML} ul the list of action elements
 * @param {String} cmd the command part of the URL
 * @param {Number} index the index into the service request list
 * @param {String} action the action to be performed
 */
CommonUI.addAction = function(ul, cmd, index, action) {
	ul.li += <li><a href={cmd + "?index=" + index + "&action=" + action}>Respond</a>{" with " + action}</li>
}