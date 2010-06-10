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
	
/*
	var pagetemplate = 
		<html>
			<head>
				<title>{this.service.type + " " + this.service.name}</title>
				<link rel="stylesheet" type="text/css" href={prefix + "../css/style.css"}/>
			</head>
			<body>
				<table border="0" cellpadding="0" cellspacing="0" width="750" align="center">
					<tr>
						<td height="80" colspan="5" class="pb">
							<div align="left">
								<a href="http://www.cardcontact.de"><img src={prefix + "../images/banner.jpg"} width="750" height="80" border="0"/></a>
							</div>
						</td>
					</tr>
					<tr height="20"/>
					<tr>
						<td width="100" valign="top" align="left">
							<p><b>{this.service.type}</b></p>
							<a href={prefix + url[0]}>Home</a><br/>
							<br/>
							<a href={prefix + url[0] + "/holderlist?path="}>Certificates</a><br/>
							<br/>
							<div id="bookmarks"/>
						</td>
						<td width="650" align="left">
							<div id="content"/>
							<p class="copyright">(c) Copyright 2003 - 2010 <a href="http://www.cardcontact.de">CardContact</a> Software &amp; System Consulting, Minden, Germany</p>
						</td>
					</tr>
				</table>
			</body>
		</html>
*/
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
					<p class="copyright">(c) Copyright 2003 - 2010 <a href="http://www.cardcontact.de">CardContact</a> Software &amp; System Consulting, Minden, Germany</p>
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
 * @returns the HTML page template
 * @type XML
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
 */
CommonUI.prototype.serveRefreshPage = function(req, res, url) {

	var prefix = "";
	for (var i = 1; i < url.length; i++) {
		prefix += "../";
	}

	var page = this.generateTemplate(url);
	
	page.head.meta = <meta http-equiv="Refresh" content={"1; url=" + prefix + url[0]}/>;
	
	var c = page..div.(@id == "content");
	c.div = <p>Operation completed</p>;
	
	res.print(page.toXMLString());
}
