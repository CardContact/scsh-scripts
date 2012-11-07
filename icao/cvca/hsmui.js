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
 * @fileoverview A simple HSM maintaince web GUI
 */



/**
 * Create a HSM maintainance web GUI
 * 
 * @class Class implementing a simple HSM maintainance user interface
 * @constructor
 * @param {SmartCardHSM} hsm the SmartCard-HSM to which the GUI is attached
 */
function HSMUI(hsm) {
	this.hsm = hsm;
	this.bookmarks = [];
}



/**
 * Generate a HTML template
 *
 * @param {String[]} url the array of URL elements
 * @returns the HTML page template
 * @type XML
 */
HSMUI.prototype.generateTemplate = function(url) {

	var prefix = "";
	for (var i = 1; i < url.length; i++) {
		prefix += "../";
	}
	
	var pagetemplate = 
		<html>
			<head>
				<title>SmartCard-HSM Maintainance</title>
				<link rel="stylesheet" type="text/css" href={prefix + "../css/style.css"}/>
			</head>
			<body>
				<div align="left">
					<a href="http://www.cardcontact.de"><img src={prefix + "../images/banner.jpg"} width="750" height="80" border="0"/></a>
				</div>
				<div id="navigator">
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
HSMUI.prototype.sendPage = function(req, res, url, page) {
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
HSMUI.prototype.addBookmark = function(name, url) {
	var m = { name: name, url: url };
	this.bookmarks.push(m);
}



HSMUI.prototype.determinePINStatus = function(sw) {
	var state = "Unknown";
	
	switch(sw) {
	case 0x9000:
		state = "User PIN verified";
		break;
	case 0x6984:
		state = "SmartCard-HSM not initialized";
		break;
	case 0x6983:
		state = "User PIN blocked";
		break;
	default:
		if ((sw & 0xFF00) != 0x6300) {
			state = "Unknown SW1/SW2 " + sw.toString(HEX);
		} else {
			state = "User PIN not verified. " + (sw & 0xF) + " tries left";
		}
	}
	return state;
}



/**
 * Serve the status page
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url array of URL path elements
 */
HSMUI.prototype.serveStatusPage = function(req, res, url) {

	var sw = this.hsm.queryUserPINStatus();

	var state = this.determinePINStatus(sw);

	var page =
		<div>
			<h1>SmartCard-HSM</h1>
			<p>PIN Status : {state}</p>
			<form action="" method="get">
				<input name="op" type="hidden" value="verifypin"/>
				<input name="pin" type="password" size="20"/>
				<button type="submit">Verify</button>
			</form>
			<form action="" method="get">
				<input name="op" type="hidden" value="logout"/>
				<button type="submit">Logout</button>
			</form>
		</div>

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
HSMUI.prototype.serveRefreshPage = function(req, res, url, statusMessage) {

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
 * Dispatch all GET inquiries
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 */
HSMUI.prototype.handleInquiry = function(req, res) {
	// pathInfo always starts with an "/"
	var url = req.pathInfo.substr(1).split("/");

	// Handle details
	if (url.length > 1) {
		var detailsType = url[1];
//		GPSystem.trace("Handle details for :" + detailsType);
		switch(detailsType) {
		default:
			res.setStatus(HttpResponse.SC_NOT_FOUND);
		}
	} else {
		// Handle operations
		if (req.queryString) {
			// Handle operations
			var operation = CertStoreBrowser.parseQueryString(req.queryString);

			switch(operation.op) {
			case "verifypin":
				var sw = this.hsm.verifyUserPIN(new ByteString(operation.pin, ASCII));
				this.serveRefreshPage(req, res, url, this.determinePINStatus(sw));
				break;
			case "logout":
				this.hsm.logout();
				this.serveStatusPage(req, res, url);
				break;
			default:
				this.serveStatusPage(req, res, url);
			}
		} else {
			this.serveStatusPage(req, res, url);
		}
	}
}
