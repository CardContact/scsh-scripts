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
 * @fileoverview A simple DVCA web GUI
 */



/**
 * Create a DVCA web GUI
 * 
 * @class Class implementing a simple DVCA web user interface
 * @constructor
 * @param {DVCAService} service the service to which the GUI is attached
 */
function DVCAUI(service) {
	CommonUI.call(this, service);
}

DVCAUI.prototype = new CommonUI();
DVCAUI.constructor = DVCAUI;



/**
 * Serves a details page for pending outbound RequestCertificate requests.
 *
 * <p>The URL processed has the format <caname>/request/<queueindex></p>
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url array of URL path elements
 */
DVCAUI.prototype.handleRequestCertificateOutboundRequestDetails = function(req, res, url) {

	var op = CertStoreBrowser.parseQueryString(req.queryString);
	
	var index = parseInt(op.index);
	var sr = this.service.getOutboundRequest(index);
	
	var certreq = sr.getCertificateRequest();
	certreq.decorate();
	
	var page = 
		<div>
			<h1>Outbound RequestCertificate request</h1>
			<p>  MessageID: {sr.getMessageID()}</p>
			<p>  ResponseURL: {sr.getResponseURL()}</p>
			<pre>{certreq.getASN1()}</pre>
		</div>;

	this.sendPage(req, res, url, page);
}



/**
 * Serve the status page
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 */
DVCAUI.prototype.serveStatusPage = function(req, res, url) {

	// Handle status page
	// ToDo: Refactor to getter
	var status = this.service.dvca.isOperational() ? "operational" : "not operational";

	var page =
		<div>
			<h1>DVCA Service {status}</h1>
			<div id="activechain"/>
			<div id="pendingoutboundrequests"/>
			<h2>Possible actions:</h2>
			<ul>
				<li><a href="?update">Update CVCA certificates synchronously</a></li>
				<li><a href="?updateasync">Update CVCA certificates asynchronously</a></li>
				<li><a href="?renew">Renew certificate synchronously</a></li>
				<li><a href="?renewasync">Renew certificate asynchronously</a></li>
				<li><a href="?initial">Request initial certificate synchronously</a></li>
				<li><a href="?initialasync">Request initial certificate asynchronously</a></li>
			</ul>
			<p><a href={url[0] + "/holderlist?path=" + this.service.path }>Browse Terminals...</a></p>
		</div>
	
	// ToDo: Refactor to getter
	var certlist = this.service.dvca.getCertificateList();
	
	if (certlist.length > 0) {
		var t = <table class="content"/>;

		t.tr += <tr><th>CHR</th><th>CAR</th><th>Type</th><th>Effective</th><th>Expiration</th></tr>;

		var i = certlist.length - 6;
		if (i <= 0) {
			i = 0;
		} else {
			refurl = url[0] + "/certlist?path=/" + this.service.parent;
			t.tr += <tr><td><a href={refurl}>Older ...</a></td><td></td><td></td><td></td><td></td></tr>;
		}
		
		for (; i < certlist.length; i++) {
			var cvc = certlist[i];
			var chr = cvc.getCHR();
			if (chr.getHolder().equals(this.service.name)) {
				var path = this.service.path;
			} else {
				var path = "/" + this.service.parent;
			}
			var selfsigned = cvc.getCHR().equals(cvc.getCAR());
			var refurl = url[0] + "/cvc?" + 
							"path=" + path + "&" +
							"chr=" + cvc.getCHR().toString() + "&" +
							"selfsigned=" + selfsigned;
			t.tr += <tr>
				<td><a href={refurl}>{cvc.getCHR().toString()}</a></td>
				<td>{cvc.getCAR().toString()}</td>
				<td>{cvc.getType()}</td>
				<td>{cvc.getCED().toLocaleDateString()}</td>
				<td>{cvc.getCXD().toLocaleDateString()}</td>
			</tr>
		}
	
		// Certificate list
		var div = page.div.(@id == "activechain");
		div.h2 = "Active certificate chain:";
		div.appendChild(t);
	}
	
	var queue = this.service.listOutboundRequests();
	
	if (queue.length > 0) {
		var t = <table class="content"/>;

		t.tr += <tr><th width="20%">MessageID</th><th>Request</th><th>Status</th><th>Final Status</th></tr>;

		for (var i = 0; i < queue.length; i++) {
			var sr = queue[i];

			var tr = <tr/>;
			var msgid = sr.getMessageID();
			if (!msgid) {
				msgid = "";
			}
			tr.td += <td>{msgid}</td>
			
			if (sr.isCertificateRequest()) {
				var refurl = url[0] + "/outrequest?" + "index=" + i;
				tr.td += <td><a href={refurl}>{sr.getCertificateRequest().toString()}</a></td>;
			} else {
				tr.td += <td>GetCertificates</td>;
			}
			var status = sr.getStatusInfo();
			if (!status) {
				status = "Undefined";
			}
			var finalStatus = sr.getFinalStatusInfo();
			if (!finalStatus) {
				finalStatus = "Not yet received";
			}
			
			tr.td += <td>{status.substr(0, 24)}</td>
			tr.td += <td>{finalStatus.substr(0, 24)}</td>
			t.tr += tr;
		}

		// Pending requests list
		var div = page.div.(@id == "pendingoutboundrequests");
		div.h2 = "Outbound requests:";
		
		div.appendChild(t);
	}

	this.sendPage(req, res, url, page);
}



/**
 * Dispatch all GET inquiries
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 */
DVCAUI.prototype.handleInquiry = function(req, res) {
	// pathInfo always starts with an "/"
	var url = req.pathInfo.substr(1).split("/");

	// Handle details
	if (url.length > 1) {
		var detailsType = url[1];
//		GPSystem.trace("Handle details for :" + detailsType);
		switch(detailsType) {
		case "cvc":
			this.handleCertificateDetails(req, res, url);
			break;
		case "certlist":
			this.handleCertificateList(req, res, url);
			break;
		case "holderlist":
			this.handleCertificateHolderList(req, res, url);
			break;
		case "getcert":
			this.handleGetCertificateRequestDetails(req, res, url);
			break;
		case "outrequest":
			this.handleRequestCertificateOutboundRequestDetails(req, res, url);
			break;
		default:
			res.setStatus(HttpResponse.SC_NOT_FOUND);
		}
	} else {
		// Handle operations
		var operation = req.queryString;

		switch(operation) {
		case "update":
			this.service.updateCACertificates(false);
			this.serveRefreshPage(req, res, url);
			break;
		case "updateasync":
			this.service.updateCACertificates(true);
			this.serveRefreshPage(req, res, url);
			break;
		case "renew":
			this.service.renewCertificate(false, false);
			this.serveRefreshPage(req, res, url);
			break;
		case "renewasync":
			this.service.renewCertificate(true, false);
			this.serveRefreshPage(req, res, url);
			break;
		case "initial":
			this.service.renewCertificate(false, true);
			this.serveRefreshPage(req, res, url);
			break;
		case "initialasync":
			this.service.renewCertificate(true, true);
			this.serveRefreshPage(req, res, url);
			break;
		default:
			this.serveStatusPage(req, res, url);
		}
	}
}
