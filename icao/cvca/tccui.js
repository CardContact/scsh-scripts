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
 * @fileoverview A simple terminal control center (TCC) web GUI
 */



/**
 * Create a terminal control center (TCC) web GUI
 * 
 * @class Class implementing a simple TCC web user interface
 * @constructor
 * @param {TCCService} service the service to which the GUI is attached
 */
function TCCUI(service) {
	CommonUI.call(this, service);
}

TCCUI.prototype = new CommonUI();
TCCUI.constructor = TCCUI;



/**
 * Serves a details page for pending outbound RequestCertificate requests.
 *
 * <p>The URL processed has the format <caname>/request/<queueindex></p>
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url array of URL path elements
 */
TCCUI.prototype.handleRequestCertificateOutboundRequestDetails = function(req, res, url) {

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
TCCUI.prototype.serveStatusPage = function(req, res, url) {

	// Handle status page
	// ToDo: Refactor to getter
	var status = this.service.tcc.isOperational() ? "operational" : "not operational";

	var page =
		<div>
			<h1>TCC Service {status}</h1>
			<div id="activechain"/>
			<div id="pendingoutboundrequests"/>
			<h2>Possible actions:</h2>
			<ul>
				<li><a href="?op=update">Update CVCA/DVCA certificates synchronously</a></li>
				<li><a href="?op=updateasync">Update CVCA/DVCA certificates asynchronously</a></li>
				<li><a href="?op=initial">Request initial certificate synchronously</a></li>
				<li><a href="?op=initialasync">Request initial certificate asynchronously</a></li>
				<li><a href="?op=renew">Renew certificate synchronously</a></li>
				<li><a href="?OP=renewasync">Renew certificate asynchronously</a></li>
			</ul>
		</div>

	// ToDo: Refactor to getter
	var certlist = this.service.tcc.getCertificateList();
	
	if (certlist.length > 0) {
		var t = <table class="content"/>;

		t.colgroup += <colgroup><col width="24"/><col width="24"/><col width="20"/><col width="16"/><col width="16"/></colgroup>
		t.tr += <tr><th>CHR</th><th>CAR</th><th>Type</th><th>Effective</th><th>Expiration</th></tr>;

		var i = certlist.length - 6;
		if (i <= 0) {
			i = 0;
		} else {
			var ofs = this.service.path.substr(1).indexOf("/") + 1;
			refurl = url[0] + "/certlist?path=" + this.service.path.substr(0, ofs);
			t.tr += <tr><td><a href={refurl}>Older ...</a></td><td></td><td></td><td></td><td></td></tr>;
		}
		
		for (; i < certlist.length; i++) {
			var cvc = certlist[i];
			var chr = cvc.getCHR();
			if (chr.getHolder().equals(this.service.name)) {
				var path = this.service.path;
			} else if (chr.getHolder().equals(this.service.parent)) {
				var path = this.service.path.substr(0, this.service.path.lastIndexOf("/"));
			} else {
				var path = "/" + chr.getHolder();
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
				<td>{CommonUI.dateString(cvc.getCED())}</td>
				<td>{CommonUI.dateString(cvc.getCXD())}</td>
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
TCCUI.prototype.handleInquiry = function(req, res) {
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
		if (req.queryString) {
			// Handle operations
			var operation = CertStoreBrowser.parseQueryString(req.queryString);

			switch(operation.op) {
			case "update":
				var status = this.service.updateCACertificates(false);
				this.serveRefreshPage(req, res, url, status);
				break;
			case "updateasync":
				var status = this.service.updateCACertificates(true);
				this.serveRefreshPage(req, res, url, status);
				break;
			case "renew":
				var status = this.service.renewCertificate(false, false);
				this.serveRefreshPage(req, res, url, status);
				break;
			case "renewasync":
				var status = this.service.renewCertificate(true, false);
				this.serveRefreshPage(req, res, url, status);
				break;
			case "initial":
				var status = this.service.renewCertificate(false, true);
				this.serveRefreshPage(req, res, url, status);
				break;
			case "initialasync":
				var status = this.service.renewCertificate(true, true);
				this.serveRefreshPage(req, res, url, status);
				break;
			default:
				this.serveRefreshPage(req, res, url, "Invalid operation " + operation.op);
			}
		} else {
			this.serveStatusPage(req, res, url);
		}
	}
}
