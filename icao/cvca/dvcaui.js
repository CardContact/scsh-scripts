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
	this.currentCVCA = service.getCVCAList()[0];
}

DVCAUI.prototype = new CommonUI();
DVCAUI.constructor = DVCAUI;



/**
 * Serves a details page for pending RequestCertificate requests.
 *
 * <p>The URL processed has the format <caname>/request/<queueindex></p>
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url array of URL path elements
 */
DVCAUI.prototype.handleRequestCertificateInboundRequestDetails = function(req, res, url) {

	var op = CertStoreBrowser.parseQueryString(req.queryString);
	
	var index = parseInt(op.index);
	var sr = this.service.getInboundRequest(index);
	
	if (typeof(op.action) != "undefined") {
		switch(op.action) {
		case "delete":
			this.service.deleteInboundRequest(index);
			this.serveRefreshPage(req, res, url);
			break;
		case "download":
			var reqbin = certreq.getBytes();
			res.setContentType("application/octet-stream");
			res.setContentLength(reqbin.length);
			var filename = certreq.getCHR().toString() + ".cvreq";
			// ToDo: Remove nativeResponse once addHeader is provided in host class
			res.nativeResponse.addHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
			res.write(reqbin);
			return;
		default:
			sr.setStatusInfo(op.action);
			var status = this.service.processRequest(index);
			this.serveRefreshPage(req, res, url, status);
		}
	} else {
		var page = this.renderServiceRequestPage(sr);
		
		var actions = <ul/>
		
		if (sr.getMessageID()) {
			CommonUI.addAction(actions, "request", op.index, ServiceRequest.OK_CERT_AVAILABLE);
			CommonUI.addAction(actions, "request", op.index, ServiceRequest.FAILURE_SYNTAX);
			CommonUI.addAction(actions, "request", op.index, ServiceRequest.FAILURE_INNER_SIGNATURE);
			CommonUI.addAction(actions, "request", op.index, ServiceRequest.FAILURE_OUTER_SIGNATURE);
			CommonUI.addAction(actions, "request", op.index, ServiceRequest.FAILURE_EXPIRED);
			CommonUI.addAction(actions, "request", op.index, ServiceRequest.FAILURE_DOMAIN_PARAMETER);
			CommonUI.addAction(actions, "request", op.index, ServiceRequest.FAILURE_REQUEST_NOT_ACCEPTED);
			CommonUI.addAction(actions, "request", op.index, ServiceRequest.FAILURE_INTERNAL_ERROR);
		}

		actions.li += <li><a href={"getcert?index=" + op.index + "&action=delete"}>Delete</a> request</li>

		var div = page.div.(@id == "actions");
		div.h2 = <h2>Possible Actions</h2>
		div.h2 += actions;

		var div = page.div.(@id == "request");
		div.h2 += <a href={url[url.length - 1] + "?" + req.queryString + "&action=download"}>Download...</a>

		this.sendPage(req, res, url, page);
	}
}



/**
 * Serve the status page
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url array of URL path elements
 */
DVCAUI.prototype.serveStatusPage = function(req, res, url) {

	// Handle status page
	// ToDo: Refactor to getter
	var status = this.service.isOperational(this.currentCVCA) ? "operational" : "not operational";

	var page =
		<div>
			<h1>DVCA Service {status}</h1>
			<form action="" method="get">
				Select CVCA
				<input name="op" type="hidden" value="changecvca"/>
				<select name="cvca" size="1">
				</select>
				<button type="submit">Change</button>
			</form>
			<div id="activechain"/>
			<div id="outboundrequests"/>
			<div id="inboundrequests"/>
			<h2>Possible actions:</h2>
			<ul>
				<li><a href="?op=update">Update CVCA certificates synchronously</a></li>
				<li><a href="?op=updateasync">Update CVCA certificates asynchronously</a></li>
				<li><a href={"?op=initial&cvca=" + this.currentCVCA}>Request initial certificate synchronously</a></li>
				<li><a href={"?op=initialasync&cvca=" + this.currentCVCA}>Request initial certificate asynchronously</a></li>
				<li><a href={"?op=renew&cvca=" + this.currentCVCA}>Renew certificate synchronously</a></li>
				<li><a href={"?op=renewasync&cvca=" + this.currentCVCA}>Renew certificate asynchronously</a></li>
			</ul>
			<p><a href={url[0] + "/holderlist?path=" + this.service.getPathFor(this.currentCVCA) }>Browse Terminals...</a></p>
		</div>
	
	var l = page.form.select;
	var cvcalist = this.service.getCVCAList();
	
	for each (var holderId in cvcalist) {
		if (this.currentCVCA == holderId) {
			l.option += <option selected="selected">{holderId}</option>
		} else {
			l.option += <option>{holderId}</option>
		}
	}

	var certlist = this.service.getCertificateList(this.currentCVCA);
	
	if (certlist.length > 0) {
		var t = <table class="content"/>;

		t.colgroup += <colgroup><col width="24"/><col width="24"/><col width="20"/><col width="16"/><col width="16"/></colgroup>
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
			var car = cvc.getCAR();

			if (chr.getHolder().equals(car.getHolder())) {		// CVCA certificate
				var path = "/" + chr.getHolder();
			} else {
				var path = "/" + car.getHolder() + "/" + chr.getHolder();
			}

			var selfsigned = chr.equals(car);
			var refurl = url[0] + "/cvc?" + 
							"path=" + path + "&" +
							"chr=" + chr.toString() + "&" +
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
		var t = this.renderServiceRequestListPage(queue, true, url[0]);
		var div = page.div.(@id == "outboundrequests");
		div.h2 = "Outbound requests:";
		div.appendChild(t);
	}

	var queue = this.service.listInboundRequests();

	if (queue.length > 0) {
		var t = this.renderServiceRequestListPage(queue, false, url[0]);

		var div = page.div.(@id == "inboundrequests");
		div.h2 = "Inbound requests:";
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
		case "request":
			this.handleRequestCertificateInboundRequestDetails(req, res, url);
			break;
		case "outrequest":
			this.handleOutboundRequestDetails(req, res, url);
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
			case "changecvca":
				this.currentCVCA = operation.cvca;
				this.serveStatusPage(req, res, url);
				break;
			case "update":
				var status = this.service.updateCACertificates(false);
				this.serveRefreshPage(req, res, url, status);
				break;
			case "updateasync":
				var status = this.service.updateCACertificates(true);
				this.serveRefreshPage(req, res, url, status);
				break;
			case "renew":
				var status = this.service.renewCertificate(false, false, operation.cvca);
				this.serveRefreshPage(req, res, url, status);
				break;
			case "renewasync":
				var status = this.service.renewCertificate(true, false, operation.cvca);
				this.serveRefreshPage(req, res, url, status);
				break;
			case "initial":
				var status = this.service.renewCertificate(false, true, operation.cvca);
				this.serveRefreshPage(req, res, url, status);
				break;
			case "initialasync":
				var status = this.service.renewCertificate(true, true, operation.cvca);
				this.serveRefreshPage(req, res, url, status);
				break;
			default:
				this.serveStatusPage(req, res, url);
			}
		} else {
			this.serveStatusPage(req, res, url);
		}
	}
}
