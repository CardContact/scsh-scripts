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
	CommonUI.call(this, service);
}

CVCAUI.prototype = new CommonUI();
CVCAUI.constructor = CVCAUI;



/**
 * Serves a details page for pending RequestCertificate requests.
 *
 * <p>The URL processed has the format <caname>/request/<queueindex></p>
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url array of URL path elements
 */
CVCAUI.prototype.handleRequestCertificateRequestDetails = function(req, res, url) {

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
			if (sr.getType() == ServiceRequest.DVCA_REQUEST_FOREIGN_CERTIFICATE) {
				CommonUI.addAction(actions, "request", op.index, ServiceRequest.OK_REQUEST_FORWARDED);
			} else {
				CommonUI.addAction(actions, "request", op.index, ServiceRequest.OK_CERT_AVAILABLE);
			}
			CommonUI.addAction(actions, "request", op.index, ServiceRequest.FAILURE_SYNTAX);
			CommonUI.addAction(actions, "request", op.index, ServiceRequest.FAILURE_INNER_SIGNATURE);
			CommonUI.addAction(actions, "request", op.index, ServiceRequest.FAILURE_OUTER_SIGNATURE);
			CommonUI.addAction(actions, "request", op.index, ServiceRequest.FAILURE_EXPIRED);
			CommonUI.addAction(actions, "request", op.index, ServiceRequest.FAILURE_DOMAIN_PARAMETER);
			CommonUI.addAction(actions, "request", op.index, ServiceRequest.FAILURE_REQUEST_NOT_ACCEPTED);
			CommonUI.addAction(actions, "request", op.index, ServiceRequest.FAILURE_FOREIGNCAR_UNKNOWN);
			CommonUI.addAction(actions, "request", op.index, ServiceRequest.FAILURE_NOT_FORWARDED);
			CommonUI.addAction(actions, "request", op.index, ServiceRequest.FAILURE_REQUEST_NOT_ACCEPTED_FOREIGN);
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
CVCAUI.prototype.serveStatusPage = function(req, res, url) {

	// Handle status page
	// ToDo: Refactor to getter
	var status = this.service.cvca.isOperational() ? "operational" : "not operational";

	var page =
		<div>
			<h1>CVCA Service {status}</h1>
			<div id="activechain"/>
			<div id="outboundrequests"/>
			<div id="inboundrequests"/>
			<h2>Possible actions:</h2>
			<form action="" method="get">
				Public Key Specification
				<input name="op" type="hidden" value="change"/>
				<select name="keyspec" size="1">
				</select>
				<button type="submit">Change</button>
			</form>
			<ul>
			</ul>
			<p><a href={url[0] + "/holderlist?path=" + this.service.path }>Browse Document Verifier...</a></p>
		</div>
	
	var l = page.form.select;
	for (var i = 0; i < CVCAService.KeySpecification.length; i++) {
		var o = CVCAService.KeySpecification[i];
		if (this.service.currentKeySpec == o.id) {
			l.option += <option value={o.id} selected="selected">{o.name}</option>
		} else {
			l.option += <option value={o.id}>{o.name}</option>
		}
	}
	
	var l = page.ul;
	
	// ToDo: Refactor to getter
	if (this.service.cvca.isOperational()) {
		l.li += <li><a href="?op=link">Generate link certificate without domain parameter</a></li>
		l.li += <li><a href="?op=linkdp">Generate link certificate with domain parameter</a></li>
		l.li += <li><a href="?op=linkdp10">Generate 10 link certificates with domain parameter</a></li>
	} else {
		l.li += <li><a href="?op=linkdp">Generate root certificate</a></li>
	}
	
	l.li += <li><a href="?op=getcacertificates">Get CA certificates of registered SPOCs</a></li>

	// ToDo: Refactor to getter
	var certlist = this.service.cvca.getCertificateList();
	
	if (certlist.length > 0) {
		var t = <table class="content"/>;

		t.colgroup += <colgroup><col width="24"/><col width="24"/><col width="20"/><col width="16"/><col width="16"/></colgroup>
		t.tr += <tr><th>CHR</th><th>CAR</th><th>Type</th><th>Effective</th><th>Expiration</th></tr>;

		var i = certlist.length - 6;
		if (i <= 0) {
			i = 0;
		} else {
			refurl = url[0] + "/certlist?path=" + this.service.path;
			t.tr += <tr><td><a href={refurl}>Older ...</a></td><td></td><td></td><td></td><td></td></tr>;
		}
		
		for (; i < certlist.length; i++) {
			var cvc = certlist[i];
			var selfsigned = cvc.getCHR().equals(cvc.getCAR());
			var refurl = url[0] + "/cvc?" + 
							"path=" + this.service.path + "&" +
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
CVCAUI.prototype.handleInquiry = function(req, res) {
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
			this.handleRequestCertificateRequestDetails(req, res, url);
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
			case "change":
				this.service.changeKeySpecification(operation.keyspec);
				this.serveStatusPage(req, res, url);
				break;
			case "link":
				this.service.generateLinkCertificate(false);
				this.serveRefreshPage(req, res, url);
				break;
			case "linkdp":
				this.service.generateLinkCertificate(true);
				this.serveRefreshPage(req, res, url);
				break;
			case "linkdp10":
				for (var i = 0; i < 10; i++) {
					this.service.generateLinkCertificate(true);
				}
				this.serveRefreshPage(req, res, url);
				break;
			case "getcacertificates":
				var status = this.service.getCACertificatesFromSPOCs();
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
