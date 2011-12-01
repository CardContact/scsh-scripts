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
	this.currentCVCA = service.getCVCAList()[0];
}

CVCAUI.prototype = new CommonUI();
CVCAUI.constructor = CVCAUI;



/**
 * Prepare and send a general message to the SPOC associated with the selected CVCA
 *
 * @param {String} msg the body of the message
 * @param {String} cvca at least the first two letter to identify the SPOC
 * @param {String} messageID the optional message ID of an related message
 */
CVCAUI.prototype.sendGeneralMessage = function(msg, cvca, messageID) {
	var msg = msg.replace(/\+/g, " ");
	var msg = decodeURIComponent(msg);

	if (typeof(cvca) == "undefined") {
		cvca = this.currentCVCA;
	}

	return this.service.sendGeneralMessage(cvca.substr(0, 2), "Message from " + cvca + " send " + Date(), msg, messageID);
}



/**
 * Serves a details page inbound general messages.
 *
 * <p>The URL processed has the format <caname>/message/<queueindex></p>
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url array of URL path elements
 */
CVCAUI.prototype.handleGeneralMessageDetails = function(req, res, url) {

	var op = CertStoreBrowser.parseQueryString(req.queryString);
	
	var index = parseInt(op.index);
	var sr = this.service.getInboundRequest(index);
	
	if (typeof(op.action) != "undefined") {
		switch(op.action) {
		case "delete":
			this.service.deleteInboundRequest(index);
			this.serveRefreshPage(req, res, url);
			break;
		case "sendmessage":
			var status = this.sendGeneralMessage(op.message, op.callerID, op.messageID);
			this.serveRefreshPage(req, res, url, status);
			break;
		default:
			sr.setStatusInfo(op.action);
			var status = this.service.processRequest(index);
			this.serveRefreshPage(req, res, url, status);
		}
	} else {
		var page = this.renderServiceRequestPage(sr);

		var actions = <ul/>
		
		actions.li += <li><a href={"message?index=" + op.index + "&action=delete"}>Delete</a> request</li>

		var div = page.div.(@id == "actions");
		div.h2 = <h2>Possible Actions</h2>
		
		div.h2 += 	<form action="" method="get">
						<input name="action" type="hidden" value="sendmessage"/>
						<input name="messageID" type="hidden" value={sr.getMessageID()}/>
						<input name="callerID" type="hidden" value={sr.getCallerID()}/>
						<input name="message" size="75" value="Enter message..."/>
						<button type="submit">Respond</button>
					</form>

		div.h2 += actions;

		this.sendPage(req, res, url, page);
	}
}



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
			<form action="" method="get">
				Select CVCA
				<input name="op" type="hidden" value="changecvca"/>
				<select name="cvca" size="1">
				</select>
				<button type="submit">Change View</button>
			</form>
			<div id="activechain"/>
			<div id="outboundrequests"/>
			<div id="inboundrequests"/>
			<h2>Possible actions:</h2>
			<div id="action"/>
			<ul>
			</ul>
			<p><a href={url[0] + "/holderlist?path=" + this.service.path }>Browse Document Verifier...</a></p>
		</div>
	
	var l = page.form.select.(@name=="cvca");
	var cvcalist = this.service.getCVCAList();
	
	for each (var holderId in cvcalist) {
		if (this.currentCVCA == holderId) {
			l.option += <option selected="selected">{holderId}</option>
		} else {
			l.option += <option>{holderId}</option>
		}
	}

	if (this.currentCVCA == this.service.name) {
		var form =	<form action="" method="get">
						Public Key Specification
						<input name="op" type="hidden" value="change"/>
						<select name="keyspec" size="1">
						</select>
						<button type="submit">Change</button>
					</form>

		var l = form.select;
		for (var i = 0; i < CVCAService.KeySpecification.length; i++) {
			var o = CVCAService.KeySpecification[i];
			if (this.service.currentKeySpec == o.id) {
				l.option += <option value={o.id} selected="selected">{o.name}</option>
			} else {
				l.option += <option value={o.id}>{o.name}</option>
			}
		}
		
		var div = page.div.(@id == "action");
		div.appendChild(form);
	
		var l = page.ul;
	
		if (this.service.isOperational()) {
			l.li += <li><a href="?op=link">Generate link certificate without domain parameter</a></li>
			l.li += <li><a href="?op=linkdp">Generate link certificate with domain parameter</a></li>
		} else {
			l.li += <li><a href="?op=linkdp">Generate root certificate</a></li>
		}
		l.li += <li><a href="?op=getcacertificates">Get CA certificates of registered SPOCs</a></li>
	} else {
/*
		var form =	<form action="" method="get">
						Message
						<textarea name="op" type="hidden" value="message" cols="50" rows="10">
						Enter message here
						</textarea>
						<button type="submit">Send</button>
					</form>
*/
		var form =	<form action="" method="get">
						<input name="op" type="hidden" value="sendmessage"/>
						<input name="message" size="75" value="Enter message..."/>
						<button type="submit">Send to SPOC</button>
					</form>

		var div = page.div.(@id == "action");
		div.appendChild(form);
	
		var l = page.ul;
	
		l.li += <li><a href={ "?op=getcacertificates&cvca=" + this.currentCVCA }>Get CA certificate via SPOC</a></li>
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
		case "message":
			this.handleGeneralMessageDetails(req, res, url);
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
				if (typeof(operation.cvca) == "undefined") {
					var status = this.service.getCACertificatesFromSPOCs();
				} else {
					var status = this.service.getCACertificatesFromSPOC(operation.cvca.substr(0, 2));
				}
				this.serveRefreshPage(req, res, url, status);
				break;
			case "sendmessage":
				var status = this.sendGeneralMessage(operation.message, operation.cvca);
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
