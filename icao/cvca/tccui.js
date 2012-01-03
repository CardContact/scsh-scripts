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
	this.currentCVCA = service.getCVCAList()[0];
}

TCCUI.prototype = new CommonUI();
TCCUI.constructor = TCCUI;



/**
 * Handle a page to upload CVCA/DVCA and terminal certificates
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 * @param {String[]} url array of URL path elements
 */
TCCUI.prototype.handleCertificateUpload = function(req, res, url) {
	if (req.method == "POST") {
		var cvcert = req.parameters.cvcert;
		assert(cvcert instanceof ByteString);
		if (cvcert.length > 0) {
			var status = this.service.processUploadedCertificate(this.currentCVCA, cvcert);
		} else {
			var status = "Empty upload";
		}
		this.serveRefreshPage(req, res, url, status);
	} else {
		page =	<div>
					<h1>CVCA/DVCA/Terminal Certificate Upload</h1>
					<p>Select a binary encoded certificate for upload.</p>
					<form action="" method="post" enctype="multipart/form-data">
						<input type="file" name="cvcert" size="60"/>
					<input type="submit" value="Upload"/>
					</form>
				</div>
		this.sendPage(req, res, url, page);
	}
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
	var status = this.service.isOperational(this.currentCVCA) ? "operational" : "not operational";

	var holderID = this.service.getHolderID();
	
	var page =
		<div>
			<h1>TCC Service {status}</h1>
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
			<form action="" method="get">
				HolderID<input name="op" type="hidden" value="changeholderid"/><input name="holderID" size="11" maxlength="11" value={holderID}/><button type="submit">Change</button>
			</form>
			<ul>
				<li><a href="?op=update">Update CVCA/DVCA certificates synchronously</a></li>
				<li><a href="?op=updateasync">Update CVCA/DVCA certificates asynchronously</a></li>
				<li><a href={"?op=initial&cvca=" + this.currentCVCA + "&holderID=" + holderID}>Request initial certificate synchronously</a></li>
				<li><a href={"?op=initialasync&cvca=" + this.currentCVCA + "&holderID=" + holderID}>Request initial certificate asynchronously</a></li>
				<li><a href={"?op=renew&cvca=" + this.currentCVCA + "&holderID=" + holderID}>Renew certificate synchronously</a></li>
				<li><a href={"?op=renewasync&cvca=" + this.currentCVCA + "&holderID=" + holderID}>Renew certificate asynchronously</a></li>
				<li><a href={url[0] + "/uploadcertificate"}>Upload CVCA, DVCA or terminal certificate</a></li>
			</ul>
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

	// ToDo: Refactor to getter
	var certlist = this.service.getCertificateList(this.currentCVCA);
	
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
			if (chr.getHolder().equals(this.service.getHolderID())) {
//				var path = this.service.path;
				var path = "/" + this.currentCVCA + "/" + this.service.parent + "/" + chr.getHolder();
			} else if (chr.getHolder().equals(this.service.parent)) {
//				var path = this.service.path.substr(0, this.service.path.lastIndexOf("/"));
				var path = "/" + this.currentCVCA + "/" + this.service.parent;
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
		var t = this.renderServiceRequestListPage(queue, true, url[0]);
		var div = page.div.(@id == "outboundrequests");
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
			this.handleOutboundRequestDetails(req, res, url);
			break;
		case "uploadcertificate":
			this.handleCertificateUpload(req, res, url);
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
			case "changeholderid":
				this.service.setHolderID(operation.holderID);
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
				var status = this.service.renewCertificate(false, false, operation.cvca, operation.holderID);
				this.serveRefreshPage(req, res, url, status);
				break;
			case "renewasync":
				var status = this.service.renewCertificate(true, false, operation.cvca, operation.holderID);
				this.serveRefreshPage(req, res, url, status);
				break;
			case "initial":
				var status = this.service.renewCertificate(false, true, operation.cvca, operation.holderID);
				this.serveRefreshPage(req, res, url, status);
				break;
			case "initialasync":
				var status = this.service.renewCertificate(true, true, operation.cvca, operation.holderID);
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
