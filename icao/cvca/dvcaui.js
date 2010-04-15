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
			<div id="pendingrequests"/>
			<h2>Possible actions:</h2>
			<ul>
				<li><a href="?update">Update CVCA certificates synchronously</a></li>
				<li><a href="?updateasync">Update CVCA certificates asynchronously</a></li>
				<li><a href="?renew">Renew certificate synchronously</a></li>
				<li><a href="?renewasync">Renew certificate asychronously</a></li>
			</ul>
			<p><a href={url[0] + "/holderlist?path=" + this.service.path }>Browse Document Verifier...</a></p>
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
	
//	var queue = this.service.listRequests();
	queue = [];
	
	if (queue.length > 0) {
		// Pending requests list
		var div = page.body.div.(@id == "pendingrequests");
		div.h2 = "Pending requests:";
		
		div.ol = <ol/>;
		var l = div.ol;
	
		for (var i = 0; i < queue.length; i++) {
			var sr = queue[i];

			if (sr.isCertificateRequest()) {
				var refurl = url[0] + "/request/" + i;
			} else {
				var refurl = url[0] + "/getcert/" + i;
			}
			l.li += <li><a href={refurl}>{sr.toString()}</a></li>;
		}
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
			this.handleRequestCertificateRequestDetails(req, res, url);
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
			this.service.renewCertificate(false);
			this.serveRefreshPage(req, res, url);
			break;
		case "renewasync":
			this.service.renewCertificate(true);
			this.serveRefreshPage(req, res, url);
			break;
		default:
			this.serveStatusPage(req, res, url);
		}
	}
}
