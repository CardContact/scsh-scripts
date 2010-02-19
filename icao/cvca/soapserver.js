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
 * @fileoverview A simple SOAP server that dispatches SOAP messages to registered SOAP services
 */



/**
 * Creates a SOAP server instance.
 *
 * @class <p>Provides for a simple SOAP server.</p>
 *
 * @constructor
 */
function SOAPServer() {
	this.services = [];
}



/**
 * Register an object that provides web services for a given relative url.
 *
 * @param {url} url the relativ URL under which the service responds
 * @param {Object} soapService the service implementation that serves POST requests
 * @param {Object} uiService the UI implementation that serves GET requests
 */
SOAPServer.prototype.registerService = function(url, soapService, uiService) {
	this.services[url] = { service: soapService, ui: uiService };
}



/**
 * Serves a simple status page that show the registered services.
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 */
SOAPServer.prototype.statusPage = function(req, res) {
	var page =
		<html>
			<head>
				<title>SOAP Server</title>
			</head>
			<body>
				<p>Services registered at this server:</p>
				<ol>
				</ol>
			</body>
		</html>
		
	for (var i in this.services) {
		var url = "se/" + i;
		var child = <li><a href={url}>{i}</a></li>;
		page.body.ol.appendChild(child);
	}
	
	res.print(page.toXMLString());
}



//
// Create server instance
//
var SOAPServer = new SOAPServer();



function dispatchSOAPRequest(req, res, service) {
	try	{
		var soapenv = req.getEntityAsXML();

		GPSystem.trace("SOAPServer - received SOAP message for " + req.pathInfo);
		GPSystem.trace(soapenv);

		var soapns = soapenv.namespace();
		var soap12 = (soapns == "http://www.w3.org/2003/05/soap-envelope")

		var soapprefix = soapns.prefix;

		var soapbody = soapenv.soapns::Body.elements()[0];
		var method = soapbody.localName();
		var bodyns = soapbody.namespace();

		var servicehandler = service.service[method];
		if (typeof(servicehandler) != "function") {
			GPSystem.trace("SOAPServer - no implementation found for message " + method);
			res.setStatus(HttpResponse.SC_NOT_FOUND);
			return;
		}

		var result = service.service[method](soapbody, req, res);
	
		var response =
		<{soapprefix}:Envelope xmlns:{soapprefix}={soapns}>
			<{soapprefix}:Header/>
			<{soapprefix}:Body>
			<response/>
			</{soapprefix}:Body>
		</{soapprefix}:Envelope>;
	
		response.soapns::Body.response = result;
	
		if (soap12) {
			res.setContentType("application/soap+xml; charset=utf-8");
		} else {
			res.setContentType("text/xml; charset=utf-8");
		}

		var responseStr = response.toXMLString();
		GPSystem.trace("SOAPServer - responding with SOAP message for " + req.pathInfo);
		GPSystem.trace(responseStr);

		res.print(responseStr);
	}
	catch(e) {
		GPSystem.trace("SOAPServer - Exception during SOAP processing in " + e.fileName + "#" + e.lineNumber);
		GPSystem.trace(e);
	}
}



/**
 * Serves a simple status page that show the registered services.
 *
 * @param {HttpRequest} req the request object
 * @param {HttpResponse} req the response object
 */
function handleRequest(req, res) {
	if (req.pathInfo == null) {
		SOAPServer.statusPage(req, res);
	} else {
		var url = req.pathInfo.split("/");
		var service = SOAPServer.services[url[1]];
	
		if (!service) {
			GPSystem.trace("SOAPServer - Service URL " + req.pathInfo + " not defined");
			res.setStatus(HttpResponse.SC_NOT_FOUND);
		} else if (req.method == "GET") {
			GPSystem.trace("SOAPServer - received GET for " + req.pathInfo);
			service.ui.handleInquiry(req, res);
		} else if (req.method == "POST") {
			dispatchSOAPRequest(req, res, service);
		} else {
			res.setStatus(HttpResponse.SC_METHOD_NOT_ALLOWED);
		}
	}
}

GPSystem.trace("soapserver.js processed...");
