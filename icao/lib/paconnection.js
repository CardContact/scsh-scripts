/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2008 CardContact Software & System Consulting
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
 * @fileoverview Connector implementing a web service interface for obtaining Master and Defect Lists from
 * a Document Verifier or National Public Key Directory (NPKD) as per TR-03129
 */


/**
 * Creates a web service connector to obtain Master and Defect Lists from  a Document Verifier or
 * a National Public Key Directory (NPKD) as per TR-03129
 *
 * @class Class implementing a DV or NPKD web service connector
 * @constructor
 * @param {String or URLConnection} url the web service endpoint
 * @param {Boolean} true if connection is made to an CVCA/NPKD, otherwise connection is made to a DV
 */
function PAConnection(url, isNPKD) {
	this.url = url;
	this.soapcon = new SOAPConnection(SOAPConnection.SOAP11);
	this.verbose = true;
	this.returnCode = null;
	this.version = "1.1";
	this.isNPKD = isNPKD;
}



/**
 * Get the return code
 *
 * @returns the last return code received or null if none defined
 * @type String
 */
PAConnection.prototype.getReturnCode = function() {
	return this.returnCode;
}



/**
 * Sets the version of the WSDL to use
 *
 * @param {String} version the version to use
 */
PAConnection.prototype.setVersion = function(version) {
	this.version = version;
}



/**
 * Close the connector and release allocated resources
 */
PAConnection.prototype.close = function() {
	this.soapcon.close();
}



/**
 * Obtain a defect list from the NPKD
 *
 * @returns a defect list
 * @type ByteString
 */
PAConnection.prototype.getDefectList = function() {

	this.returnCode = null;

	if (this.isNPKD) {
		var ns = new Namespace("uri:EAC-PKI-CVCA-Protocol/" + this.version);
	} else {
		var ns = new Namespace("uri:EAC-PKI-DV-Protocol/" + this.version);
	}

	var ns1 = new Namespace("uri:eacBT/" + this.version);

	var request =
      <ns:GetDefectList xmlns:ns={ns} xmlns:ns1={ns1}>
         <callbackIndicator>callback_not_possible</callbackIndicator>
         <messageID>
         </messageID>
         <responseURL>
         </responseURL>
      </ns:GetDefectList>;

	if (this.verbose) {
		GPSystem.trace(request.toXMLString());
	}

	try	 {
		var response = this.soapcon.call(this.url, request);
		if (this.verbose) {
			GPSystem.trace(response.toXMLString());
		}
	}
	catch(e) {
		GPSystem.trace("SOAP call to " + this.url + " failed : " + e);
		throw new GPError("PAConnection", GPError.DEVICE_ERROR, 0, "getDefectList failed with : " + e);
	}

	if (!response.hasOwnProperty("Result")) {
		throw new GPError("PAConnection", GPError.DEVICE_ERROR, 0, "Returned SOAP message does not contain expected element Result");
	}

	this.returnCode = response.Result.ns1::returnCode.toString();
	var defectlist = null;
	
	if (this.returnCode == "ok_list_available") {
		defectlist = new ByteString(response.Result.ns1::defectList.ns1::binary.toString(), BASE64);
	}
	return defectlist;
}



/**
 * Obtain a master list from the NPKD
 *
 * @returns a masterlist
 * @type ByteString
 */
PAConnection.prototype.getMasterList = function() {

	this.returnCode = null;

	if (this.isNPKD) {
		var ns = new Namespace("uri:EAC-PKI-CVCA-Protocol/" + this.version);
	} else {
		var ns = new Namespace("uri:EAC-PKI-DV-Protocol/" + this.version);
	}

	var ns1 = new Namespace("uri:eacBT/" + this.version);

	var request =
      <ns:GetMasterList xmlns:ns={ns} xmlns:ns1={ns1}>
         <callbackIndicator>callback_not_possible</callbackIndicator>
         <messageID>
         </messageID>
         <responseURL>
         </responseURL>
      </ns:GetMasterList>;

	if (this.verbose) {
		GPSystem.trace(request.toXMLString());
	}

	try	 {
		var response = this.soapcon.call(this.url, request);
		if (this.verbose) {
			GPSystem.trace(response.toXMLString());
		}
	}
	catch(e) {
		GPSystem.trace("SOAP call to " + this.url + " failed : " + e);
		throw new GPError("PAConnection", GPError.DEVICE_ERROR, 0, "getMasterList failed with : " + e);
	}
	
	if (!response.hasOwnProperty("Result")) {
		throw new GPError("PAConnection", GPError.DEVICE_ERROR, 0, "Returned SOAP message does not contain expected element Result");
	}

	this.returnCode = response.Result.ns1::returnCode.toString();
	var masterlist = null;
	
	if (this.returnCode == "ok_list_available") {
		masterlist = new ByteString(response.Result.ns1::masterList.ns1::binary.toString(), BASE64);
	}

	return masterlist;
}



PAConnection.test = function() {
	var c = new PAConnection("http://localhost:8080/se/scs");
	c.verbose = true;
	var defectlist = c.getDefectList();
}
