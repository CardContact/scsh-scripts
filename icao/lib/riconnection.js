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
 * @fileoverview Connector implementing a web service interface for a 
 * Recovation Service using Restricted Identification as per TR-03129
 */



/**
 * Creates a web service connector to access a revocation service as per TR-03129
 *
 * @class Class implementing a revocation service web service connector
 * @constructor
 * @param {String} url the web service endpoint
 * @param {Boolean} isMBS true if connection is made to an CVCA/MBS, otherwise connection is made to a DV
 */
function RIConnection(url, isMBS) {
	this.url = url;
	this.soapcon = new SOAPConnection(SOAPConnection.SOAP11);
	this.verbose = true;
	this.lastError = null;
	this.version = "1.1";
	this.isMBS = isMBS;
}



/**
 * Sets the version of the WSDL to use
 *
 * @param {String} version the version to use
 */
RIConnection.prototype.setVersion = function(version) {
	this.version = version;
}



/**
 * Set the keystore used for HTTPS downloads
 *
 * @param {KeyStore} truststore the truststore for the HTTPS file download
 * @param {TrustStore} keystore the keystore for the HTTPS file download
 */
RIConnection.prototype.setTrustAndKeystore = function(truststore, keystore, privateKeyPIN) {
	this.truststore = truststore;
	this.keystore = keystore;
	this.privateKeyPIN = privateKeyPIN;
}



/**
 * Get the last error return code
 *
 * @returns the last error return code received or null if none defined
 * @type String
 */
RIConnection.prototype.getLastError = function() {
	return this.lastError;
}



/**
 * Close the connector and release allocated resources
 */
RIConnection.prototype.close = function() {
	this.soapcon.close();
}



/**
 * Get sector public key
 *
 * @returns the sector public key
 * @type ByteString
 */
RIConnection.prototype.getSectorPublicKey = function(sectorID) {

	this.lastError = null;

	if (this.isMBS) {
		var ns = new Namespace("uri:EAC-PKI-CVCA-Protocol/" + this.version);
	} else {
		var ns = new Namespace("uri:EAC-PKI-DV-Protocol/" + this.version);
	}

	var ns1 = new Namespace("uri:eacBT/" + this.version);

	var request =
		<typ:GetSectorPublicKey xmlns:typ={ns}>
			<sectorID>{sectorID.toString(BASE64)}</sectorID>
		</typ:GetSectorPublicKey>;

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
		throw new GPError("RIConnection", GPError.DEVICE_ERROR, 0, "getSectorPublicKey failed with : " + e);
	}

	if (!response.hasOwnProperty("Result")) {
		throw new GPError("RIConnection", GPError.DEVICE_ERROR, 0, "Returned SOAP message does not contain expected element Result");
	}

	
}



/**
 * Obtain a complete blacklist list from the revocation service
 *
 * @returns the blacklist as CMS object
 * @type ByteString
 */
RIConnection.prototype.getCompleteBlackList = function() {

	this.lastError = null;

	if (this.isMBS) {
		var ns = new Namespace("uri:EAC-PKI-CVCA-Protocol/" + this.version);
	} else {
		var ns = new Namespace("uri:EAC-PKI-DV-Protocol/" + this.version);
	}

	var ns1 = new Namespace("uri:eacBT/" + this.version);

	var request = <typ:GetBlackList xmlns:typ={ns}>
         <callbackIndicator>callback_not_possible</callbackIndicator>
         <messageID>
         </messageID>
         <deltaIndicator>complete_list</deltaIndicator>
         <deltaBase>
         </deltaBase>
    </typ:GetBlackList>;

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
		throw new GPError("RIConnection", GPError.DEVICE_ERROR, 0, "getBlackList failed with : " + e);
	}

	if (!response.hasOwnProperty("Result")) {
		throw new GPError("RIConnection", GPError.DEVICE_ERROR, 0, "Returned SOAP message does not contain expected element Result");
	}

	var xml = new XML(response.Result);
	
	var elementList = xml.elements();
	
	var size = elementList.length();
	assert(size == 2);
	
	var returnCode = elementList[0];
	print(returnCode.toString());
	assert(returnCode.toString().equals("ok_list_available"));
	
	var downloadUrl = elementList[1];
	print(downloadUrl);
	
	var xml = new XML(downloadUrl);
	var elementList = xml.elements();
	
	var conn = new URLConnection(elementList[0].toString());
	
	if (typeof(this.truststore) != "undefined") {
		conn.setTLSKeyStores(this.truststore, this.keystore, this.privateKeyPIN);
	}

	var bl = conn.getAsByteString();
	
	return(bl);
}



/**
 * Obtain a complete blacklist list from the revocation service
 *
 * @returns the blacklist as CMS object
 * @type ByteString
 */
RIConnection.prototype.getDeltaBlackLists = function(deltaBase) {

	this.lastError = null;

	if (this.isMBS) {
		var ns = new Namespace("uri:EAC-PKI-CVCA-Protocol/" + this.version);
	} else {
		var ns = new Namespace("uri:EAC-PKI-DV-Protocol/" + this.version);
	}

	var ns1 = new Namespace("uri:eacBT/" + this.version);

	var request = <typ:GetBlackList xmlns:typ={ns} xmlns:ns1={ns1}>
         <callbackIndicator>callback_not_possible</callbackIndicator>
         <messageID>
         </messageID>
         <deltaIndicator>delta_list</deltaIndicator>
         <deltaBase>
			<ns1:deltaBase>{deltaBase.toString()}</ns1:deltaBase>
         </deltaBase>
    </typ:GetBlackList>;

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
		throw new GPError("RIConnection", GPError.DEVICE_ERROR, 0, "getBlackList failed with : " + e);
	}

	if (!response.hasOwnProperty("Result")) {
		throw new GPError("RIConnection", GPError.DEVICE_ERROR, 0, "Returned SOAP message does not contain expected element Result");
	}

	var xml = new XML(response.Result);
	
	var elementList = xml.elements();
	
	var size = elementList.length();
	assert(size == 3);
	
	var returnCode = elementList[0];
	print(returnCode.toString());
	assert(returnCode.toString().equals("ok_list_available"));
	
	var addedItemsElement = elementList[1];
	var addedItemsList = addedItemsElement.elements();
	var addedItemsBytes = new ByteString(addedItemsList[0], BASE64);
	
	var removedItemsElement = elementList[2];
	var removedItemsList = removedItemsElement.elements();
	var removedItemsBytes = new ByteString(removedItemsList[0], BASE64);
	
	var bl = new Array(2);
	bl[0] = addedItemsBytes;
	bl[1] = removedItemsBytes;
	
	return(bl);
}



RIConnection.test = function() {
	var ri = new RIConnection("https://localhost:8443/dvsd-local");
	var blacklist = ri.getCompleteBlackList();
	
	var deltaLists = ri.getDeltaBlackLists("9000");
}
