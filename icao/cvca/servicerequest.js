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
 * @fileoverview A service request stores information about a request pending service on a CA
 */



/**
 * Create a service request to be added to the internal work queue
 *
 * @class Class storing entries in the internal work queue
 * @constructor
 *
 * @param {String} messageID the message identifier send by the client (optional)
 * @param {String} responseURL the URL to which the result of processing this request is send (optional)
 * @param {CVC} certificateRequest the optional certificate request for this request (optional)
 */
function ServiceRequest(messageID, responseURL, certificateRequest) {
	if (messageID) {
		this.messageID = messageID.toString();
	}
	if (responseURL) {
		this.responseURL = responseURL.toString();
	}
	this.certificateRequest = certificateRequest;
}


ServiceRequest.OK_CERT_AVAILABLE							= "ok_cert_available";
ServiceRequest.OK_SYNTAX									= "ok_syntax";
ServiceRequest.OK_RECEIVED_CORRECTLY						= "ok_received_correctly";
ServiceRequest.OK_RECEPTION_ACK								= "ok_reception_ack";
ServiceRequest.OK_SIGNATURE_AVAILABLE						= "ok_signature_available";
ServiceRequest.OK_REQUEST_FORWARDED							= "ok_request_forwarded";
ServiceRequest.NEW_CERT_AVAILABLE_NOTIFICATION				= "new_cert_available_notification";
ServiceRequest.FAILURE_SYNTAX								= "failure_syntax";
ServiceRequest.FAILURE_INNER_SIGNATURE						= "failure_inner_signature";
ServiceRequest.FAILURE_OUTER_SIGNATURE						= "failure_outer_signature";
ServiceRequest.FAILURE_EXPIRED								= "failure_expired";
ServiceRequest.FAILURE_DOMAIN_PARAMETER						= "failure_domain_parameter";
ServiceRequest.FAILURE_REQUEST_NOT_ACCEPTED					= "failure_request_not_accepted";
ServiceRequest.FAILURE_FOREIGNCAR_UNKNOWN					= "failure_foreignCAR_unknown";
ServiceRequest.FAILURE_NOT_FORWARDED						= "failure_not_forwarded";
ServiceRequest.FAILURE_REQUEST_NOT_ACCEPTED_FOREIGN			= "failure_request_not_accepted_foreign";
ServiceRequest.FAILURE_MESSAGEID_UNKNOWN					= "failure_messageID_unknown";
ServiceRequest.FAILURE_SYNCHRONOUS_PROCESSING_NOT_POSSIBLE	= "failure_synchronous_processing_not_possible";
ServiceRequest.FAILURE_CAR_UNKNOWN							= "failure_CAR_unknown";
ServiceRequest.FAILURE_CHR_UNKNOWN							= "failure_CHR_unknown";
ServiceRequest.FAILURE_INTERNAL_ERROR						= "failure_internal_error";

ServiceRequest.DVCA_GET_CA_CERTIFICATES						= "DVCA.GetCACertificates";
ServiceRequest.DVCA_REQUEST_CERTIFICATE						= "DVCA.RequestCertificate";
ServiceRequest.DVCA_REQUEST_FOREIGN_CERTIFICATE				= "DVCA.RequestForeignCertificate";

ServiceRequest.SPOC_GET_CA_CERTIFICATES						= "SPOC.GetCACertificates";
ServiceRequest.SPOC_REQUEST_CERTIFICATE						= "SPOC.RequestCertificate";
ServiceRequest.SPOC_FORWARD_REQUEST_CERTIFICATE				= "SPOC.ForwardRequestCertificate";

ServiceRequest.TERM_GET_CA_CERTIFICATES						= "TERM.GetCACertificates";
ServiceRequest.TERM_REQUEST_CERTIFICATE						= "TERM.RequestCertificate";

ServiceRequest.CVCA_SEND_CERTIFICATE						= "CVCA.SendCertificate";
ServiceRequest.DVCA_SEND_CERTIFICATE						= "DVCA.SendCertificate";

/**
 * Returns true if this is a certificate request
 *
 * @returns true if this is a certificate request
 * @type boolean
 */
ServiceRequest.prototype.isCertificateRequest = function() {
	return (typeof(this.certificateRequest) != "undefined");
}



/**
 * Returns true if this is an asynchronous request
 *
 * @returns true if this is an asynchronous request
 * @type boolean
 */
ServiceRequest.prototype.isAsynchronous = function() {
	return (typeof(this.messageID) != "undefined");
}



/**
 * Gets the messageID
 *
 * @returns the messageID
 * @type String
 */
ServiceRequest.prototype.getMessageID = function() {
	return this.messageID;
}



/**
 * Gets the response URL
 *
 * @returns the response URL
 * @type String
 */
ServiceRequest.prototype.getResponseURL = function() {
	return this.responseURL;
}



/**
 * Sets response URL
 *
 * @param {String} responseURL the response URL
 */
ServiceRequest.prototype.setResponseURL = function(responseURL) {
	this.responseURL = responseURL;
}



/**
 * Gets the certificate request
 *
 * @returns the certificate request which may be undefined
 * @type CVC
 */
ServiceRequest.prototype.getCertificateRequest = function() {
	return this.certificateRequest;
}



/**
 * Sets certificate request
 *
 * @param {CVC} certificateRequest the certificate request
 */
ServiceRequest.prototype.setCertificateRequest = function(certificateRequest) {
	this.certificateRequest = certificateRequest;
}



/**
 * Sets raw certificate request
 *
 * @param {ByteString} certificateRequest the raw certificate request
 */
ServiceRequest.prototype.setRawCertificateRequest = function(certificateRequest) {
	this.rawCertificateRequest = certificateRequest;
}



/**
 * Gets the raw certificate request
 *
 * @returns the certificate request which may be undefined
 * @type ByteString
 */
ServiceRequest.prototype.getRawCertificateRequest = function() {
	return this.rawCertificateRequest;
}



/**
 * Gets the status information for the last processing
 *
 * @returns the last status information which may be undefined
 * @type String
 */
ServiceRequest.prototype.getStatusInfo = function() {
	return this.statusInfo;
}



/**
 * Sets the status information for this request
 *
 * @param {String} statusInfo the last status information
 */
ServiceRequest.prototype.setStatusInfo = function(statusInfo) {
	this.statusInfo = statusInfo;
}



/**
 * Sets the service request type
 *
 * @param {String} type the request type
 */
ServiceRequest.prototype.setType = function(type) {
	this.type = type;
}



/**
 * Gets the service request type
 *
 * @returns the service request type
 * @type String
 */
ServiceRequest.prototype.getType = function() {
	return this.type;
}



/**
 * Adds a list of certificates to the service request
 *
 * @param {CVC[]} certlist the list of certificates
 */
ServiceRequest.prototype.setCertificateList = function(certlist) {
	this.certlist = certlist;
}



/**
 * Gets the list of certificates associated with this request
 *
 * @returns the list of certificates
 * @type CVC[]
 */
ServiceRequest.prototype.getCertificateList = function() {
	return this.certlist;
}



/**
 * Set a message related to this service request
 *
 * @param {String} message the message
 */
ServiceRequest.prototype.setMessage = function(message) {
	this.message = message;
}



/**
 * Add a message related to this service request
 *
 * @param {String} message the message
 */
ServiceRequest.prototype.addMessage = function(message) {
	if (typeof(this.message) == "undefined") {
		this.setMessage(message);
	} else {
		this.message += "\n" + message;
	}
}



/**
 * Gets the message associated with this request
 *
 * @returns the message
 * @type String
 */
ServiceRequest.prototype.getMessage = function() {
	return this.message;
}



/**
 * Set a callerID related to this service request
 *
 * @param {String} foreignCAR the foreignCAR
 */
ServiceRequest.prototype.setCallerID = function(callerID) {
	this.callerID = callerID;
}



/**
 * Gets the callerID associated with this request
 *
 * @returns the callerID
 * @type String
 */
ServiceRequest.prototype.getCallerID = function() {
	return this.callerID;
}



/**
 * Set a foreignCAR related to this service request
 *
 * @param {String} foreignCAR the foreignCAR
 */
ServiceRequest.prototype.setForeignCAR = function(foreignCAR) {
	this.foreignCAR = foreignCAR;
}



/**
 * Gets the foreignCAR associated with this request
 *
 * @returns the foreignCAR
 * @type String
 */
ServiceRequest.prototype.getForeignCAR = function() {
	return this.foreignCAR;
}



/**
 * Sets the related service request
 *
 * @param {ServiceRequest} sr the related service request
 */
ServiceRequest.prototype.setRelatedServiceRequest = function(relatedServiceRequest) {
	this.relatedServiceRequest = relatedServiceRequest;
}



/**
 * Gets the related service request
 *
 * @returns the related service request
 * @type ServiceRequest
 */
ServiceRequest.prototype.getRelatedServiceRequest = function() {
	return this.relatedServiceRequest;
}



/**
 * Sets the raw SOAP XML request
 *
 * @param {XML} request the raw SOAP xml request
 */
ServiceRequest.prototype.setSOAPRequest = function(soapRequest) {
	this.soapRequest = soapRequest;
}



/**
 * Gets the raw SOAP XML request
 *
 * @returns the the raw SOAP xml request
 * @type XML
 */
ServiceRequest.prototype.getSOAPRequest = function() {
	return this.soapRequest;
}



/**
 * Sets the raw SOAP XML response
 *
 * @param {XML} request the raw SOAP xml response
 */
ServiceRequest.prototype.setSOAPResponse = function(soapResponse) {
	this.soapResponse = soapResponse;
}



/**
 * Gets the raw SOAP XML response
 *
 * @returns the the raw SOAP xml response
 * @type XML
 */
ServiceRequest.prototype.getSOAPResponse = function() {
	return this.soapResponse;
}



/**
 * Gets the status information after the asynchronously requests has been completed
 *
 * @returns the last status information which may be undefined
 * @type String
 */
ServiceRequest.prototype.getFinalStatusInfo = function() {
	if (!this.isAsynchronous()) {
		return "Synchronous Request";
	}
	return this.finalStatusInfo;
}



/**
 * Sets the final status information for this request
 *
 * @returns the last status information which may be undefined
 * @type String
 */
ServiceRequest.prototype.setFinalStatusInfo = function(statusInfo) {
	this.finalStatusInfo = statusInfo;
}



/**
 * Create a describing string
 *
 * @returns the string
 * @type String
 */
ServiceRequest.prototype.toString = function() {
	if (this.isAsynchronous()) {
		var str = this.messageID + " - ";
	} else {
		var str = "";
	}
	
	if (this.isCertificateRequest()) {
		str += this.certificateRequest.toString() + " - ";
	} else {
		str += "GetCertificates() - ";
	}
	
	str += this.responseURL;
	
	if (typeof(this.statusInfo) != "undefined") {
		str += " [" + this.statusInfo;
		if (typeof(this.finalStatusInfo) != "undefined") {
			str += "/" + this.finalStatusInfo + "]";
		} else {
			str += "]"
		}
	}
	return str;
}
