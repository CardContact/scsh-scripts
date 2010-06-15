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
 * Gets the certificate request
 *
 * @returns the certificate request which may be undefined
 * @type CVC
 */
ServiceRequest.prototype.getCertificateRequest = function() {
	return this.certificateRequest;
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
 * @returns the last status information which may be undefined
 * @type String
 */
ServiceRequest.prototype.setStatusInfo = function(statusInfo) {
	this.statusInfo = statusInfo;
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
