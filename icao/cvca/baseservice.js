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
 * @fileoverview Base class for all EACPKI services
 */

load("tools/eccutils.js");


/**
 * Create basic service instance for EAC-PKI services
 *
 */ 
function BaseService() {
	this.crypto = new Crypto();

	this.inqueue = new ServiceQueue(30);
	this.outqueue = new ServiceQueue(10);
}



/**
 * Enumerate all pending service requests to superior systems
 *
 * @returns the pending service requests
 * @type ServiceRequest[]
 */
BaseService.prototype.listOutboundRequests = function() {
	return this.outqueue.getList();
}



/**
 * Gets the indexed request
 *
 * @param {Number} index the index into the work queue identifying the request
 * @returns the indexed request
 * @type ServiceRequest
 */
BaseService.prototype.getOutboundRequest = function(index) {
	return this.outqueue.getEntryByIndex(index);
}



/**
 * Gets the request identified by it message id
 *
 * @param {String} msgid the message id for the request
 * @returns the request
 * @type ServiceRequest
 */
BaseService.prototype.getOutboundRequestByMessageId = function(msgid) {
	return this.outqueue.getEntryByMessageID(msgid);
}



/**
 * Adds an outbound request to the internal queue, removing the oldest entry if more than
 * 10 entries are contained
 *
 * @param {ServiceRequest} sr the service request
 */
BaseService.prototype.addOutboundRequest = function(sr) {
	this.outqueue.addEntry(sr);
}



/**
 * Adds an inbound request to the internal queue
 *
 * @param {ServiceRequest} sr the service request
 */
BaseService.prototype.addInboundRequest = function(sr) {
	this.inqueue.addEntry(sr);
}



/**
 * Enumerate all pending service requests from subordinate systems
 *
 * @returns the pending service requests
 * @type ServiceRequest[]
 */
BaseService.prototype.listInboundRequests = function() {
	return this.inqueue.getList();
}



/**
 * Gets the indexed request
 *
 * @param {Number} index the index into the work queue identifying the request or -1 for the last request
 * @returns the indexed request
 * @type ServiceRequest
 */
BaseService.prototype.getInboundRequest = function(index) {
	return this.inqueue.getEntryByIndex(index);
}



/**
 * Delete a request from the work queue
 *
 * @param {Number} index the index into the work queue
 */
BaseService.prototype.deleteInboundRequest = function(index) {
	this.inqueue.deleteEntry(index);
}



/**
 * Generate a new message ID
 *
 * @type String
 * @return a new message ID
 */
BaseService.prototype.newMessageID = function() {
	return this.crypto.generateRandom(2).toString(HEX);
}



/**
 * Check certificate request syntax
 *
 * @param {ByteString} req the request in binary format
 * @returns the decoded request or null in case of error
 * @type CVC
 */
BaseService.prototype.checkRequestSyntax = function(reqbin) {
	try	{
		var reqtlv = new ASN1(reqbin);
		var req = new CVC(reqtlv);
	}
	catch(e) {
		GPSystem.trace("Error decoding ASN1 structure of request: " + e);
		return null;
	}
	
	return req;
}



/**
 * Check certificate request inner signature
 *
 * @param {ServiceRequest} sr the service request
 * @returns true if all checks passed or false and update in statusInfo
 * @type boolean
 */
BaseService.prototype.checkRequestInnerSignature = function(sr) {
	var req = sr.getCertificateRequest();
	
	// Check inner signature
	try	{
		var puk = req.getPublicKey();
	}
	catch(e) {
		sr.addMessage("FAILED - Invalid public key encoding detected (in " + e.fileName + "#" + e.lineNumber + ")" + e);
		sr.setStatusInfo(ServiceRequest.FAILURE_SYNTAX);
		return false;
	}
	sr.addMessage("Passed - Valid public key encoding");

	if (!req.verifyWith(this.crypto, puk)) {
		sr.addMessage("FAILED - Inner signature is invalid or content is tampered with");
		sr.setStatusInfo(ServiceRequest.FAILURE_INNER_SIGNATURE);
		return false;
	}
	sr.addMessage("Passed - Inner signature is valid");

	return true;
}



/**
 * A queue for service requests
 *
 * @param {Number} capacity the maximum number of entries in the queue
 */
function ServiceQueue(capacity) {
	this.capacity = capacity;
	this.queue = [];
	this.map = [];
}



/**
 * Enumerate all service requests
 *
 * @returns the service request list
 * @type ServiceRequest[]
 */
ServiceQueue.prototype.getList = function() {
	return this.queue;
}



/**
 * Delete a request from the work queue
 *
 * @param {Number} index the index into the work queue
 */
ServiceQueue.prototype.deleteEntry = function(index) {
	var oldsr = this.getEntryByIndex(index);
	var msgid = oldsr.getMessageID();
	if (msgid) {
		delete(this.map[msgid]);
	}

	this.queue.splice(index, 1);
}



/**
 * Adds a request to the queue, removing the oldest entry if the capacity is exhausted
 *
 * @param {ServiceRequest} sr the service request
 */
ServiceQueue.prototype.addEntry = function(sr) {
	if (this.queue.length >= this.capacity) {
		this.deleteEntry(0);
	}
	this.queue.push(sr);
	var msgid = sr.getMessageID();
	if (msgid) {
		this.map[msgid] = sr;
	}
}



/**
 * Gets the indexed request
 *
 * @param {Number} index the index into the work queue identifying the request or -1 for the last request
 * @returns the indexed request
 * @type ServiceRequest
 */
ServiceQueue.prototype.getEntryByIndex = function(index) {
	if (index == -1) {
		index = this.queue.length - 1;
	}
	return this.queue[index];
}



/**
 * Gets the request identified by its message id
 *
 * @param {String} msgid the message id for the request
 * @returns the request
 * @type ServiceRequest
 */
ServiceQueue.prototype.getEntryByMessageID = function(msgid) {
	return this.map[msgid];
}



