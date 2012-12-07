/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2009 CardContact Software & System Consulting
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
 * @fileoverview SignatureKey - Object storing information related to PrK.QES
 */

 
/**
 * Create a signature key object
 *
 * @class Class implementing signature keys
 *
 * @param {String} name the human readable name of the object
 * @param {Number} id the key id
 */
function SignatureKey(name, id) {
	FileSystemIdObject.call(this, name, id);
	this.isTerminated = true;			// State after TERMINATE
	this.allowTerminate = true;
}

SignatureKey.prototype = new FileSystemIdObject();
SignatureKey.prototype.constructor = SignatureKey;


SignatureKey.TYPE_KEY = "signaturekey";


/**
 * Override from base class
 */
SignatureKey.prototype.getType = function() {
	return SignatureKey.TYPE_KEY = "signaturekey";
}



/**
 * Terminate authentication object
 */
SignatureKey.prototype.terminate = function() {
	if (!this.allowTerminate) {
		throw new GPError("SignatureKey", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Terminate not allowed for signature key");
	}
	this.isTerminated = true;
}



/**
 * Convert object to a human readable string
 */
SignatureKey.prototype.toString = function() {
	return this.name + (this.isTerminated ? " terminated" : " active");
}


