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
 * @fileoverview AuthenticationObject - Password, PIN or key container for external authentication
 */

 
/**
 * Create an authentication object
 *
 * @class Class implementing authentication objects like PINs, PACE passwords or keys
 *
 * @param {String} name the human readable name of the object
 * @param {String} type one of AuthenticationObject.TYPE_PACE or AuthenticationObject.TYPE_PIN
 * @param {Number} id the password or key id
 * @param {ByteString} value the reference value
 */
function AuthenticationObject(name, type, id, value) {
	FileSystemIdObject.call(this, name, id);
	this.type = type;
	this.value = value;
	this.retrycounter = 3;
	this.initialretrycounter = 3;
	this.usecounter = -1;
	this.resetcounter = -1;
	this.minLength = 4;
	this.isActive = true;				// State after using ACTIVATE / DEACTIVATE
	this.isEnabled = true;				// State after using ENABLE / DISABLE VERIFICATION REQUIREMENT 
	this.isTransport = false;			// State before first change PIN
	this.isTerminated = false;			// State after TERMINATE
	this.allowActivate = false;
	this.allowDeactivate = false;
	this.allowEnable = false;
	this.allowDisable = false;
	this.allowResetRetryCounter = false;
	this.allowResetValue = false;
	this.allowTerminate = false;
	this.unsuspendAuthenticationObject = null;
	this.unblockAuthenticationObject = null;
}

AuthenticationObject.prototype = new FileSystemIdObject();
AuthenticationObject.prototype.constructor = AuthenticationObject;


AuthenticationObject.TYPE_PACE = "pace";
AuthenticationObject.TYPE_PIN = "pin";



/**
 * Override from base class
 */
AuthenticationObject.prototype.getType = function() {
	return this.type;
}



AuthenticationObject.prototype.isBlocked = function() {
	return ((this.initialretrycounter != 0) && (this.retrycounter == 0));
}



AuthenticationObject.prototype.isSuspended = function() {
	return ((this.initialretrycounter != 0) && (this.retrycounter == 1));
}



/**
 * Activate authentication object
 */
AuthenticationObject.prototype.activate = function() {
	if (!this.allowActivate) {
		throw new GPError("AuthenticationObject", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Activate not allowed for authentication object");
	}
	this.isActive = true;
}



/**
 * Deactivate authentication object
 */
AuthenticationObject.prototype.deactivate = function() {
	if (!this.allowDeactivate) {
		throw new GPError("AuthenticationObject", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Deactivate not allowed for authentication object");
	}
	this.isActive = false;
}



/**
 * Reset retry counter and optionally set new reference value
 *
 * @param {ByteString} newValue new reference value
 */
AuthenticationObject.prototype.resetRetryCounter = function(newValue) {
	if (!this.allowResetRetryCounter) {
		throw new GPError("AuthenticationObject", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Reset retry counter not allowed for authentication object");
	}
	if (newValue && !this.allowResetValue) {
		throw new GPError("AuthenticationObject", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Reset retry counter not allowed with new value for authentication object");
	}
	if (this.resetcounter != -1) {
		if (this.resetcounter == 0) {
			throw new GPError("AuthenticationObject", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Reset retry counter is 0");
		}
		this.resetcounter--;
	}
	if (newValue && (newValue.length < this.minLength)) {
		throw new GPError("AuthenticationObject", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "New reference data too short");
	}
	this.retrycounter = this.initialretrycounter;
	this.isActive = true;

	if (this.initialretrycounter) {
		this.retrycounter = this.initialretrycounter;
	}
	if (newValue) {
		this.isTransport = false;
		this.value = newValue;
	}
}



/**
 * Change reference data, optionally verifying the old value before
 *
 * @param {Number} qualifier command qualifier, 00 = oldPIN||newPIN, 01 = newPIN
 * @param {ByteString} value new reference value
 */
AuthenticationObject.prototype.changeReferenceData = function(qualifier, value) {
	if (!this.allowChangeReferenceData) {
		throw new GPError("AuthenticationObject", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Change reference data not allowed for authentication object");
	}
	if ((qualifier == 0x01) && !this.isTerminated) {
		throw new GPError("AuthenticationObject", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Change reference data with P1=01 not allowed non terminated authentication object");
	}
	if ((qualifier == 0x00) && (value.length <= this.value.length)) {
		throw new GPError("AuthenticationObject", GPError.INVALID_DATA, APDU.SW_INVDATA, "Command data does not contain a new PIN value for P1=00");
	}
	if (qualifier == 0x00) {
		this.verify(value.left(this.value.length));
		value = value.bytes(this.value.length);
	}

	if (value.length < this.minLength) {
		throw new GPError("AuthenticationObject", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "New reference data too short");
	}

	this.value = value;
	this.isTerminated = false;
}



/**
 * Verify PIN value
 *
 * @param {ByteString} value reference value
 */
AuthenticationObject.prototype.verify = function(value) {
	if (this.isBlocked()) {
		throw new GPError("AuthenticationObject", GPError.INVALID_DATA, APDU.SW_AUTHMETHLOCKED, "Authentication method blocked");
	}
	if (this.isTerminated) {
		throw new GPError("AuthenticationObject", GPError.INVALID_DATA, APDU.SW_REFDATANOTUSABLE, "Authentication method terminated");
	}
	this.decreaseRetryCounter();
	if (!this.value.equals(value)) {
		var sw = APDU.SW_WARNINGNVCHG | this.retrycounter;
		throw new GPError("AuthenticationObject", GPError.INVALID_DATA, sw, "Authentication failed");
	}
	this.restoreRetryCounter();
}



/**
 * Deactivate authentication object
 */
AuthenticationObject.prototype.decreaseRetryCounter = function() {
	if (this.initialretrycounter) {
		this.retrycounter--;
	}
}



/**
 * Deactivate authentication object
 */
AuthenticationObject.prototype.restoreRetryCounter = function() {
	if (this.initialretrycounter) {
		this.retrycounter = this.initialretrycounter;
	}
}



/**
 * Terminate authentication object
 */
AuthenticationObject.prototype.terminate = function() {
	if (!this.allowTerminate) {
		throw new GPError("AuthenticationObject", GPError.INVALID_DATA, APDU.SW_CONDOFUSENOTSAT, "Terminate not allowed for authentication object");
	}
	this.isTerminated = true;
}



/**
 * Convert object to a human readable string
 */
AuthenticationObject.prototype.toString = function() {
	var state = "";
	if (this.isBlocked()) {
		state += "blocked ";
	} else if (this.isTerminated) {
		state += "terminated ";
	} else {
		if (this.isActive) {
			state += "active ";
		}
		if (this.isActive) {
			state += "enabled ";
		} else {
			state += "disabled ";
		}
		if (this.isTransport) {
			state += "transport ";
		}
	}
	var str = this.type + ":" + this.name + "(" + this.id + ") is " + state;
	if (this.initialretrycounter) {
		str += " RC=" + this.retrycounter;
	}
	return str;
}


