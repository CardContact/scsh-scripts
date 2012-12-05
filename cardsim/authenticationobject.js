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
	this.name = name;
	this.type = type;
	this.id = id;
	this.value = value;
	this.retrycounter = 3;
	this.initialretrycounter = 3;
	this.usecounter = -1;
	this.resetcounter = -1;
	this.isActive = true;
	this.isEnabled = true;
	this.isTransport = false;
	this.allowActivate = false;
	this.allowDeactivate = false;
	this.allowEnable = false;
	this.allowDisable = false;
	this.allowResetRetryCounter = false;
	this.allowResetValue = false;
	this.unsuspendAuthenticationObject = null;
	this.unblockAuthenticationObject = null;
}

AuthenticationObject.TYPE_PACE = "pace";
AuthenticationObject.TYPE_PIN = "pin";



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
 * Convert object to a human readable string
 */
AuthenticationObject.prototype.toString = function() {
	var state = "";
	if (this.isBlocked()) {
		state += "blocked ";
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


