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
 * @fileoverview AccessController base class
 */

 
/**
 * Create an default controller granting read but denying write access 
 * @Class Class implementing a default access controller
 * @constructor
 */
function AccessController() {
	this.name = "AccessController";
}



/**
 * Check if read access to file system node is allowed
 *
 * @param {APDU} apdu the APDU used to access the object
 * @param {FSNode} node the file system object
 * @type boolean
 * @return true if access is allowed
 */
AccessController.prototype.checkFileReadAccess = function(ci, apdu, node) {
	return true;
}



/**
 * Check if write access to file system node is allowed
 *
 * @param {APDU} apdu the APDU used to access the object
 * @param {FSNode} node the file system object
 * @type boolean
 * @return true if access is allowed
 */
AccessController.prototype.checkFileWriteAccess = function(ci, apdu, node) {
	return false;
}



AccessController.prototype.toString = function() {
	return this.name;
}
