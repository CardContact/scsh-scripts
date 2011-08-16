/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2011 CardContact Software & System Consulting
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
 * @fileoverview Create a vCard object
 */

function Vcard() {
	
}


/**
 *	Set Name.
 */
Vcard.prototype.setName = function(firstName, lastName) {
	this.n = "N:" + lastName + ";" + firstName + "\n";
}


/**
 *	Check if the Name is present.
 *	@return {Boolean}
 */
Vcard.prototype.hasName = function() {
	return this.n != undefined;
}


/**
 *	Set Formatted Name with the structure: "first name last name".
 *	@param {String} fname 
 */
Vcard.prototype.setFormattedName = function(fname) {
	this.fn = "FN:" + fname + "\n";
}

/**
 *	Check if Formatted Name is present.
 *	@return {Boolean}
 */
Vcard.prototype.hasFormattedName = function() {
	return this.fn != undefined;
}


/**
 *	Set Nickname.
 *	@param {String} nick 
 */
Vcard.prototype.setNickname = function(nick) {
	this.nickname = "NICKNAME:" + nick + "\n";
}


/**
 *	Check if Nickname is present.
 *	@return {Boolean}
 */
Vcard.prototype.hasNickname = function() {
	return this.nickname != undefined;
}
	

/**
 *	Set Birthday
 *	@param {String} bday 
 */ 
Vcard.prototype.setBirthday = function(bday) {
	this.bday = "BDAY:" + bday + "\n";
}	


/**
 *	Check if Birthday is present.
 *	@return {Boolean}
 */
Vcard.prototype.hasBirthday = function() {
	return this.bday != undefined;
}


/**
 *	Set Organization.
 *	@param {String} org 
 */ 
Vcard.prototype.setOrganization = function(org) {
	this.org = "ORG:" + org + "\n";
}


/**
 *	Check if Organization is present.
 *	@return {Boolean}
 */
Vcard.prototype.hasOrganization = function() {
	return this.org != undefined;
}


/**
 *	Set Version
 *	@param {String} version 
 */ 
Vcard.prototype.setVersion = function(version) {
	this.version = "VERSION:" + version + "\n";
}


/**
 *	Check if Version is present.
 *	@return {Boolean}
 */
Vcard.prototype.hasVersion = function() {
	return this.version != undefined;
}


/**
 *	Add a telephone number to the buffer.
 *
 *	@param {String} type The type parameter specify the use of the number or null if not present. 
 *	The types are: home, msg, work, pref , fax, pager, etc.
 *	A number can have serveral type which are seperated with commas.
 *
 *	@param {Number} tel The telephone number.
 */ 
Vcard.prototype.addTelephone = function(type, tel) {
	if (type == null) {
		tel = "TEL:" + tel + "\n";
	}
	else {
		tel = "TEL;TYPE=" + type + ":" + tel + "\n";
	}
	if (this.tel == undefined) {
		this.tel = new ByteBuffer(tel, ASCII);
	}
	else {
		this.tel.append(tel);
	}
}


/**
 *	Check if Telephone Number is present.
 *	@return {Boolean}
 */
Vcard.prototype.hasTelephone = function() {
	return this.tel != undefined;
}


/**
 *	Add an Email to the buffer.
 *	@param {String} email
 */
Vcard.prototype.addEmail = function(email) {
	email = "EMAIL;TYPE=internet:" + email + "\n";
	if (this.email == undefined) {
		this.email = new ByteBuffer(email, ASCII);
	}
	else {
		this.email.append(email, ASCII);
	}
}


/**
 *	Check if Email Address is present.
 *	@return {Boolean}
 */
Vcard.prototype.hasEmail = function() {
	return this.email != undefined;
}


/**
 *	Set an Address.
 * @param {String} street
 * @param {String} city
 * @param {String} postalCode
 * @param {String} country
 */
Vcard.prototype.setAddress = function(street, city, postalCode, country) {
	this.adr = "ADR:;;" + street + city + ";;" + postalCode + country + "\n"; 
}


/**
 *	Check if Address is present.
 *	@return {Boolean}
 */
Vcard.prototype.hasAddress = function() {
	return this.adr != undefined;
}


/**
 *	Set a URL.
 *	@param {String} url
 */
Vcard.prototype.setUrl = function(url) {
	this.url = "URL:" + url + "\n";
}


/**
 *	Check if URL is present.
 *	@return {Boolean}
 */
Vcard.prototype.hasUrl = function() {
	return this.url != undefined;
}


/**
 * Return the encoded vCard object
 * @return {ByteString} the encoded vCard
 */
Vcard.prototype.getEncoded = function() {
	encoded = new ByteBuffer();
	encoded.append(new ByteString("BEGIN:VCARD\n", ASCII));
	if (this.hasName()) {
		encoded.append(this.n);		
	}
	if (this.hasFormattedName()) {
		encoded.append(this.fn);
	}
	if (this.hasNickname()) {
		encoded.append(this.nickname);
	}
	if (this.hasBirthday()) {
		encoded.append(this.bday);
	}
	if (this.hasOrganization()) {
		encoded.append(this.org);
	}
	if (this.hasVersion()) {
		encoded.append(this.version);
	}
	if (this.hasTelephone()) {
		encoded.append(this.tel.toByteString());
	}
	if (this.hasEmail()) {
		encoded.append(this.email.toByteString());
	}
	if (this.hasAddress()) {
		encoded.append(this.adr);
	}
	if (this.hasUrl()) {
		encoded.append(this.url);
	}
	encoded.append(new ByteString("END:VCARD", ASCII));
	return encoded.toByteString();
}