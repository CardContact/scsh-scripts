/*
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2006 CardContact Software & System Consulting
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
 * @fileoverview
 * BlackListGenerator - Simple generator for black lists
 * based on TR-03129, Version 1.0
 *
 *
 * TODO: For now we only support ECC crypto
 *
 */
 
//TODO: Move to oid file
//ASN1.defineObjectIdentifier("id-BlackList", "bsi-de applications(3) eID(2) 2");


/*
 * Define a generator object for the black list generator
 */
// Constructor
function BlackListGenerator() {
	this.content = new ASN1("content", ASN1.SEQUENCE);
}


BlackListGenerator.prototype.reset = function() {
}


BlackListGenerator.prototype.setVersion = function(version) {
	this.version = version;
}


BlackListGenerator.prototype.setType = function(type) {
	this.type = type;
}


BlackListGenerator.prototype.setListID = function(listID) {
	this.listID = listID;
}


BlackListGenerator.prototype.setDeltaBase = function(deltaBase) {
	this.deltaBase = deltaBase;
}

BlackListGenerator.prototype.setDeltaBase = function(deltaBase) {
	this.deltaBase = deltaBase;
}

BlackListGenerator.prototype.addBlackListDetails = function(sectorID, sectorSpecificIDs) {

	// Create the details
	var details = new ASN1("BlackListDetails", ASN1.SEQUENCE);
	details.add(new ASN1("sectorID", ASN1.OCTET_STRING, new ByteString(sectorID, HEX)));

	var ids = new ASN1("sectorSpecificIDs", ASN1.SEQUENCE);
	
	for (var index in sectorSpecificIDs) {
		var sectorSpecificID = sectorSpecificIDs[index];
		ids.add(new ASN1(ASN1.OCTET_STRING, sectorSpecificID));
	}
	
	// Add the IDs to the details
	details.add(ids);

	// Add the details to the content
	this.content.add(details);
}

BlackListGenerator.prototype.generateBlackList = function() {
	
	// Create a black list
	var bl = new ASN1(ASN1.SEQUENCE);

	bl.add(new ASN1("version", ASN1.INTEGER, new ByteString(this.version, HEX)));

	bl.add(new ASN1("type", ASN1.INTEGER, new ByteString(this.type, HEX)));

	bl.add(new ASN1("listID", ASN1.OCTET_STRING, new ByteString(this.listID, HEX)));

	if (typeof(this.deltaBase) != "undefined") {
		bl.add(new ASN1("deltaBase", ASN1.OCTET_STRING, new ByteString(this.deltaBase, HEX)));
	}

	// Add the content to the list
	bl.add(this.content);
	
	return bl.getBytes();
}
