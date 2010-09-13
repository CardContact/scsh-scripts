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
 * @fileoverview Data model as reference data for tests
 */



/**
 * Create data model object
 *
 * @class Class providing for a reference model containing static card data
 * @constructor
 */
function CardDataModel() {
	this.dm = { name: "CardSIM" };

	this.dm.MF = { fid:"3F00"};
	CardDataModel.populateFromProfile(this.dm.MF, CardDataModel.path + "/mf.xml");
	
	var k = new Key();
	k.setComponent(Key.AES, new ByteString("7CA110454A1A6E570131D9619DC1376E4A1A6E570131D961", HEX));
	this.dm.MF.K_MAC = k;

	var k = new Key();
	k.setComponent(Key.AES, new ByteString("0131D9619DC1376E7CA110454A1A6E579DC1376E7CA11045", HEX));
	this.dm.MF.K_ENC = k;


}

CardDataModel.path = GPSystem.mapFilename("", GPSystem.CWD);



/**
 * Populate a node from an XML profile
 *
 * @param {Object} node the node where the data from the profile is inserted
 * @param {String} profile the XML application profile
 */
CardDataModel.populateFromProfile = function(node, profile) {
	var xml = GPXML.parse(profile);
	var list = xml.DataStructure.FileStructure.EF;
	for (var i = 0; i < list.length; i++) {
		var item = list[i];
		node[item.name] = item;
	}
}



/**
 * Return the node at the given path
 *
 * @param {String} path the path to the node
 * @type Object
 * @return the node
 */
CardDataModel.prototype.getNode = function(path) {
	var items = path.split("/");
	var node = this.dm;
	for (var i = 0; i <items.length; i++) {
		node = node[items[i]];
		if (!node) {
			throw new GPError("CardDataModel", GPError.OBJECT_NOT_FOUND, 0, "Element " + path + " not found in data model");
		}
//		print(items[i] + ":" + node);
	}
	return node;
}



/**
 * Dump the complete model
 */
CardDataModel.prototype.dump = function() {
	function _dump(indent, o) {
		for (i in o) {
			var t = o[i];
			if (typeof(t) == "object") {
				print(indent + i + ":");
				_dump(indent + "  ", t);
			} else {
				print(indent + i + ": " + o[i]);
			}
		}
	}
	
	_dump("", this.dm);
}
