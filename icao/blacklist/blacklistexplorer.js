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
 * @fileoverview Tool to decode and browse CMS objects
 */


requires("3.6.790");


/**
 * Creates a simple BlackListExplorer object
 *
 * @class Class providing a simple explorer for CMS objects according to RFC 3852
 * containing blacklist according to TR-03129, Version 1.0.
 */
function BlackListExplorer() {
}


// Some static strings
BlackListExplorer.FILESTR = "Open File...";
BlackListExplorer.DUMPSTR = "Dump";
BlackListExplorer.DUMPIDS = "Dump RevIDs";
BlackListExplorer.REMOVESTR = "Remove";


/**
 * Loads a binary file from disk
 *
 * @param {String} filename the fully qualified file name
 * @return the binary content
 * @type ByteString
 */
BlackListExplorer.loadBinaryFile = function(filename) {
	// Open stream
	var f = new java.io.FileInputStream(filename);

	// Determine file size
	var flen = f.available();

	// Allocate native byte array
	var bs = java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, flen);

	// Read into byte array
	var len = f.read(bs);

	// Allocate JavaScript ByteBuffer from native/wrapped byte array
	var bb = new ByteBuffer(bs);

	// Convert to JavaScript ByteString
	var data = bb.toByteString();

	return data;
}



/**
 * Dump an ASN.1 encoded CMS object
 *
 * @param {CMS} cms the cms object to dump
 */
BlackListExplorer.dumpCMS = function(cms) {
	print(new ASN1(cms.bin));
}



/**
 * Selects a file with a file dialog, creates the associated node in the outline
 * and dumps the CMS and blacklist contents.
 *
 */
BlackListExplorer.prototype.selectFile = function() {
	var filename = _scsh3.lastcms;
	if (!filename) {
		filename = "";
	}

	var select = Dialog.prompt("Select file", filename, null, "*.bin");

	if (select != null) {
		_scsh3.setProperty("lastcms", select.replace(/\\/g, "/"));

		var bin = BlackListExplorer.loadBinaryFile(select);

		var cms = new CMSSignedData(bin);

		var fn = new OutlineNode(select);
		fn.cms = cms;
		fn.cms.bin = bin;
		fn.setContextMenu([BlackListExplorer.DUMPSTR, BlackListExplorer.DUMPIDS, BlackListExplorer.REMOVESTR ]);
		fn.setUserObject(this);

		this.node.insert(fn);

		// Add all the certificates
		var certs = cms.getSignedDataCertificates();
		var signerCertsNode = new OutlineNode("Number of signer certificates: " + certs.length);

		for (i = 0; i < certs.length; i++) {
			var cert = certs[i];
			var certNode = new OutlineNode(cert.getSubjectDNString());
			certNode.insert(new ASN1(cert.getBytes()));
			signerCertsNode.insert(certNode);
		}

		fn.insert(signerCertsNode);
		fn.insert(new OutlineNode("Content type OID: " + cms.getEContentType().toString(OID)));
		// fn.insert(new ASN1(bin));

		var content = new ASN1(cms.getSignedContent());
		var contentNode = new OutlineNode("Signed content");
		contentNode.insert(content);

		fn.insert(contentNode);
	}
}



BlackListExplorer.prototype.dumpIDS = function(cms) {

	var id = new ByteString("049DFDFC117C2D0879EE13A9C9B2F058909D66C5EE428D5699ED6F755ADB858A618C988C47D92FF3BE793DE9C56DB8F44C352282A5B2F15DAA38B526B6A8397C7D", HEX);
	while (id.length > 0) {
		var ofs = cms.bin.find(id);
		if (ofs >= 0) {
			print("Found " + id.toString(HEX) + " [" + id.length + "] at " + ofs);
			print(cms.bin.bytes(ofs & ~15, 512));
			break;
		}
		id = id.left(id.length - 1);
	}

	var sofs = ofs;

//	var id = new ByteString("049DFDFC117C2D0879EE13A9C9B2F058909D66C5EE428D5699ED6F755ADB858A618C988C47D92FF3BE793DE9C56DB8F44C352282A5B2F15DAA38B526B6A8397C7D", HEX);
	var id = new ByteString("38B526B6A8397C7D", HEX);
	while (id.length > 0) {
		var ofs = cms.bin.find(id);
		if (ofs >= 0) {
			print("Found " + id.toString(HEX) + " [" + id.length + "] at " + ofs);
			print(cms.bin.bytes(ofs & ~15, 256));
			break;
		}
		id = id.left(id.length - 1);
	}


	var content = new ASN1(cms.getSignedContent());
	var list = content.get(4).get(0).get(1);
	print("Elements " + list.elements);
	for (var i = 0; i < list.elements; i++) {
		var r = list.get(i);
		print(r.value.toString(HEX));
	}

}



/**
 * Action listener called when a entry in the context menu is selected
 *
 * @param {OutlineNode} source the object to which the context menu is associated
 * @param {String} action the action selected from the context menu
 */
BlackListExplorer.prototype.actionListener = function(source, action) {

	switch(action) {
	case BlackListExplorer.FILESTR:
		this.selectFile();
		break;
	case BlackListExplorer.DUMPSTR:
		BlackListExplorer.dumpCMS(source.cms);
		break;
	case BlackListExplorer.DUMPIDS:
		this.dumpIDS(source.cms);
		break;
	case BlackListExplorer.REMOVESTR:
		source.remove();
		break;
	}
}



/**
 * Creates the top level node and displays the outline
 */
BlackListExplorer.prototype.run = function() {
	this.node = new OutlineNode("BlackListExplorer");
	this.node.setToolTip("Right click to select file");
	this.node.setUserObject(this);
	this.node.setContextMenu([BlackListExplorer.FILESTR]);
	this.node.show();
	print("Click with the right mouse button on the \"BlackListExplorer\" entry to select a file");
}



var instance = new BlackListExplorer();
instance.run();
