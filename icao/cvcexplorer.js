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
 * @fileoverview Tool to decode and dump CVC certificates
 */


load("cvc.js");



/**
 * Creates a simple CVCExplorer object
 *
 * @class Class providing for a simple explorer for CV-Certificates according to EAC specification.
 */
function CVCExplorer() {
}



// Some static strings
CVCExplorer.FILESTR = "Open File...";
CVCExplorer.DUMPSTR = "Dump";
CVCExplorer.REMOVESTR = "Remove";




/**
 * Loads a binary file from disk
 *
 * @param {String} filename the fully qualified file name
 * @return the binary content
 * @type ByteString
 */
CVCExplorer.loadBinaryFile = function(filename) {
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
 * Dump certificate content
 *
 * @param {CVC} cvc the certificate to dump
 */
CVCExplorer.dumpCertificate = function(cvc) {
	print("-----8<----------8<----------8<----------8<----------8<----------8<----------8<----------8<-----");
	print(cvc);
	var list = cvc.getRightsAsList();
	for (var i = 0; i < list.length; i++) {
		print("  " + list[i]);
	}
	print(cvc.getASN1());
}



/**
 * Selects a file with a file dialog, creates the associated node in the outline
 * and dumps the certificate contents.
 *
 */
CVCExplorer.prototype.selectFile = function() {
	var filename = _scsh3.lastcvc;
	if (!filename) {
		filename = "";
	}
	
	var select = Dialog.prompt("Select CVC file", filename, null, "*.cvcert");
	
	if (select != null) {
		_scsh3.setProperty("lastcvc", select.replace(/\\/g, "/"));
		
		var bin = CVCExplorer.loadBinaryFile(select);
		
		var cvc = new CVC(bin);
		cvc.decorate();
		
		var fn = new OutlineNode(select);
		fn.cvc = cvc;
		fn.setContextMenu([CVCExplorer.DUMPSTR, CVCExplorer.REMOVESTR]);
		fn.setUserObject(this);
		
		this.node.insert(fn);
		fn.insert(cvc.getASN1());
		
		CVCExplorer.dumpCertificate(cvc);
	}
}



/**
 * Action listener called when a entry in the context menu is selected
 *
 * @param {OutlineNode} source the object to which the context menu is associated
 * @param {String} action the action selected from the context menu
 */  
CVCExplorer.prototype.actionListener = function(source, action) {

	switch(action) {
	case CVCExplorer.FILESTR:
		this.selectFile();
		break;
	case CVCExplorer.DUMPSTR:
		CVCExplorer.dumpCertificate(source.cvc);
		break;
	case CVCExplorer.REMOVESTR:
		source.remove();
		break;
	}
}



/**
 * Creates the top level node and displays the outline
 */
CVCExplorer.prototype.run = function() {
	this.node = new OutlineNode("CVCExplorer");
	this.node.setToolTip("Right click to select file");
	this.node.setUserObject(this);
	this.node.setContextMenu([CVCExplorer.FILESTR]);
	this.node.show();
	print("Click with the right mouse button on the \"CVCExplorer\" entry to select a file");
}



var instance = new CVCExplorer();
instance.run();
