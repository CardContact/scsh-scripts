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
 * @fileoverview Implementation of a ISO 7816-4 file system simulation
 */


load("apdu.js");



/**
 * Create a File Control Parameter containing information about a file system node
 *
 * @class Class storing File Control Parameter for a file system node
 * @constructor
 */
function FCP() {
}


/** File type for DF */
FCP.DEDICATEDFILE = 0x38;

/** File type for transparent EF */
FCP.TRANSPARENT   = 0x01;

/** File type for record oriented EF with fixed record size */
FCP.LINEARFIXED   = 0x02;

/** File type for record oriented EF with variable record size */
FCP.LINEARVARIABLE   = 0x04;


/**
 * Convert an integer value into an two byte ByteString
 *
 * @param {Number} val the value
 * @type ByteString
 * @return the 2 byte encoded value MSB||LSB
 */
FCP.short2bytestring = function(val) {
	var bb = new ByteBuffer();
	bb.append(val >> 8);
	bb.append(val & 0xFF);
	return(bb.toByteString());
}



/**
 * Construct a new FCP object from parameters.
 *
 * <p>This function should never be called directly. Use newTransparentDF(), newDF() or newLinearEF() instead.</p>
 *
 * @param {String|ByteString} fid the file identifier (2 Bytes)
 * @param {Number} sfi the short file identifier or -1 if not defined
 * @param {Number} type the file type, one of FCP.DEDICATEDFILE, FCP.TRANSPARENT or FCP.LINEAR*
 * @param {Boolean} shareable true, if file may be shared between logical channels
 * @param {Boolean} internal true, if file is internal only and not externally selectable
 * @param {ByteString} supl supplemental information
 * @type FCP
 * @return the newly constructed FCP object
 */
FCP.newFCP = function(fid, sfi, type, shareable, internal, supl) {
	var fcp = new FCP();
	
	if (fid != null) {
		if (typeof(fid) == "string") {
			if (fid.length != 4) {
				throw new GPError("FCP", GPError.INVALID_DATA, 0, "File Identifier must be 2 bytes");
			}
			fcp.fid = new ByteString(fid, HEX);
		} else if (fid instanceof ByteString) {
			if (fid.length != 2) {
				throw new GPError("FCP", GPError.INVALID_DATA, 0, "File Identifier must be 2 bytes");
			}
			fcp.fid = fid;
		} else {
			throw new GPError("FCP", GPError.INVALID_TYPE, 0, "Argument must be of type String or ByteString");
		}
	}
	
	if (typeof(sfi) != "number") {
		throw new GPError("FCP", GPError.INVALID_TYPE, 1, "Argument must be of type Number");
	}
	fcp.sfi = sfi;

	if (typeof(type) != "number") {
		throw new GPError("FCP", GPError.INVALID_TYPE, 2, "Argument must be of type Number");
	}
	fcp.type = type;

	if (typeof(shareable) != "boolean") {
		throw new GPError("FCP", GPError.INVALID_TYPE, 3, "Argument must be of type Boolean");
	}
	fcp.shareable = shareable;

	if (typeof(internal) != "boolean") {
		throw new GPError("FCP", GPError.INVALID_TYPE, 4, "Argument must be of type Boolean");
	}
	fcp.internal = internal;

	fcp.supl = supl;
	return fcp;
}



/**
 * Construct a new FCP object for an EF of type transparent.
 *
 * @param {String|ByteString} fid the file identifier (2 Bytes)
 * @param {Number} sfi the short file identifier or -1 if not defined
 * @param {Number} size the file size
 * @param {ByteString} supl supplemental information
 * @type FCP
 * @return the newly constructed FCP object
 */
FCP.newTransparentEF = function(fid, sfi, size, supl) {
	if (typeof(size) != "number") {
		throw new GPError("FCP", GPError.INVALID_TYPE, 2, "Argument size must be of type Number");
	}

	var fcp = FCP.newFCP(fid, sfi, FCP.TRANSPARENT, false, false, supl);

	fcp.size = size;
	return fcp;
}



/**
 * Construct a new FCP object for a DF.
 *
 * @param {String|ByteString} fid the file identifier (2 Bytes)
 * @param {ByteString} aid the DF's application identifier (DFName)
 * @param {ByteString} supl supplemental information
 * @type FCP
 * @return the newly constructed FCP object
 */
FCP.newDF = function(fid, aid, supl) {
	var fcp = FCP.newFCP(fid, -1, FCP.DEDICATEDFILE, false, false, supl);

	if (aid != null) {
		if ((typeof(aid) != "object") && !(aid instanceof(ByteString))) {
			throw new GPError("FCP", GPError.INVALID_TYPE, 2, "Argument size must be of type Number");
		}
		fcp.aid = aid;
	}

	return fcp;
}



/**
 * Construct a new FCP object for an EF of type linear.
 *
 * @param {String|ByteString} fid the file identifier (2 Bytes)
 * @param {Number} sfi the short file identifier or -1 if not defined
 * @param {Number} type the file type, one of FCP.LINEARFIXED or FCP.LINEARVARIABLE
 * @param {Number} recsize the maximum or fixed record size
 * @param {Number} recno the maximum number of records
 * @param {ByteString} supl supplemental information
 * @type FCP
 * @return the newly constructed FCP object
 */
FCP.newLinearEF = function(fid, sfi, type, recsize, recno, supl) {
	if (typeof(recsize) != "number") {
		throw new GPError("FCP", GPError.INVALID_TYPE, 3, "Argument recsize must be of type Number");
	}
	if (typeof(recno) != "number") {
		throw new GPError("FCP", GPError.INVALID_TYPE, 4, "Argument recno must be of type Number");
	}

	var fcp = FCP.newFCP(fid, sfi, type, false, false, supl);
	return fcp;
}



/**
 * Returns the File Identifier (FID)
 *
 * @type ByteString
 * @return the FID
 */
FCP.prototype.getFID = function() {
	return this.fid;
}



/**
 * Returns the Application Identifier (AID)
 *
 * @type ByteString
 * @return the AID
 */
FCP.prototype.getAID = function() {
	return this.aid;
}



/**
 * Returns the Short File Identifier (SFI)
 *
 * @type Number
 * @return the SFI
 */
FCP.prototype.getSFI = function() {
	return this.sfi;
}



/**
 * Returns the encoded FCP
 *
 * @type ByteString
 * @return the encoded FCP
 */
FCP.prototype.getBytes = function() {
	var fcp = new ASN1("fcp", 0x62);

	if (typeof(this.size) != "undefined") {
		fcp.add(new ASN1("fileSizeTransparent", 0x80, FCP.short2bytestring(this.size)));
	}

	var bb = new ByteBuffer();
	bb.append(this.type);
	
	// ToDo: extra type bytes
	
	fcp.add(new ASN1("fileDescriptor", 0x82, bb.toByteString()));
	
	if (typeof(this.fid) != "undefined") {
		fcp.add(new ASN1("fileIdentifier", 0x83, this.fid));
	}
	
	if (typeof(this.aid) != "undefined") {
		fcp.add(new ASN1("dFName", 0x84, this.aid));
	}
	
	if ((typeof(this.sfi) != "undefined") && (this.sfi > 0)) {
		var bb = new ByteBuffer();
		bb.append(this.sfi << 3);
		fcp.add(new ASN1("shortFileIdentifier", 0x88, bb.toByteString()));
	}
	
	return(fcp.getBytes());
}



/**
 * Return a human readible string for this object
 *
 * @type String
 * @return the string
 */
FCP.prototype.toString = function() {
	var str = "FCP(";
	
	for (var i in this) {
		if (typeof(this[i]) != "function") {
			str += i + "=" + this[i] + ",";
		}
	}
	str += ")";
	return str;
}



/**
 * Construct a file system node
 *
 * @class Abstract class for file system nodes
 * @constructor
 */
function FSNode(fcp) {
	this.parent = null;
	this.fcp = fcp;
}



/**
 * Sets the parent for this node
 *
 * @param {DF} the parent node
 */
FSNode.prototype.setParent = function(parent) {
	if ((typeof(parent) != "object") && !(parent instanceof(DF))) {
		throw new GPError("FSNode", GPError.INVALID_TYPE, 0, "Argument parent must be of type DF");
	}
	this.parent = parent;
}



/**
 * Gets the parent node for this node
 *
 * @type DF
 * @returns the parent node
 */
FSNode.prototype.getParent = function() {
	return this.parent;
}



/**
 * Gets the file control parameter for this node
 *
 * @type FCP
 * @returns the FCP
 */
FSNode.prototype.getFCP = function() {
	return this.fcp;
}



/**
 * Returns true if this is a DF
 *
 * @type boolean
 * @return true if this is a DF
 */
FSNode.prototype.isDF = function() {
	return (this instanceof DF);
}



/**
 * Returns a human readible string
 *
 * @type String
 * @return a string
 */
FSNode.prototype.toString = function() {
	if (!this.fcp) {
		return "FSNode";
	}
	return this.fcp.getFID().toString(HEX);
}



/**
 * Create a file system node that represents a transparent EF
 *
 * @class Class implementing a transparent EF
 * @constructor
 * @param {FCP} fcp the FCP for this EF
 * @param {ByteString} contents the contents for this EF
 */
function TransparentEF(fcp, contents) {
	if (!(fcp instanceof FCP)) {
		throw new GPError("TransparentEF", GPError.INVALID_TYPE, APDU.SW_GENERALERROR, "Argument 1 must be of type FCP");
	}

	if ((typeof(contents) != "undefined") && (contents != null) && !(contents instanceof ByteString)) {
		throw new GPError("TransparentEF", GPError.INVALID_TYPE, APDU.SW_GENERALERROR, "Argument 2 must be of type ByteString");
	}

	FSNode.call(this, fcp);
	this.content = contents;
}

TransparentEF.prototype = new FSNode();
TransparentEF.prototype.constructor = TransparentEF;



/**
 * Reads data from a transparent EF
 *
 * @param {APDU} apdu the APDU used for reading
 * @param {Number} offset the offset to read from
 * @param {Number} length the length in bytes or 0 for all in short APDU or 65536 for all in extended APDUs
 * @type ByteString
 * @return the data read
 */
TransparentEF.prototype.readBinary = function(apdu, offset, length) {
	if (typeof(offset) != "number") {
		throw new GPError("TransparentEF", GPError.INVALID_TYPE, APDU.SW_GENERALERROR, "Offset must be type Number");
	}
	if (typeof(length) != "number") {
		throw new GPError("TransparentEF", GPError.INVALID_TYPE, APDU.SW_GENERALERROR, "Length must be type Number");
	}

	if (offset >= this.content.length) {
	
	}
	
	var rlen = length;
	if ((length == 0) || (length == 65536)) {
		rlen = this.content.length - offset;
		if ((length == 0) && (rlen > 256)) {
			rlen = 256;
		}
	}
	return this.content.bytes(offset, rlen);
}



/**
 * Creates a LinearEF
 *
 * @class Class implementing linear EFs
 * @constructor
 * @param {FCP} the file control parameter
 * @param {ByteString[]} records the array of records
 */
function LinearEF(fcp, records) {
	if (!(fcp instanceof FCP)) {
		throw new GPError("LinearEF", GPError.INVALID_TYPE, APDU.SW_GENERALERROR, "Argument 1 must be of type FCP");
	}
	if ((typeof(records) != "undefined") && (records != null) && (typeof(records) != "array")) {
		throw new GPError("LinearEF", GPError.INVALID_TYPE, APDU.SW_GENERALERROR, "Argument 2 must be of type ByteString[]");
	}

	FSNode.call(this, fcp);
	this.records = records;
}

LinearEF.prototype = new FSNode();
LinearEF.prototype.constructor = LinearEF;



/**
 * Creates a Dedicated File (DF)
 *
 * <p>The constructor supports as argument a list of child elements</p>
 *
 * @class Class implementing dedicated files
 * @constructor
 * @param {FCP} the file control parameter
 */
function DF(fcp) {
	this.childs = new Array();
	this.fidmap = new Array();
	this.sfimap = new Array();
	this.aidmap = new Array();
	
	FSNode.call(this, fcp);
	
	if (arguments.length > 1) {
		for (var i = 1; i < arguments.length; i++) {
			var arg = arguments[i];
			this.add(arg);
		}
	}
}

DF.prototype = new FSNode();
DF.prototype.constructor = DF;



/**
 * Adds a new child node to the DF
 *
 * @param {FSNode} node the node to add
 */
DF.prototype.add = function(node) {
	this.childs.push(node);
	node.setParent(this);
	
	var f = node.getFCP();
	
	var fid = f.getFID();
	if (fid) {
		if (this.fidmap[fid]) {
			throw new GPError("DF", GPError.INVALID_DATA, APDU.SW_FILEEXISTS, "Duplicate file identifier " + fid);
		}
		this.fidmap[fid] = node;
	}

	if (node.isDF()) {
		var aid = f.getAID();
		if (aid) {
			if (this.aidmap[aid]) {
				throw new GPError("DF", GPError.INVALID_DATA, APDU.SW_FILEEXISTS, "Duplicate application identifier " + aid);
			}
			this.aidmap[aid] = node;
		}
	} else {
		var sfi = f.getSFI();
//		print("Found SFI " + sfi);
		if (sfi != -1) {
			if (this.sfimap[sfi]) {
				throw new GPError("DF", GPError.INVALID_DATA, APDU.SW_FILEEXISTS, "Duplicate short file identifier " + sfi);
			}
			this.sfimap[sfi] = node;
		}
	}

}



/**
 * Select a file contained in the DF using the file identifier
 *
 * @param {ByteString} the file identifier
 * @type FSNode
 * @return the found node or undefined
 */
DF.prototype.selectByFID = function(fid) {
	return this.fidmap[fid];
}



/**
 * Select a file contained in the DF using the short file identifier
 *
 * @param {Number} the short file identifier
 * @type FSNode
 * @return the found node or undefined
 */
DF.prototype.selectBySFI = function(sfi) {
	return this.sfimap[sfi];
}



/**
 * Select a DF contained in the DF using the application identifier
 *
 * @param {ByteString} the application identifier
 * @type FSNode
 * @return the found node or undefined
 */
DF.prototype.selectByAID = function(aid) {
	return this.aidmap[aid];
}



/**
 * Dump the file system system recursively starting this this node
 *
 * @param {String} indent the string to prefix the output with
 * @type String
 * @return the dump 
 */
DF.prototype.dump = function(indent) {
	var str = indent + this.toString() + "\n";
	
	for (var i = 0; i < this.childs.length; i++) {
		var c = this.childs[i];
		
		if (c instanceof DF) {
			str += c.dump("  " + indent);
		} else {
			str += "  " + indent + c.toString() + "\n";
		}
	}
	return str;
}



/**
 * Create a file selector object
 *
 * @class Class implementing a file selector used to store information about the currently selected
 *        file system object and to process the SELECT APDU
 * @constructor
 * @param {DF} mf the master file
 */
function FileSelector(mf) {
	if ((typeof(mf) != "object") && !(mf instanceof DF)) {
		throw new GPError("FileSelector", GPError.INVALID_TYPE, APDU.SW_GENERALERROR, "Argument 1 must be of type DF");
	}
	this.mf = mf;
	this.currentDF = mf;
	this.currentEF = null;
}



/**
 * Select the MF
 */
FileSelector.prototype.selectMF = function() {
	this.currentDF = this.mf;
	this.currentEF = null;

	return this.mf;
}



/**
 * Select a DF entry by FID
 *
 * @param {ByteString} fid the file identifier
 * @param {boolean} check if file matches expected type EF or DF
 * @param {boolean} df true if the check must check for a DF type, else a EF type
 * @type FSNode
 * @return the selected file system node
 */
FileSelector.prototype.selectFID = function(fid, check, df) {
	var node = this.currentDF.selectByFID(fid);
	
	if (!node) {
		throw new GPError("FileSelector", GPError.INVALID_DATA, APDU.SW_FILENOTFOUND, "File " + fid + " not found");
	}

	if (check) {
		if ((df && !node.isDF()) || (!df && node.isDF())) {
			throw new GPError("FileSelector", GPError.INVALID_DATA, APDU.SW_FILENOTFOUND, "File " + fid + " not found or not of matching type");
		}
	}
	
	if (node.isDF()) {
		this.currentDF = node;
		this.currentEF = null;
	} else {
		this.currentEF = node;
	}
	return node;
}



/**
 * Processes the SELECT APDU
 *
 * <p>Supports in P1</p>
 * <ul>
 *  <li>'00' with empty data to select the MF</li>
 *  <li>'00' with "3F00" to select the MF</li>
 *  <li>'00' with fid to select an entry in the current DF</li>
 *  <li>'01' with fid to select a DF in the current DF</li>
 *  <li>'02' with fid to select an EF in the current DF</li>
 *  <li>'03' with empty data to select the parent</li>
 * </ul>
 * <p>Supports in P2</p>
 * <ul>
 *  <li>'00' with P1=='00' return no data</li>
 *  <li>'04' return FCP</li>
 *  <li>'0C' return no data</li>
 * </ul>
 * @param {APDU} apdu the select APDU
 */
FileSelector.prototype.processSelectAPDU = function(apdu) {
	var node;
	var reponse;

	var data = apdu.getCData();
	var p1 = apdu.getP1();
	switch(p1) {
	case 0x00:
		if ((typeof(data) == "undefined") || (data.toString(HEX) == "3F00")) {
			node = this.selectMF();
		} else {
			node = this.selectFID(data, false, false);
		}
		break;
	case 0x01:
		node = this.selectFID(data, true, true);
		break;
	case 0x02:
		node = this.selectFID(data, true, false);
		break;
	case 0x03:
		// ToDo data must be missing APDU.SW_INVLC
		if (this.currentEF) {
			this.currentEF = null;
			node = this.currentDF;
		} else {
			node = this.currentDF.getParent();
			if (node) {
				this.currentDF = node;
			} else {
				node = this.currentDF;
			}
		}
		break;
	case 0x04:
		node = this.mf.selectByAID(data);
		if (typeof(node) == "undefined") {
			throw new GPError("FileSelector", GPError.INVALID_DATA, APDU.SW_FILENOTFOUND, "Application " + data + " not found");
		}
		this.currentDF = node;
		this.currentEF = null;
		break;
	default:
		throw new GPError("FileSelector", GPError.INVALID_DATA, APDU.SW_INCP1P2, "Incorrect parameter P1 (" + p1.toString(16) + ")");
	}
	
	var p2 = apdu.getP2();
	switch(p2) {
	case 0x00:
		if (p1 != 0x00) {
			throw new GPError("FileSelector", GPError.INVALID_DATA, APDU.SW_INCP1P2, "Incorrect parameter P2 (" + p2.toString(16) + ")");
		}
		response = new ByteString("", HEX);
		break;
	case 0x04:
		apdu.setRData(node.getFCP().getBytes());
		break;
	case 0x0C:
		response = new ByteString("", HEX);
		break;
	default:
		throw new GPError("FileSelector", GPError.INVALID_DATA, APDU.SW_INCP1P2, "Incorrect parameter P2 (" + p2.toString(16) + ")");
	}

	apdu.setSW(APDU.SW_OK);
}



/**
 * Return a human readable string for this object
 */
FileSelector.prototype.toString = function() {
	return "FileSelector: Current DF=" + this.currentDF + " / Current EF=" + this.currentEF;
}



function test() {

	var aid = new ByteString("A0000000010101", HEX);

	var mf = new DF(FCP.newDF("3F00", null),
						new TransparentEF(FCP.newTransparentEF("2F00", -1, 100)),
						new TransparentEF(FCP.newTransparentEF("2F01", 0x17, 100)),
						new DF(FCP.newDF("DF01", aid),
							new TransparentEF(FCP.newTransparentEF("2F01", -1, 100))
						)
					);

	print(mf.dump(""));

	assert(mf.isDF());
	
	var ef = mf.selectByFID(new ByteString("2F00", HEX));
	assert(!ef.isDF());
	assert(ef.getFCP().getFID().toString(HEX) == "2F00");

	var ef = mf.selectBySFI(0x17);
	assert(ef.getFCP().getFID().toString(HEX) == "2F01");
	
	var df = mf.selectByAID(aid);
	assert(df.getFCP().getFID().toString(HEX) == "DF01");

	var fs = new FileSelector(mf);
	
	var a = new APDU(0x00, 0xA4, 0x00, 0x0C, new ByteString("3F00", HEX));
	fs.processSelectAPDU(a);
	print(fs);
	print(a);

	var a = new APDU(0x00, 0xA4, 0x00, 0x0C, new ByteString("2F00", HEX));
	fs.processSelectAPDU(a);
	print(fs);
	print(a);
	
	var a = new APDU(0x00, 0xA4, 0x01, 0x0C, new ByteString("DF01", HEX));
	fs.processSelectAPDU(a);
	print(fs);
	print(a);

	var a = new APDU(0x00, 0xA4, 0x02, 0x0C, new ByteString("2F01", HEX));
	fs.processSelectAPDU(a);
	print(fs);
	print(a);
}


// test();

