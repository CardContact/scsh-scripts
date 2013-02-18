/**
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
 * @fileoverview General File I/O Class
 */



/**
 * Create a reference to a file system object (file or directory)
 *
 * @class Class implementing basic support for files
 * @constructor
 * @param {String} name relative or absolute file path
 */
function File(name) {
	this.name = name;
}



/**
 * Return absolute path
 *
 * @param{Number} mode one of GPSystem.AUTO, GPSystem.CWD, GPSystem.USR or GPSystem.SYS. See GPSystem.mapFilename() for details
 * @type String
 * @return the absolute path
 */
File.prototype.getAbsolutePath = function(mode) {
	if (typeof(mode) == "undefined") {
		mode = GPSystem.CWD;
	}
	if (typeof(this.abspath) == "undefined") {
		this.abspath = GPSystem.mapFilename(this.name, mode);
	}
	return this.abspath;
}



/**
 * @private
 * Return a java.io.File object
 */
File.prototype.getFile = function() {
	if (typeof(this.file) == "undefined") {
		this.file = new java.io.File(this.getAbsolutePath(GPSystem.AUTO));
	}
	return this.file; 
}



/**
 * Close streams associated with file
 */
File.prototype.close = function() {
	if (typeof(this.os) != "undefined") {
		this.os.close();
		delete(this.os);
	}

	if (typeof(this.is) != "undefined") {
		this.is.close();
		delete(this.is);
	}
}



/**
 * @private
 * Return a java.io.FileInputStream
 */
File.prototype.getInputStream = function() {
	if (typeof(this.is) == "undefined") {
		this.is = new java.io.FileInputStream(this.getAbsolutePath(GPSystem.AUTO));
	}
	return this.is; 
}



/**
 * @private
 * Return a java.io.FileOutputStream
 */
File.prototype.getOutputStream = function() {
	if (typeof(this.os) == "undefined") {
		this.os = new java.io.FileOutputStream(this.getAbsolutePath(GPSystem.CWD));
	}
	return this.os; 
}



/**
 * Read complete file into ByteString object
 *
 * @type ByteString
 * @return the binary content
 */
File.prototype.readAllAsBinary = function() {
	var is = this.getInputStream();

	// Determine file size
	var flen = is.available();

	// Allocate native byte array
	var bs = java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, flen);

	// Read into byte array
	var len = is.read(bs);

	this.close();

	// Allocate JavaScript ByteBuffer from native/wrapped byte array
	var bb = new ByteBuffer(bs);

	// Convert to JavaScript ByteString
	var data = bb.toByteString();

	return data;
}



/**
 * Read complete file into String object
 *
 * @type String
 * @return the text content
 */
File.prototype.readAllAsString = function(encoding) {

	if (typeof(encoding) == "undefined") {
		encoding = UTF8;
	}

	return this.readAllAsBinary().toString(encoding);
}



/**
 * Write the object to file
 *
 * @param{Object} obj to write to file (Using toString() for any other than String and ByteString)
 * @param{Number} one of UTF8 or ASCII (Default is UTF8)
 */
File.prototype.writeAll = function(obj, encoding) {
	if ((typeof(obj) != "string") && !(obj instanceof ByteString)) {
		obj = obj.toString();
	}
	if (typeof(obj) == "string") {
		if (typeof(encoding) == "undefined") {
			encoding = UTF8;
		}
		obj = new ByteString(obj, encoding);
	}

	var os = this.getOutputStream();
	os.write(obj);
	this.close();
}



/**
 * Return list of files contained in the directory referenced by the File object
 *
 * @type String[]
 * @return the list of file names
 */
File.prototype.list = function() {
	var list = this.getFile().list();
	var jslist = [];
	
	for (var i = 0; i < list.length; i++) {
		jslist.push(new String(list[i]));
	}
	return jslist;
}



/**
 * Return the parent file of this file object
 *
 * @type File
 * @return the parent file object or null
 */
File.prototype.getParentFile = function() {
	var file = this.getFile();
	var parent = file.getParent();
	if (parent == null) {
		return null;
	}
	return new File(parent);
}



File.test = function() {
	var file = new File("test.bin");
	var b = new ByteString("Hello World", ASCII);
	file.writeAll(b);
	
	var file = new File("test.bin");
	var c = file.readAllAsBinary();
	print(c.toString(ASCII));
	
	var file = new File("test.txt");
	var s = "Hello World";
	file.writeAll(s);
	
	var file = new File("test.txt");
	var c = file.readAllAsString();
	print(c);
	
	var dir = file.getParentFile();
	print(dir.getAbsolutePath());
	print(dir.list());
	
}
