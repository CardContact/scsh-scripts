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
 * @fileoverview Class for reading and writing CSV files
 */



/**
 * Create an instance of a comma separated file access object
 *
 * @class Class implementing support for reading and writing CSV files.
 *
 * @constructor
 *
 */
function CSV() {
	this.db = new Array();
	this.separator = ',';
	this.spec = null;
}



/**
 * Sets the field separator
 *
 * @param {String} separator the separator (',' is default)
 */
CSV.prototype.setSeparator = function(separator) {
	this.separator = separator;
}



/**
 * Sets the field specification
 *
 * @param {String[]} spec the list of field names
 */
CSV.prototype.setSpecification = function(spec) {
	assert(spec instanceof Array);

	this.spec = spec;
	this.map = new Array();

	for (var i = 0; i < spec.length; i++) {
		this.map[spec[i]] = i;
	}
}



/**
 * Reads a CVS file into memory 
 *
 * @param {String} filename the file name
 */
CSV.prototype.readFile = function(filename) {
	var fr = new java.io.FileReader(filename);
	var lbr = new java.io.LineNumberReader(fr);

	var str = lbr.readLine();

	if (!this.spec) {
		if (str == null) {
			throw new GPError("CSV", GPError.INVALID_DATA, 0, "Empty file and no field format specified");
		}

		str = new String(str);

		this.setSpecification(str.split(this.separator));

	}


	while (str = lbr.readLine()) {
		var str = new String(str);
		var fields = str.split(this.separator);
		this.db.push(fields);
	}
	lbr.close();
}



/**
 * Internal function. Writes a line to the CSV file.
 *
 * @param {java.io.FileWriter} filewriter the file writer object
 * @param {String[]} the fields to be written
 */
CSV.prototype.writeLine = function(filewriter, rec) {
	var str = rec[0];
	for (var j = 1; j < rec.length; j++) {
		str += this.separator;
		str += rec[j];
	}
	filewriter.write(str + "\r\n");
}



/**
 * Write CSV file with data from internal data base
 *
 * @param {String} filename the file name
 */
CSV.prototype.writeFile = function(filename) {
	var fw = new java.io.FileWriter(filename);

	if (this.spec) {
		this.writeLine(fw, this.spec);
	}

	for (var i = 0; i < this.db.length; i++) {
		this.writeLine(fw, this.getRecord(i));
	}
	fw.close();
}



/**
 * Gets the number of records stored
 *
 * @return number of records
 * @type Number
 */
CSV.prototype.getNumberOfRecords = function() {
	return this.db.length;
}



/**
 * Gets the indexed record
 *
 * @param {Number} index the 0 based index into the CSV data
 * @return the record identified by index
 * @type String[]
 */
CSV.prototype.getRecord = function(index) {
	return this.db[index];
}



/**
 * Gets the named field from the indexed record
 *
 * @param {Number} index the 0 based index into the CSV data
 * @param {String} fieldname the field name to get
 * @return the field contents
 * @type String
 */
CSV.prototype.getField = function(index, fieldname) {
	var rec = this.getRecord(index);
	var i = this.map[fieldname];

	if (typeof(i) == "undefined") {
		throw new GPError("CSV", GPError.INVALID_DATA, 0, "Field " + fieldname + " not found");
	}

	return rec[i];
}



/**
 * Adds a record to the internal database
 *
 * @param {String[]} rec the record to add
 */
CSV.prototype.addRecord = function(rec) {
	this.db.push(rec);
}



/**
 * Tests the class
 */
CSV.test = function() {

	var csv = new CSV();

	csv.setSeparator(";");
	csv.setSpecification(["Field1", "Field2", "Field3"]);

	var filename = GPSystem.mapFilename("test.csv", GPSystem.CWD);

	var ref1 = ["Rec1F1", "Rec1F2", "Rec1F3"];
	var ref2 = ["Rec2F1", "Rec2F2", "Rec2F3"];
	var ref3 = ["Rec3F1", "Rec3F2", "Rec3F3"];

	assert(csv.getNumberOfRecords() == 0);

	csv.addRecord(ref1);
	csv.addRecord(ref2);
	csv.addRecord(ref3);

	assert(csv.getNumberOfRecords() == 3);

	csv.writeFile(filename);


	var csv = new CSV();
	csv.setSeparator(";");
	csv.readFile(filename);

	assert(csv.getNumberOfRecords() == 3);

	var rec = csv.getRecord(1);
	assert(rec[0] == "Rec2F1");
	assert(rec[1] == "Rec2F2");

	var f2 = csv.getField(2, "Field3");

	assert(f2 == "Rec3F3");

}


// CSV.test();

