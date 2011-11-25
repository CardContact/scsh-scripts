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
 * @fileoverview Core elements of a test group containing individual test cases
 */


 
/**
 * Create a test group object containing Global Tester test cases.
 * 
 * @class
 * <p>Abstract base class implementing a group of test cases.</p>
 * @constructor
 * @param {String} name the name of the test group
 * @param {String} dir the directory in which test case are executed (for including files with load())
 * @param {Object} parameter the parameter object for this group of tests
 */
function GTTestGroup(name, dir, parameter) {
	this.name = name;
	this.dir = dir;
	this.parameter = parameter;
	this.testcasenames = [];
	this.testcases = [];
}



/**
 * Load all test cases defined in a test suite
 *
 * <p>Test groups are allocated for any sub-directories. If no sub-directories are defined, then
 * the test group "Default" is created.
 *
 * @param {String} filename the suite file
 * @param {Object} parameter the parameter object. Properties are copied into the scope in which test cases
 *                           are executed
 * @type TestGroup[] Hash table of test groups
 */
GTTestGroup.loadSuite = function(filename, parameter) {
	filename = filename.replace("\\", "/", "g");
	
	var ofs = filename.lastIndexOf("/");
	
	var dir = "";
	if (ofs >= 0) {
		dir = filename.substr(0, ofs);
	}
	
	// Create XML parser
	var tsparser = new GPXML();

	tsparser.defineArrayElement("/testsuite/testcases", "testcase");
	
	var suite = tsparser.parse(filename);

	var groups = [];
	
	for (var i = 0; i < suite.testcases.testcase.length; i++) {
		var casename = suite.testcases.testcase[i].elementValue;
		var o = casename.lastIndexOf("/");
		var groupname = "Default";
		var subdir = "";
		if (o > 0) {
			groupname = casename.substr(0, o);
			casename = casename.substr(o + 1);
			subdir = "/" + groupname;
		}

		if (typeof(groups[groupname]) == "undefined") {
//			print("dir/subdir: " + dir + " - " + subdir);
			groups[groupname] = new GTTestGroup(groupname, dir + subdir, parameter);
		}
		groups[groupname].addTestCase(casename);
	}
	return groups;
}



/**
 * Return the name of the test group
 *
 * @type String
 * @return the test group name
 */
GTTestGroup.prototype.getName = function() {
	return this.name;
}



/**
 * Return a list of test case names
 *
 * @type String[]
 * @return the list of test case names
 */
GTTestGroup.prototype.getTestCaseNames = function() {
	return this.testcasenames;
}



/**
 * Return the list of test procedures used by a test case
 *
 * @type String[]
 * @return empty list as not used in this context
 */
GTTestGroup.prototype.getUsedTestProceduresForTestCase = function() {
	return [];
}



/**
 * Parse the XML file and add the test case to the group
 *
 * @param {String} name the name of the test case xml relative to the directory for this test group
 */
GTTestGroup.prototype.addTestCase = function(name) {
	this.testcasenames.push(name);

	var fn = this.dir + "/" + name;

	// Create XML parser
	var tcparser = new GPXML();

	// Define location of script fragments in XML file
	tcparser.defineScriptElement("/testsuite/testcase/preconditions", false);
	tcparser.defineScriptElement("/testsuite/testcase/testscript", false);
	tcparser.defineScriptElement("/testsuite/testcase/postconditions/condition", false);

	// Postconditions contain an array of conditions
	tcparser.defineArrayElement("/testsuite/testcase/postconditions", "condition");
	
	this.testcases[name] = tcparser.parse(fn);
}



/**
 * Run all tests in this test group
 *
 * @param {TestRunner} runner the controlling test runner instance
 */
GTTestGroup.prototype.run = function(runner) {
	for (var i = 0; i < this.testcasenames.length; i++) {
		this.runTestCase(this.testcasenames[i], runner);
	}
}



/**
 * Run named tests from this test group
 *
 * @param {String} casename the test case named as defined by the file name
 * @param {TestRunner} runner the controlling test runner instance
 */
GTTestGroup.prototype.runTestCase = function(casename, runner) {
	var tc = this.testcases[casename];
	
	// Create new dynamic scope that stores all global variables from test script
	// Use "Shell" for a scope that contains the print() method or "Object" for a completly clean scope
	var scope = JsScript.newDynamicScope("Shell");

	for (var i in this.parameter) {
		scope[i] = this.parameter[i];
	}
	scope.AssertionError = function(location, level, code, text, validSW, receivedSW) {
								this.location = location;
								this.level = level;
								this.code = code;
								this.text = text;
								this.validSW = validSW;
								this.receivedSW = receivedSW;
								};
	scope.AssertionError.prototype.toString = function() { print(this.text); };
	scope.print = GPSystem.trace;
	
	print("Running test " + tc.testcase.testcaseid.elementValue + " - " + tc.testcase.shortdescription.elementValue);
	
	GPSystem.markTrace();
	// Execute script from preconditions
	tc.testcase.preconditions.Script.execute(scope, this.dir);

	//Execute script from testscript
	try	{
		tc.testcase.testscript.Script.execute(scope, this.dir);
		var logfile = GPSystem.copyTrace();

		//Execute script from all postconditions
		for (var i = 0; i < tc.testcase.postconditions.condition.length; i++) {
			tc.testcase.postconditions.condition[i].Script.execute(scope, this.dir);
		}
		runner.hasPassed(this.name + "/" + casename, logfile);
	}
	catch(e) {
		var msg = e + " in " + e.fileName + "#" + e.lineNumber;
		print(msg);
		GPSystem.trace(msg);
		var logfile = GPSystem.copyTrace();
		runner.hasFailed(this.name + "/" + casename, logfile);
	}
}
