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
 * Create a test group object containing test cases.
 * 
 * @class
 * <p>Abstract base class implementing a group of test cases.</p>
 * <p>Actual test group objects are derived from this base class.</p>
 * <p>Each test case is created as a method of this object.</p>
 * @constructor
 * @param {String} name the name of the test group
 * @param {Object} parameter the parameter object for this group of tests
 */
function TestGroup(name, parameter) {

	this.name = name;
	this.parameter = parameter;
	this.logfile = new String("--- TestGroup " + name + "\n");
	this.marker = null;
	
//	print("TestGroup constructor called");
}



/**
 * Log a text message.
 * 
 * @param {String} message the message to add to the log
 */
TestGroup.prototype.log = function(message) {
	this.logfile += message + "\n";
//	print(message);
}



/**
 * Setup method called before invoking each individual test case.
 */
TestGroup.prototype.setUp = function() {
//	this.log("TestGroup.setUp() called");
}



/**
 * Teardown method called after invocation of a test case.
 */
TestGroup.prototype.tearDown = function() {
//	this.log("TestGroup.tearDown() called");
}



/**
 * Verify that the given assertion evaluates to true. Throw an exception if result is false.
 * 
 * @param {Boolean} result true if assertion is valid
 * @param {String} message the message to log in case result is false
 */
TestGroup.prototype.assertTrue = function(result, message) {
	if (!result) {
		if (this.marker) {
			throw new Error("Assertion failed for [" + this.marker + "]: " + message);
		} else {
			throw new Error("Assertion failed: " + message);
		}
	}
}



/**
 * Verify that the given values are equal. Throw an exception if not.
 * 
 * @param {Any} first the first argument
 * @param {Any} second the second argument
 * @param {String} message the message to log in case result is false
 */
TestGroup.prototype.assertEquals = function(first, second, message) {
	if (first != second) {
		if (this.marker) {
			throw new Error("Assertion failed for [" + this.marker + "]: " + message);
		} else {
			throw new Error("Assertion failed: " + message);
		}
	}
}



/**
 * Sets a marker used to identify a context in which an assertion failed.
 * 
 * <p>A context can be a certain iteration
 * or group of assertions. A marker allows to further identify the area of a problem.</p>
 * 
 * @param {String} marker the marker to set
 */
TestGroup.prototype.setMarker = function(marker) {
	this.marker = marker;
}



/**
 * Returns the name of test group.
 * 
 * @type String
 * @return the name of the test group
 */
TestGroup.prototype.getName = function() {
		return this.name;
}



/**
 * Returns a list of tests as sorted array of test case names.
 * 
 * @type String[]
 * @return the sorted array of test case names
 */
TestGroup.prototype.getTestCaseNames = function() {
	var tests = new Array();
	
	for (f in this) {
		if (f.substr(0, 4) == "case") {
			if (this[f] instanceof Function) {
				tests.push(f.substr(4));
			}
		}
	}

	tests.sort();
	return tests;
}



/**
 * Returns a specific test case function.
 * 
 * @param {String} name the test case name
 * @type Function
 * @return the test case method
 */
TestGroup.prototype.getTestCase = function(name) {
	return this["case" + name];
}



/**
 * Returns a list of test procedure names referenced by a test case.
 * 
 * @param {String} test case name
 * @type String[]
 * @return a list of test procedure names or undefined
 */
TestGroup.prototype.getUsedTestProceduresForTestCase = function(name) {
	if (this.constructor.prototype.usedProcedures) {
		return this.constructor.prototype.usedProcedures[name];
	} else {
		return undefined;
	}
}



/**
 * Run a named test procedure.
 * 
 * <p>This method is called by code in a test case to run a test procedure.</p>
 * <p>This method uses the test runner to create a new instance of the test procedure object.
 * All test steps in the procedure are executed and the test procedure object is returned to
 * the caller for further processing of test results.</p>
 * 
 * @param {String} name the test procedure name
 * @param {Object} param the parameter object to pass to the execution of the test procedure
 * @type TestProcedure
 * @return the test procedure object
 */
TestGroup.prototype.runTestProcedure = function(name, param) {
	if (!this.testRunner) {
		throw new GPError("TestGroup", GPError.INVALID_USAGE, 0, "No test runner defined");
	}
	var proc = this.testRunner.getTestProcedure(name);
	var test = new proc(name, this, param);
	test.run();
	
	return test; 
}



/**
 * Report progress of passed steps in a test procedure to the test runner. This method is used internally.
 * 
 * @private
 * @param {String} procedure the procedure name
 * @param {String} step the step name
 */
TestGroup.prototype.reportProgress = function(procedure, step) {
	if (this.testRunner) {
		var runner = this.testRunner;
		var uniqueName = this.currentTestCase + "/" + procedure + "/" + step;
		runner.hasPassed(uniqueName, null);
	}
}



/**
 * Initialize a test run. This method is used internally.
 * @private
 */
TestGroup.prototype.initTestRun = function() {
	this.marker = null;
}



/**
 * Run a single test case. This method is called internally. Use {@link #runTestCase} for running a single test case.
 * 
 * @private
 * @type boolean
 * @return true if test passed
 */
TestGroup.prototype.runTestCaseInternal = function(casename, runner) {
	var result = false;
	this.currentTestCase = this.name + "/" + casename;
	this.testRunner = runner;

	this.logfile = "";

	var starttime = new Date();
	logentry = "TestCase " + this.currentTestCase + " started " + starttime;
	print(logentry);
	this.log(logentry);
	try {
		this.setUp();
		var func = this.getTestCase(casename);
		func.call(this);
		this.tearDown();
		var endtime = new Date();
		logentry = "TestCase " + this.currentTestCase + " completed on " + endtime + " after " + (endtime.valueOf() - starttime.valueOf()) + " ms";
		print(logentry);
		this.log(logentry);
		if (runner) {
			runner.hasPassed(this.currentTestCase, this.logfile);
		}
		result = true;
	}
	catch(e) {
		var endtime = new Date();
		logentry = "TestCase " + this.currentTestCase + " failed on " + endtime + " after " + (endtime.valueOf() - starttime.valueOf()) + " ms";
		print(logentry);
		this.log(logentry);
		
		logentry = "  ### - " + e;
		print(logentry);
		this.log(logentry);
		for (j in e) {
			logentry = "  ### " + j + " = " + e[j];
			print(logentry);
			this.log(logentry);
		}
		
		if (runner) {
			runner.hasFailed(this.currentTestCase, this.logfile);
		}
	}
	return result;
}



/**
 * Runs all tests in a test group.
 * 
 * <p>This method can be used to run a test group without a test runner. In that case leave the runner
 * argument empty or null.</p>
 * 
 * @param {TestRunner} runner the test runner to report progress or undefined or null
 */
TestGroup.prototype.run = function(runner) {
	this.initTestRun();
	
	var tests = this.getTestCaseNames();
	
	var startgroup = new Date();
	var logentry = "TestGroup " + this.name + " started " + startgroup;
	var failures = 0;
	print(logentry);
	this.log(logentry);
	
	for (var i = 0; i < tests.length; i++) {
		var uniqueName = this.name + "/" + tests[i];
		
		if (runner) {
			if (!runner.isEnabled(uniqueName))
				continue;
		}
		
		if (!this.runTestCaseInternal(tests[i], runner)) {
			failures++;
		}
	}

	var endgroup = new Date();
	logentry = "TestGroup " + this.name + " completed on " + endgroup + " with " + failures + " failed tests";
	print(logentry);
	this.log(logentry);
}



/**
 * Run a single test in a test group, optionally using a test runner.
 * 
 * @param {String} casename the name of the test case
 * @param {TestRunner} the test runner object or undefined or null
 */
TestGroup.prototype.runTestCase = function(casename, runner) {
	this.initTestRun();
	this.runTestCaseInternal(casename, runner);
}
