//
//  ---------
// |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
// |#       #|  
// |#       #|  Copyright (c) 1999-2006 CardContact Software & System Consulting
// |'##> <##'|  Andreas Schwier, 32429 Minden, Germany (www.cardcontact.de)
//  --------- 
//
//  This file is part of OpenSCDP.
//
//  OpenSCDP is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  OpenSCDP is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with OpenSCDP; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
//
//  Simple test runner framework

// defineClass("de.cardcontact.scdp.scsh3.OutlineNode");




// ---------------------------
// Create a test runner object
//
function TestRunner(name) {

	this.name = name;
	this.testGroupRunners = new Array();
	this.testProcedures = new Array();
	this.testMapper = new Array();
//	this.testGroupPrototype = new TestGroup();
//	this.testProcedurePrototype = new TestProcedure();
	
	// Create root node and set as view
	var view = new OutlineNode(name, true);
	view.setContextMenu(["run", "clear"]);
	view.setUserObject(this);
	this.view = view;

	view.show();
}



//
// Event listener for actions selected from context menu
//
TestRunner.prototype.actionListener = function(source, actionName) {
	switch(actionName) {
	case "run" :
		this.run();
		break;
	case "clear" :
		this.clearResults();
		break;
	}
}



//
// Add a test group to the test runner
// This will iterate through all test cases and locate used procedures and steps
//
TestRunner.prototype.addTestGroup = function(testGroup) {
	var tgrs = this.testGroupRunners;
	
	tgr = new TestGroupRunner(this, testGroup);

	tgrs.push(tgr);

	var view = this.view;	
	view.insert(tgr.view);
}



//
// Create test group from XML file and add to test runner
// 
TestRunner.prototype.addTestGroupFromXML = function (file, parameter) {
	// Parse XML file.
	var parser = new GPXML();
	parser.defineArrayElement("/testgroup", "testcase,function", "id,Name");
	parser.defineArrayElement("/testgroup/testcase/procedures", "procedure");
	var xml = parser.parse(file);

	// Determine CTOR function
	var ctor = xml.constructor.Script;
	if (!ctor) {
		// Use a default constructor unless defined in XML profile
		ctor = function(name, parameter) { TestGroup.call(this, name, parameter); };
	}
	
	// Make CTOR available in scope object
	// this[xml.id] = ctor;
	
	// Set correct prototype object
	ctor.prototype = new TestGroup();
	ctor.prototype.constructor = ctor;
	ctor.prototype.usedProcedures = new Array();
	
	// Add test cases to prototype object
	var testcases = xml.testcase;
	for (var i in testcases) {
		if (i != "arrayIndex") {
			var s = testcases[i].Script;
			ctor.prototype["case" + i] = s;
			if (testcases[i].procedures) {
				var procedures = testcases[i].procedures.procedure;
				ctor.prototype.usedProcedures[i] = new Array();
				
				for (var p = 0; p < procedures.length; p++) {
					ctor.prototype.usedProcedures[i].push(procedures[p].id);
				}
			}
		}
	}
	
	// Add setup function to prototype object
	if (xml.setup) {
		ctor.prototype["setUp"] = xml.setup.Script;
	}
	
	// Add teardown function to prototype object
	if (xml.teardown) {
		ctor.prototype["tearDown"] = xml.teardown.Script;
	}
	
	// Add functions to prototype object
	var functions = xml["function"];
	for (var i in functions) {
		if (i != "arrayIndex") {
			var s = functions[i].Script;
			ctor.prototype[i] = s;
		}
	}
	
	ctor.XML = xml;
	
	var tc = new ctor(xml.id, parameter);
	
	this.addTestGroup(tc);
}



//
// Add a test procedure constructor to the list
// Use the getName() method to obtain the test procedure name
//
TestRunner.prototype.addTestProcedure = function(proc) {
	var name = proc.getName();
	if (name) {
		this.testProcedures[name] = proc;
	}
}



//
// Create test procedure from XML file and add to test runner
// 
TestRunner.prototype.addTestProcedureFromXML = function (file, parameter) {
	// Parse XML file.
	var parser = new GPXML();
	parser.defineArrayElement("/testprocedure", "teststep,function", "id,Name");
	var xml = parser.parse(file);

	// Determine CTOR function
	var ctor = xml.constructor.Script;
	if (!ctor) {
		// Use a default constructor unless defined in XML profile
		ctor = function(testgroup, name, parameter) { TestProcedure.call(this, testgroup, name, parameter); };
	}

	// Make CTOR available in scope object
	// this[xml.id] = ctor;
	
	// Set correct prototype object
	ctor.prototype = new TestProcedure();
	ctor.prototype.constructor = ctor;
	var teststeps = xml.teststep;
	for (var i in teststeps) {
		if (i != "arrayIndex") {
			var s = teststeps[i].Script;
			ctor.prototype["step" + i] = s;
		}
	}
	if (xml.setup) {
		ctor.prototype["setUp"] = xml.setup.Script;
	}
	if (xml.teardown) {
		ctor.prototype["tearDown"] = xml.teardown.Script;
	}
	
	// Add functions to prototype object
	var functions = xml["function"];
	for (var i in functions) {
		if (i != "arrayIndex") {
			var s = functions[i].Script;
			ctor.prototype[i] = s;
		}
	}

	ctor.XML = xml;
	ctor.getName = function() { return xml.id; };	

	this.testProcedures[xml.id] = ctor;
}



//
// Return constructor of test procedure
// 
TestRunner.prototype.getTestProcedure = function(name) {
	return this.testProcedures[name];
}



//
// Add test to test mapper, which maps test unique id to listening object
//
TestRunner.prototype.addTest = function(name, listener) {
	this.testMapper[name] = listener;
}



//
// Run all test groups
//
TestRunner.prototype.run = function() {
	for (var i = 0; i < this.testGroupRunners.length; i++) {
		var testGroupRunner = this.testGroupRunners[i];
		testGroupRunner.run();
	}
}



//
// Clear result of last test run
//
TestRunner.prototype.clearResults = function() {
	for (var i in this.testMapper) {
		var listener = this.testMapper[i];
		if (listener) {
			listener.clearResult();
		}
	}
}



//
// Enable or disable test
//
TestRunner.prototype.enable = function(name, state) {
	var listener = this.testMapper[name];
	if (listener && listener.enable) {
		return listener.enable(state);
	} else {
		throw new GPError("TestRunner", GPError.OBJECT_NOT_FOUND, 0, name);
	}
}



//
// isEnabled query from TestGroup runner
//
TestRunner.prototype.isEnabled = function(name) {
	var listener = this.testMapper[name];
	if (listener) {
		return listener.isEnabled();
	}
	return true;
}



//
// hasPassed Listener
//
TestRunner.prototype.hasPassed = function(name, log) {
	var listener = this.testMapper[name];
	if (listener) {
		listener.hasPassed(log);
	} else {
		print("No receiver for passed notification : " + name);
		for (var i in this.testMapper) {
			print("- " + i);
		}
	}
}



//
// hasFailed Listener
//
TestRunner.prototype.hasFailed = function(name, log) {
	var listener = this.testMapper[name];
	if (listener) {
		listener.hasFailed(log);
	}
}



// ----------------------------------------
// Constructor for a TestGroupRunner object
//
function TestGroupRunner(testRunner, testGroup) {
	this.testRunner = testRunner;
	this.testGroup = testGroup;
	
	var view = new OutlineNode(testGroup.getName());
	view.setContextMenu(["run"]);
	view.setUserObject(this);
	
	this.view = view;

	var testcases = testGroup.getTestCaseNames();
	
	for (var i = 0; i < testcases.length; i++) {
		var tcr = new TestCaseRunner(this, testcases[i]);
		view.insert(tcr.view);
	}
}



//
// Event listener for context menu
//
TestGroupRunner.prototype.actionListener = function(source, action) {
	switch(action) {
	case "run" : 
		this.run();
		break;
	}
}



//
// run this test group
//
TestGroupRunner.prototype.run = function() {
	var test = this.testGroup;
	
	test.run(this.testRunner);
}




// ---------------------------------------
// Constructor for a TestCaseRunner object
//
function TestCaseRunner(testGroupRunner, testCase) {
	this.testGroupRunner = testGroupRunner;
	this.testCase = testCase;
	this.selected = true;

	var testRunner = testGroupRunner.testRunner;
	testRunner.addTest(testGroupRunner.testGroup.getName() + "/" + testCase, this);
			
	var view = new OutlineNode(testCase);
	view.setUserObject(this);
	view.setIcon("selected");
	view.setContextMenu(["select", "deselect", "run"]);
	this.view = view;

	var testGroup = testGroupRunner.testGroup;
		
	var testprocedures = testGroup.getUsedTestProceduresForTestCase(testCase);
	
	if (testprocedures) {
		for (var i = 0; i < testprocedures.length; i++) {
			var tpr = new TestProcedureRunner(this, testprocedures[i]);
			view.insert(tpr.view);
		}
	}
}



//
// Action listener for context menu
//
TestCaseRunner.prototype.actionListener = function(source, actionName) {
	print("Action " + actionName);
	switch(actionName) {
	case "select":
		this.selected = true;
		source.setIcon("selected");
		break;
	case "deselect":
		this.selected = false;
		source.setIcon("deselected");
		break;
	case "run":
		this.run();
		break;
	}
}



//
// Run this test case
//
TestCaseRunner.prototype.run = function() {
	var test = this.testGroupRunner.testGroup;
	
	test.runTestCase(this.testCase, this.testGroupRunner.testRunner);
}



//
// Tell test runner if case is enabled
//
TestCaseRunner.prototype.isEnabled = function() {
	return this.selected;
}



//
// Add a log entry to the test case node
//
TestCaseRunner.prototype.addLog = function(log) {
	var view = this.view;
	var lognode = new TestLogFile(this, log);
	this.log = lognode;
	view.insert(lognode.view);
}



//
// Listener for passed notifications
// 
TestCaseRunner.prototype.hasPassed = function(log) {
	this.failed = false;
	var view = this.view;
	view.setIcon("passed");
	this.addLog(log);
}



//
// Listener for failed notifications
// 
TestCaseRunner.prototype.hasFailed = function(log) {
	this.failed = true;
	var view = this.view;
	view.setIcon("failed");
	this.addLog(log);
}



//
// Clear result of test
//
TestCaseRunner.prototype.clearResult = function() {
	this.failed = false;
	var view = this.view;
	if (this.selected) {
		view.setIcon("selected");
	} else {
		view.setIcon("deselected");
	}
}




//
// Enable or disable test
//
TestCaseRunner.prototype.enable = function(state) {
	var view = this.view;
	this.selected = state;
	if (this.selected) {
		view.setIcon("selected");
	} else {
		view.setIcon("deselected");
	}
}




//
// Constructor for test log entry in outline
//
function TestLogFile(parent, log) {
	this.log = log;
	
	var view = new OutlineNode("Log from " + Date());
	this.view = view;
	view.setUserObject(this);
}



//
// Listener for node selection - Display log
//
TestLogFile.prototype.selectedListener = function() {
	print("--------------------------------------------------------------------------------");
	print(this.log);
}



// --------------------------------------------
// Constructor for a TestProcedureRunner object
//
function TestProcedureRunner(testCaseRunner, testProcedure) {
	this.testCaseRunner = testCaseRunner;
	this.testProcedure = testProcedure;
	
	var view = new OutlineNode(testProcedure);
	this.view = view;

	var tp = this.testCaseRunner.testGroupRunner.testRunner.testProcedures[testProcedure];

	if (tp) {
		var list = new Array();
		for (var i in tp.prototype) {
			if (i.substr(0, 4) == "step") {
				var step = i.substr(4);
				list.push(step);
			}
		}

		list.sort();
		
		for (var i = 0; i < list.length; i++) {
			var tpsr = new TestStepRunner(this, list[i]);
			view.insert(tpsr.view);
		}
	} else {
		print("No test procedure implementation found for " + testProcedure);
	}
}




// ---------------------------------------
// Constructor for a TestStepRunner object
//
function TestStepRunner(testProcedureRunner, testStep) {
	this.testProcedureRunner = testProcedureRunner;
	this.testStep = testStep;
	
	var view = new OutlineNode(testStep);
	this.view = view;

	var testCaseRunner = testProcedureRunner.testCaseRunner;	
	var testGroupRunner = testCaseRunner.testGroupRunner;
	var testRunner = testGroupRunner.testRunner;
	var testName = testGroupRunner.testGroup.getName() + "/" + 
	               testCaseRunner.testCase + "/" + 
	               testProcedureRunner.testProcedure + "/" +
	               testStep;
	               
	testRunner.addTest(testName, this);
}



//
// Receive passed notifications
//
TestStepRunner.prototype.hasPassed = function() {
	var view = this.view;
	view.setIcon("passed");
}



//
// Clear test result display
//
TestStepRunner.prototype.clearResult = function() {
	var view = this.view;
	view.setIcon();
}

