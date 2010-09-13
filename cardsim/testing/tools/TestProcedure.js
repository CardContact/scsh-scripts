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
 *  Core elements of a test procedure
 */


//
// Constructor
// 
function TestProcedure(name, testgroup, parameter) {

	this.name = name;
	this.testgroup = testgroup;
	this.parameter = parameter;
//	print("TestProcedure constructor called");
}



//
// Log message to console
// 
TestProcedure.prototype.log = function(message) {
	this.testgroup.log(message);
//	print(message);
}



//
// Setup object for a test procedure
//
TestProcedure.prototype.setUp = function() {
//	this.log("TestProcedure.setUp() called");
}



//
// Remove residue from test procedure
// 
TestProcedure.prototype.tearDown = function() {
//	this.log("TestProcedure.tearDown() called");
}



//
// Verify that assertion is true
//
TestProcedure.prototype.assertTrue = function(result, message) {
	this.testgroup.assertTrue(result, message);
}



//
// Verify that expressions are equal
//
TestProcedure.prototype.assertEquals = function(first, second, message) {
	this.testgroup.assertEquals(first, second, message);
}



//
// Run all tests in a test procedure
//
TestProcedure.prototype.run = function() {
	var steps = new Array();
	
	for (f in this) {
		if (f.substr(0, 4) == "step") {
			if (this[f] instanceof Function) {
				steps.push(f);
			}
		}
	}

	steps.sort();
	
	for (var i = 0; i < steps.length; i++) {
		var step = steps[i].substr(4);
//		print("    Step " + step + " of procedure " +  this.name);
		this.setUp();
		this[steps[i]].call(this);
		this.tearDown();

		var testgroup = this.testgroup;
		testgroup.reportProgress(this.name, step);
	}
}
