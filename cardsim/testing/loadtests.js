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
 * @fileoverview Script to load all tests for the card simulation test suite into the GUI test runner
 */

//
// Script to load test cases
//


load("tools/TestRunner.js");
load("tools/TestGroup.js");
load("tools/TestProcedure.js");

load("../datamodel.js");


var param = new Array();

param["dataModel"] = new CardDataModel();
param["card"] = new Card();
param["crypto"] = new Crypto();

var testRunner = new TestRunner("Card Simulation Test Suite");

testRunner.addTestProcedureFromXML("tp_fci.xml");
testRunner.addTestGroupFromXML("tg_select.xml", param);
testRunner.addTestGroupFromXML("tg_readbinary_even_ins.xml", param);
testRunner.addTestGroupFromXML("tg_readbinary_odd_ins.xml", param);
testRunner.addTestGroupFromXML("tg_readbinary_sw.xml", param);
testRunner.addTestGroupFromXML("tg_updatebinary_even_ins.xml", param);
testRunner.addTestGroupFromXML("tg_updatebinary_odd_ins.xml", param);
testRunner.addTestGroupFromXML("tg_updatebinary_sw.xml", param);
testRunner.addTestGroupFromXML("tg_secmsg.xml", param);

print("Test-Suite loaded...");
