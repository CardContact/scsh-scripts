
load("tools/TestRunner.js");
load("tools/TestGroup.js");
load("tools/TestProcedure.js");

var param = new Array();

var testRunner = new TestRunner("APDU Testapplet Approval Test Suite");
testRunner.addTestGroupFromXML("tg_case_1.xml", param);
testRunner.addTestGroupFromXML("tg_case_2.xml", param);
testRunner.addTestGroupFromXML("tg_case_3.xml", param);
testRunner.addTestGroupFromXML("tg_case_4.xml", param);
print("Test-Suite loaded...");
