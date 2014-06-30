
load("tools/TestRunner.js");
load("tools/TestGroup.js");
load("tools/TestProcedure.js");

var param = new Array();

param.maxAPDU = 1024;

function strInfo(info) {
	return info.bytes(0, 4).toString(HEX) + "  Nc(Req)=" + info.bytes(4,2).toUnsigned() + 
				" Nc(Rcvd)=" + info.bytes(6,2).toUnsigned() + 
				" Ne(Req)=" + info.bytes(8,2).toUnsigned() + 
				" Ne(Trans)=" + info.bytes(10,2).toUnsigned();
}



var testRunner = new TestRunner("APDU Testapplet Approval Test Suite");
testRunner.addTestGroupFromXML("tg_case_1.xml", param);
testRunner.addTestGroupFromXML("tg_case_2.xml", param);
testRunner.addTestGroupFromXML("tg_case_3.xml", param);
testRunner.addTestGroupFromXML("tg_case_4.xml", param);
print("Test-Suite loaded...");
