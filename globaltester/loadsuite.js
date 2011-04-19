//
// Run Global Tester scripts from the Smart Card Shell
//


load("lib/GTTestGroup.js");
load("lib/TestRunner.js");


// What is our working directory ?
var cwd = GPSystem.mapFilename("", GPSystem.CWD);

var groups = GTTestGroup.loadSuite(cwd + "/suite/testsuite.xml");

var runner = new TestRunner("TestSuite");
for (var i in groups) {
	runner.addTestGroup(groups[i]);
}
