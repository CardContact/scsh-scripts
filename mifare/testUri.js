load("ndef.js");
load("loader.js");

var loader = new Loader();
loader.initialize();

///////////////////////////////////////////////////

print("--------------Uri mit http...--------------\n");

var n = Ndef.newUri("http://www.openscdp.org");
var enc = n.getEncoded();
var n2 = new Ndef(enc);
//print(n.getUri());
print(n2.getUri());
print(enc);
loader.load(enc)
