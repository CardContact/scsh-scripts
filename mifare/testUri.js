load("ndef.js");
load("loader.js");

var loader = new Loader();
//loader.initialize();

///////////////////////////////////////////////////

print("--------------Uri mit http...--------------\n");

var n = Ndef.newUri("http://www.openscdp.org");
var enc = n.getEncoded();
var n2 = new Ndef(enc);
//print(n.getUri());
print(n2.getUri());
print(enc);
//loader.load(enc)

///////////////////////////////////////////////////

print("\n--------------Encoded Telephone Number--------------\n");

var enc = new ByteString("D1010D55052b3335383931323334353637", HEX);
var telephoneNumber = new Ndef(enc);
print(telephoneNumber.getUri());
print(telephoneNumber.toString());

// loader.load(telephoneNumber.getEncoded());

///////////////////////////////////////////////////

print("\n--------------Proprietary URI--------------\n");

var n = Ndef.newUri("mms://example.com/download.wmv" );
print(n.getUri());
print(n.getEncoded()); 

//loader.load(n.getEncoded());

///////////////////////////////////////////////////

print("\n--------------Testing Chunked Record--------------\n");

// D1 01 0D 55 052b3335383931323334353637

// B1 01 08 55 052b333538393132 
// 36 00 03    333435 
// 56 00 02    3637


var enc = new ByteString("B1010855052b3335383931323600033334355600023637", HEX);
var dec = new Ndef(enc);
print(dec.toString());
print(dec.getUri());
print(dec.getEncoded());

//loader.load(dec.getEncoded());


