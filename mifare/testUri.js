//---TEST---
load("ndef.js");

///////////////////////////////////////////////////

print("--------------Uri mit http...--------------\n");

var n = Ndef.newUri("http://www.openscdp.org");
var enc = n.getEncoded();
var n2 = new Ndef(enc);
//print(n.getUri());
print(n2.getUri());

///////////////////////////////////////////////////

print("\n--------------Encoded Telephone Number--------------\n");

var enc = new ByteString("D1010D55052b3335383931323334353637", HEX);
var telephoneNumber = new Ndef(enc);
print(telephoneNumber.getUri());
print(telephoneNumber.toString());

///////////////////////////////////////////////////

print("\n--------------Proprietary URI--------------\n");

var n = Ndef.newUri("mms://example.com/download.wmv" );
print(n.getUri());
print(n.getEncoded()); 
// print(n.getPayload());

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
// print("bla");
// print(dec.isIdLengthFlag());

///////////////////////////////////////////////////
print("\n--------------Ndef Message--------------\n");

load("vcard.js");

var v = new Vcard();

v.setFormattedName("Max Mustermann");
v.setOrganization("CardContact");
v.addTelephone(null, "0571");
v.addEmail("CardContact@CardContact.de");
v.addUrl("www.cardcontact.de");

var enc = v.getEncoded();

var n = Ndef.newMessage("text/x-vCard", enc);

enc = n.getEncoded();
print(enc);

///////////////////////////////////////////////////
