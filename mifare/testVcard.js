load("ndef.js");
load("vcard.js");
load("storeNdef.js");

var v = new Vcard();

v.setFormattedName("Max Mustermann");
v.setOrganization("CardContact");
v.addTelephone(null, "0571");
v.addEmail("CardContact@CardContact.de");
v.addUrl("www.cardcontact.de");

var enc = v.getEncoded();

var n = Ndef.newMessage("text/x-vCard", enc);

enc = n.getEncoded();

var loader = new Loader();
//loader.initialize();
loader.load(enc);

