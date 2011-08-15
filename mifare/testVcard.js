load("ndef.js");
load("vcard.js");
load("loader.js");

var v = new Vcard();

v.setFormattedName("Max Mustermann");
v.setOrganization("CardContact");
v.addTelephone(null, "1234");
v.addEmail("CardContact@CardContact.de");
v.setUrl("www.cardcontact.de");

var enc = v.getEncoded();

var n = Ndef.newMessage("text/x-vCard", enc);

enc = n.getEncoded();

var loader = new Loader();
//loader.initialize();
loader.load(enc);

