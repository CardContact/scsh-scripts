load("vcard.js");

var v = new Vcard();

v.setFormattedName("Max Mustermann");
//print(v.hasFormattedName());
v.setOrganization("CardContact");
//print(v.hasOrganization());
v.addTelephone(null, "0571");
v.addEmail("CardContact@CardContact.de");
v.addUrl("www.cardcontact.de");

print(v.getEncoded().toString(ASCII));