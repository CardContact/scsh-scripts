load("vcard.js");
load("test.js");

var v = new Vcard();

v.setFormattedName("Max Mustermann");
//print(v.hasFormattedName());
v.setOrganization("CardContact");
//print(v.hasOrganization());
v.addTelephone(null, "0571");
v.addEmail("CardContact@CardContact.de");
v.addUrl("www.cardcontact.de");

print(v.getEncoded().toString(ASCII));

//var loader = new LoadIntoMifare(new ByteString("D1010D55016F70656E736364702E6F7267FE", HEX));
var loader = new Loader();
//loader.initialize();
loader.load(new ByteString("424547494E3A56434152440A464E3A4D6178204D75737465726D616E6E0A4F52473A43617264436F6E746163740A54454C3A303537310A454D41494C3B545950453D696E7465726E65743A43617264436F6E746163744043617264436F6E746163742E64650A55524C3A7777772E63617264636F6E746163742E64650A454E443A5643415244", HEX));

