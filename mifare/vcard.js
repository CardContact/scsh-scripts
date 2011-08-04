function Vcard() {
	
}
//Identification
Vcard.prototype.setName = function(firstName, lastName) {
	this.n = "N:" + lastName + ";" + firstName + "\n";
}

Vcard.prototype.hasName = function() {
	return this.n != undefined;
}

Vcard.prototype.setFormattedName = function(fname) {
	this.fn = "FN:" + fname + "\n";
}
//funzt
Vcard.prototype.hasFormattedName = function() {
	return this.fn != undefined;
}

Vcard.prototype.setNickname = function(nick) {
	this.nickname = "NICKNAME:" + nick + "\n";
}

Vcard.prototype.hasNickname = function() {
	return this.nickname != undefined;
}

Vcard.prototype.setPhoto = function(photo) {
	this.photo = "PHOTO:" + photo + "\n";
}

Vcard.prototype.hasPhoto = function() {
	return this.phtoto != undefined;
}	

Vcard.prototype.setBirthday = function(bday) {
	this.bday = "BDAY:" + bday + "\n";
}	

Vcard.prototype.hasBirthday = function() {
	return this.bday != undefined;
}

Vcard.prototype.setOrganization = function(org) {
	this.org = "ORG:" + org + "\n";
}

Vcard.prototype.hasOrganization = function() {
	return this.org != undefined;
}

Vcard.prototype.setVersion = function(version) {
	this.version = "VERSION:" + version + "\n";
}

Vcard.prototype.hasVersion = function() {
	return this.version != undefined;
}

Vcard.prototype.addTelephone = function(type, tel) {
	if (type == null) {
		tel = "TEL:" + tel + "\n";
	}
	else {
		tel = "TEL;TYPE=" + type + ":" + tel + "\n";
	}
	if (this.tel == undefined) {
		this.tel = new ByteBuffer(tel, ASCII);
	}
	else {
		this.tel.append(tel);
	}
}

Vcard.prototype.hasTelephone = function() {
	return this.tel != undefined;
}


Vcard.prototype.addEmail = function(email) {
	email = "EMAIL;TYPE=internet:" + email + "\n";
	if (this.email == undefined) {
		this.email = new ByteBuffer(email, ASCII);
	}
	else {
		this.email.append(email, ASCII);
	}
}

Vcard.prototype.hasEmail = function() {
	return this.email != undefined;
}

Vcard.prototype.addAddress = function(street, city, postalCode, country) {
	this.adr = "ADR:;;" + street + city + ";;" + postalCode + country + "\n"; 
}

Vcard.prototype.hasAddress = function() {
	return this.adr != undefined;
}

Vcard.prototype.addUrl = function(url) {
	this.url = "URL:" + url + "\n";
}

Vcard.prototype.hasUrl = function() {
	return this.url != undefined;
}

Vcard.prototype.getEncoded = function() {
	//print("encode...");
	encoded = new ByteBuffer();
	encoded.append(new ByteString("BEGIN:VCARD\n", ASCII));
	if (this.hasName()) {
		encoded.append(this.n);		
	}
	if (this.hasFormattedName()) {
		encoded.append(this.fn);
	}
	if (this.hasNickname()) {
		encoded.append(this.nickname);
	}
	if (this.hasPhoto()) {
		encoded.append(this.photo);
	}
	if (this.hasBirthday()) {
		encoded.append(this.bday);
	}
	if (this.hasOrganization()) {
		encoded.append(this.org);
	}
	if (this.hasVersion()) {
		encoded.append(this.version);
	}
	if (this.hasTelephone()) {
		encoded.append(this.tel.toByteString());
	}
	if (this.hasEmail()) {
		encoded.append(this.email.toByteString());
	}
	if (this.hasAddress()) {
		encoded.append(this.adr);
	}
	if (this.hasUrl()) {
		encoded.append(this.url);
	}
	encoded.append(new ByteString("END:VCARD", ASCII));
	return encoded.toByteString();
}