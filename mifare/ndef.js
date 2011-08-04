function Ndef(encoded) {
	if (typeof(encoded) != "undefined") {
		this.decode(encoded);
	} else {
		this.typeLength = 0;
		this.flags = Ndef.messageBegin | Ndef.messageEnd | Ndef.shortRecord | 1;
		this.id = null;
	}
}

//Flags 
Ndef.messageBegin = 0x80;
Ndef.messageEnd = 0x40;
Ndef.chunkFlag = 0x20;
Ndef.shortRecord = 0x10;
Ndef.idLengthFlag = 0x08; //IL
Ndef.tnf = 0x07;


//Uri Identifier Abbrevations
Ndef.uriIdentifier = new Array(null, "http://www.", "https://www.", "http://", "https://", "tel:", "mailto:", "ftp://anonymous:anonymous@", "ftp://ftp.", "ftps://", "sftp://", "smb://", "nfs://", "ftp://", "dav://", "news:", "telnet://", "imap:", "rtsp://", "urn:", "pop", "sip:", "sips:", "tftp:", "btspp://", "btl2cap://", "btgoep://", "tcpobex://", "irdaobex://", "file://", "urn:epc:id:", "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:", "urn:epc:", "urn:nfc:");

/* Ndef.prototype.decode = function(encoded) {
	this.flags = encoded.byteAt(0);
	
	Ndef.messageBegin = this.flags & 0x80;
	Ndef.messageEnd = this.flags & 0x40;
	Ndef.chunkFlag = this.flags & 0x20;
	Ndef.shortRecord = this.flags & 0x10;
	Ndef.idLengthFlag = this.flags & 0x08;
	Ndef.tnf = this.flags & 0x07;
	
	this.typeLength = encoded.byteAt(1);
	if (Ndef.shortRecord == 0x10) {
		this.payloadLength = encoded.byteAt(2);
		if (Ndef.idLengthFlag == 0x08) {
			this.idLength = encoded.byteAt(3);
			this.type = encoded.bytes(4, this.typeLength);
			this.id = encoded.byteAt(4 + this.typeLength, this.idLength);			
			this.payload = encoded.bytes(4 + this.typeLength + this.idLength);				
		}
		else {
			this.type = encoded.bytes(3, this.typeLength);
			this.payload = encoded.bytes(3 + this.typeLength);
		}
	}
	else {
		this.payloadLength = encoded.bytes(2, 4);
		if (Ndef.idLengthFlag == 0x08) {
			this.idLength = encoded.byteAt(6);
			this.type = encoded.bytes(7, this.typeLength);
			this.id = encoded.byteAt(7 + this.typeLength, this.idLength);			
			this.payload = encoded.bytes(7 + this.typeLength + this.idLength);				
		}
		else {
			this.type = encoded.bytes(6, this.typeLength);
			this.payload = encoded.bytes(6 + this.typeLength);
		}		
	}
}
 */
 
/**
 *	Create Ndef object
 *	@param {ByteString} encoded the encoded Ndef ByteString
 */
Ndef.prototype.decode = function(encoded) {
	 // print("encoded:");
	 // print(encoded);
	
	this.flags = encoded.byteAt(0);
	this.typeLength = encoded.byteAt(1);
	var ofs = 2;
	
	if (this.isShortRecord()) {
		this.payloadLength = encoded.byteAt(ofs++);
	} else {
		this.payloadLength = encoded.bytes(ofs, 4).toUnsigned();
		ofs += 4;
	}
	
	if (this.isIdLengthFlag()) {
		this.idLength = encoded.byteAt(ofs++);
	}

	this.type = encoded.bytes(ofs, this.typeLength);
	ofs += this.typeLength;
	
	if (this.isIdLengthFlag()) {
		this.id = encoded.bytes(ofs, this.idLength);
		ofs += this.idLength;
	}

	this.payload = encoded.bytes(ofs, this.payloadLength);
	ofs += this.payloadLength;
	
	if (this.isChunked()) {
		var nextRecord = new Ndef(encoded.bytes(ofs));
		this.payload += nextRecord.getPayload();
	}

/*			
	if (this.isShortRecord()) {
		//print("is Short Record");
		this.payloadLength = encoded.byteAt(2);
		if (this.isIdLengthFlag()) {
			//print("IL");
			this.idLength = encoded.byteAt(3);
			this.type = encoded.bytes(4, this.typeLength);
			this.id = encoded.bytes(4 + this.typeLength, this.idLength);			
			this.payload = encoded.bytes(4 + this.typeLength + this.idLength, this.payloadLength);
			if(this.isChunked()) {
				var nextRecord = new Ndef(encoded.bytes(4 + this.typeLength + this.payloadLength));
				this.payload += nextRecord.getPayload();
			}
		}
		else {
			//print("IL: false");
			this.type = encoded.bytes(3, this.typeLength);
			this.payload = encoded.bytes(3 + this.typeLength, this.payloadLength);
			if (this.isChunked()) {
				//print("isChunked");
				var nextRecord = new Ndef(encoded.bytes(3 + this.typeLength + this.payloadLength));
				this.payload += nextRecord.getPayload();
			}
		}
	}
	else {
		this.payloadLength = encoded.bytes(2, 4).toUnsigned();
		if (this.isIdLengthFlag()) {
			this.idLength = encoded.byteAt(6);
			this.type = encoded.bytes(7, this.typeLength);
			this.id = encoded.bytes(7 + this.typeLength, this.idLength);			
			this.payload = encoded.bytes(7 + this.typeLength + this.idLength, this.payloadLength);				
			if(this.isChunked()) {
				var nextRecord = new Ndef(encoded.bytes(7 + this.typeLength + this.payloadLength));
				this.payload += nextRecord.getPayload();
			}
		}
		else {
			this.type = encoded.bytes(6, this.typeLength);
			this.payload = encoded.bytes(6 + this.typeLength, this.payloadLength);
			if(this.isChunked()) {
				var nextRecord = new Ndef(encoded.bytes(6 + this.typeLength + this.payloadLength));
				this.payload += nextRecord.getPayload();
			}
		}		
	}
*/
	this.setMessageBegin(true);
	this.setMessageEnd(true);
	this.setChunked(false);
	this.payloadLength == this.payload.length;
}



Ndef.prototype.getPayload = function() {
	return new ByteString(this.payload, HEX);
}



Ndef.prototype.getUri = function() {
	//type must be "U" 
	var payload = new ByteString(this.payload, HEX);
	
	if (this.type == 55) {
		var i = payload.byteAt(0);
		var str = "";
		if (i > 0) {
			str += Ndef.uriIdentifier[i];
		}
		str += payload.bytes(1).toString(UTF8);
		
		return str;
	}
}



Ndef.prototype.isMessageBegin = function() {
	return (this.flags & Ndef.messageBegin) == 0x80;
}

Ndef.prototype.setMessageBegin = function(state) {
	this.flags = this.flags & ~Ndef.messageBegin | (state ? Ndef.messageBegin : 0);
	return this.flags & Ndef.messageBegin;
}

Ndef.prototype.isMessageEnd = function(state) {
	return (this.flags & Ndef.messageBegin) == 0x40;
}

Ndef.prototype.setMessageEnd = function(state) {
	this.flags = this.flags & ~Ndef.messageEnd | (state ? Ndef.messageEnd : 0);
	return this.flags & Ndef.messageBegin;
}

Ndef.prototype.isChunked = function() {
	return (this.flags & Ndef.chunkFlag) == 0x20;
}

Ndef.prototype.setChunked = function(state) {
	this.flags = this.flags & ~Ndef.chunkFlag | (state ? Ndef.chunkFlag : 0);
	return this.flags & Ndef.chunkFlag;
}

Ndef.prototype.isShortRecord = function() {
	return (this.flags & Ndef.shortRecord) == 0x10;
}

Ndef.prototype.setShortRecord = function(state) {
	this.flags = this.flags & ~Ndef.shortRecord | (state ? Ndef.shortRecord : 0);
	return this.flags & Ndef.shortRecord;
}

Ndef.prototype.isIdLengthFlag = function() {
	return (this.flags & Ndef.idLengthFlag) == 0x08;
}

Ndef.prototype.setIdLengthFlag = function(state) {
	this.flags = this.flags & ~Ndef.idLengthFlag | (state ? Ndef.idLengthFlag : 0);
	return this.flags & Ndef.idLengthFlag;
}

Ndef.prototype.setTNF = function(tnf) {
	if (tnf <= 7 && tnf >= 0) {
		this.flags = this.flags & ~Ndef.tnf | tnf;
	}
}

Ndef.prototype.getTNF = function() {
	return this.flags & Ndef.tnf;
}




/**
 *	Search for possible abbrevation in String and return the corresponding Uri Identifier
 *	@param {String} str the message coded in UTF-8
 *	@return {ByteString} the payload consisting of the Uri Identifier and the shortened string
 */
Ndef.shortenString = function(str) {
	for(var i = 1; i <= Ndef.uriIdentifier.length; i++) {
		
		var containsUriID = str.indexOf(Ndef.uriIdentifier[i])
		if(containsUriID != -1) {
			str = new ByteString(str.substring(Ndef.uriIdentifier[i].length), UTF8);
			var payload = ByteString.valueOf(i);
			return payload.concat(str);			
		}		
	}
	var payload = new ByteString("0x00", HEX).concat(new ByteString(str, UTF8));
	return payload;	
}


/**
 *	Create a new Uri from string
 *	@param {String} str 
 *	@return {Ndef} the Ndef object
 */
Ndef.newUri = function(str) {
	var n = new Ndef();
	var payload = Ndef.shortenString(str);
	
	n.typeLength = ByteString.valueOf(1);
	n.payloadLength = new ByteString(payload.length, HEX);
	n.type = new ByteString("U", UTF8);
	n.payload = payload;
	
	if (n.payloadLength > 255) {
		n.setShortRecord(false);
	}
	
	
	return n;
}

Ndef.newMessage = function(type, payload) {
	var n = new Ndef();
	n.typeLength = new ByteString(type.length, HEX);
	n.payloadLength = payload.length;
	n.type = type;
	n.payload = payload;
	
	//TODO...
	//n.setTNF();
	
	if (n.payloadLength > 255) {
		n.setShortRecord(false);
	}
	
	
	return n;
}

/**
 *	Return the Ndef in encoded format
 *	@return {ByteString} encoded Ndef
 */
Ndef.prototype.getEncoded = function() {
	var buffer = new ByteBuffer();
	var flagByte = new ByteString(ByteString.valueOf(this.flags), HEX);
	
	this.flags = (this.flags & ~Ndef.idLengthFlag) | (this.id ? Ndef.idLengthFlag : 0);

	buffer.append(flagByte);
	buffer.append(this.type.length);
	buffer.append(this.payload.length);
	if (this.id) {
		buffer.append(this.id.length);
	}
	buffer.append(this.type);
	if (this.id) {
		buffer.append(this.id);
	}
	buffer.append(this.payload);
	
	//print(buffer.toByteString());
	return buffer.toByteString();
}

/* Ndef.prototype.toString = function() {
	var str = "MB:" + this.flags & Ndef.messageBegin + " ,ME:" + this.flags & Ndef.messageEnd + " ,CF:" + this.flags & Ndef.chunkFlag + " ,SR:" + this.flag & Ndef.shortRecord + " ,IL:" + this.flag & Ndef.idLengthFlag + " ,TNF:" + this.flag & Ndef.tnf;
	str += ",uri=";
	var payload = new ByteString(this.payload, HEX);
	var i = payload.byteAt(0);
	if (i > 0) {
		str += Ndef.uriIdentifier[i];
	}
	str += payload.bytes(1).toString(UTF8);
	
	return str;
} */


Ndef.prototype.toString = function() {
	var str = "flag=" + this.flags.toString(HEX);
	str += ",uri=";
	var payload = new ByteString(this.payload, HEX);
	var i = payload.byteAt(0);
	if (i > 0) {
		str += Ndef.uriIdentifier[i];
	}
	str += payload.bytes(1).toString(UTF8);
	
	return str;
}
