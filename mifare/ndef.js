/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2011 CardContact Software & System Consulting
 * |'##> <##'|  Andreas Schwier, 32429 Minden, Germany (www.cardcontact.de)
 *  --------- 
 *
 *  This file is part of OpenSCDP.
 *
 *  OpenSCDP is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  OpenSCDP is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with OpenSCDP; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * @fileoverview Create or decode NDEF messages
 */

function Ndef(encoded) {
	if (typeof(encoded) != "undefined") {
		this.decode(encoded);
	} else {
		this.typeLength = 0;
		this.flags = Ndef.messageBegin | Ndef.messageEnd | Ndef.shortRecord | 1;
		this.id = null;
	}
}

//Flag Byte Constants
Ndef.messageBegin = 0x80;
Ndef.messageEnd = 0x40;
Ndef.chunkFlag = 0x20;
Ndef.shortRecord = 0x10;
Ndef.idLengthFlag = 0x08; //IL
Ndef.tnf = 0x07;


//Uri Identifier Abbrevations
Ndef.uriIdentifier = new Array(null, "http://www.", "https://www.", "http://", "https://", "tel:", "mailto:", "ftp://anonymous:anonymous@", "ftp://ftp.", "ftps://", "sftp://", "smb://", "nfs://", "ftp://", "dav://", "news:", "telnet://", "imap:", "rtsp://", "urn:", "pop", "sip:", "sips:", "tftp:", "btspp://", "btl2cap://", "btgoep://", "tcpobex://", "irdaobex://", "file://", "urn:epc:id:", "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:", "urn:epc:", "urn:nfc:");
 
/**
 *	Create Ndef object
 *	@param {ByteString} encoded the encoded Ndef ByteString
 */
Ndef.prototype.decode = function(encoded) {
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

	this.setMessageBegin(true);
	this.setMessageEnd(true);
	this.setChunked(false);
	this.payloadLength == this.payload.length;
}


/**
 *	Return the payload of the NDEF object.
 *	@return {ByteString} the payload
 */
Ndef.prototype.getPayload = function() {
	return new ByteString(this.payload, HEX);
}


/**
 *	Return the decoded URI in readable form.
 *	@return {String} the UTF-8 decoded URI
 */
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


/**
 *	Check if the Message Begin flag is set. The flag indicates the start of an NDEF message. 
 *	@return {Boolean}
 */
Ndef.prototype.isMessageBegin = function() {
	return (this.flags & Ndef.messageBegin) == 0x80;
}


/**
 *	Set the Message Begin flag. The flag indicates the start of an NDEF message.
 *	@param {Boolean} state
 */
Ndef.prototype.setMessageBegin = function(state) {
	this.flags = this.flags & ~Ndef.messageBegin | (state ? Ndef.messageBegin : 0);
	return this.flags & Ndef.messageBegin;
}


/**
 *	Check if the Message End flag is set. The flag indicates the end of an NDEF message.
 *	@return {Boolean}
 */
Ndef.prototype.isMessageEnd = function(state) {
	return (this.flags & Ndef.messageBegin) == 0x40;
}


/**
 *	Set the Message End flag. The flag indicates the end of an NDEF message.
 *	@param {Boolean} state
 */
Ndef.prototype.setMessageEnd = function(state) {
	this.flags = this.flags & ~Ndef.messageEnd | (state ? Ndef.messageEnd : 0);
	return this.flags & Ndef.messageBegin;
}


/**
 *	Check if the Chunk flag is set. 
 *	The flag indicates that this is either the first or the middle record chunk of a chunked payload.
 *	@return {Boolean}
 */
Ndef.prototype.isChunked = function() {
	return (this.flags & Ndef.chunkFlag) == 0x20;
}


/**
 *	Set the Chunk flag.
 *	The flag indicates that this is either the first or the middle record chunk of a chunked payload.
 *	@param {Boolean} state
 */
Ndef.prototype.setChunked = function(state) {
	this.flags = this.flags & ~Ndef.chunkFlag | (state ? Ndef.chunkFlag : 0);
	return this.flags & Ndef.chunkFlag;
}


/**
 *	Check if the Short Record flag is set.
 *	The flag indicates that the payload size will range between 0 to 255 octets.
 *	@return {Boolean}
 */
Ndef.prototype.isShortRecord = function() {
	return (this.flags & Ndef.shortRecord) == 0x10;
}


/**
 *	Set the Short Record flag.
 *	The flag indicates that the payload size will range between 0 to 255 octets.
 *	@param {Boolean} state
 */
Ndef.prototype.setShortRecord = function(state) {
	this.flags = this.flags & ~Ndef.shortRecord | (state ? Ndef.shortRecord : 0);
	return this.flags & Ndef.shortRecord;
}


/**
 *	Check if the ID Length flag is set.
 *	The flag indicates that the ID Length field and the ID field are present. Otherwise the both are omitted from the record.
 *	@return {Boolean}
 */
Ndef.prototype.isIdLengthFlag = function() {
	return (this.flags & Ndef.idLengthFlag) == 0x08;
}


/**
 *	Set the ID Length flag.
 *	The flag indicates that the ID Length field and the ID field are present. Otherwise the both are omitted from the record.
 *	@param {Boolean} state
 */
Ndef.prototype.setIdLengthFlag = function(state) {
	this.flags = this.flags & ~Ndef.idLengthFlag | (state ? Ndef.idLengthFlag : 0);
	return this.flags & Ndef.idLengthFlag;
}


/**
 *	Set the TNF (Type Name Format) flag.
 *	The flag indicates the structure of the type value.
 *	
 *	0x00 = Empty
 *	0x01 = NFC Forum well-known type
 *	0x02 = Media-type as defined in RFC 2046
 *	0x03 = Absolute URI as defined in RFC 3986
 *	0x04 = NFC Forum external type
 *	0x05 = Unknown
 *	0x06 = Unchanged
 *	0x07 = Reserved
 *
 *	@param {Boolean} state
 */
Ndef.prototype.setTNF = function(tnf) {
	if (tnf <= 7 && tnf >= 0) {
		this.flags = this.flags & ~Ndef.tnf | tnf;
	}
}


/**
 *	Return the TNF flag
 *	The flag indicates the structure of the type value.
 *	
 *	0x00 = Empty
 *	0x01 = NFC Forum well-known type
 *	0x02 = Media-type as defined in RFC 2046
 *	0x03 = Absolute URI as defined in RFC 3986
 *	0x04 = NFC Forum external type
 *	0x05 = Unknown
 *	0x06 = Unchanged
 *	0x07 = Reserved
 *
 
 *	@return {ByteString} the TNF
 */
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
 *	@return {NDEF} the NDEF object
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


/**
 *	Create a new NDEF Message
 *	@param {String} type The type of the NDEF Message coded in US-ASCII. 
 *	@param {ByteString} payload
 */
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


/**
 *	@return {String} str A String containing the flag byte and the uri payload.
 */
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
