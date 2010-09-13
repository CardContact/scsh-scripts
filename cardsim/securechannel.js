/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2009 CardContact Software & System Consulting
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
 * @fileoverview Implementation of a secure messaging channel as defined in ISO 7814-4 and eSign-K
 */



/**
 * Create a secure channel
 *
 * @class Class implementing a secure messaging channel
 * @constructor
 * @param {Crypto} crypto the crypto provider
 */
function SecureChannel(crypto) {
	this.crypto = crypto;
	this.policy = IsoSecureChannel.SSC_DEFAULT_POLICY;
}



/**
 * Sets the policy for handling send sequence counters
 *
 * See IsoSecureChannel for details
 *
 * @param {Number} policy one of IsoSecureChannel.SSC_DEFAULT_POLICY, SSC_SYNC_POLICY or SSC_SYNC_ENC_POLICY
 */
SecureChannel.prototype.setSendSequenceCounterPolicy = function(policy) {
	this.policy = policy;
}



/**
 * Sets the key used for encryption
 *
 * @param {Key} key the encryption key
 */
SecureChannel.prototype.setEncKey = function(key) {
	this.encKey = key;

	if (key.getComponent(Key.AES)) {
		this.encBlockSize = 16;
		this.encMechanism = Crypto.AES_CBC;
		this.iv = new ByteString("00000000000000000000000000000000", HEX);
	} else {
		this.encBlockSize = 8;
		this.encMechanism = Crypto.DES_CBC;
		this.iv = new ByteString("0000000000000000", HEX);
	}
}



/**
 * Sets the key used for message authentication
 *
 * @param {Key} key the message authentication key
 */
SecureChannel.prototype.setMacKey = function(key) {
	this.macKey = key;

	if (key.getComponent(Key.AES)) {
		this.macBlockSize = 16;
		this.macMechanism = Crypto.AES_CMAC;
	} else {
		this.macBlockSize = 8;
		this.macMechanism = Crypto.DES_MAC_EMV;
	}
}



/**
 * Set the send sequence counter for MAC calculation
 *
 * @param {ByteString} ssc the send sequence counter
 */
SecureChannel.prototype.setMACSendSequenceCounter = function(ssc) {
	this.macSendSequenceCounter = ssc;
}



/**
 * Set the send sequence counter for encryption calculation
 *
 * @param {ByteString} ssc the send sequence counter
 */
SecureChannel.prototype.setEncSendSequenceCounter = function(ssc) {
	this.encSendSequenceCounter = ssc;
}



/**
 * Return an initialisation vector based on the defined policy
 *
 * @type ByteString
 * @return the IV
 */
SecureChannel.prototype.getIV = function() {
	var iv = this.iv;
	if (this.policy == IsoSecureChannel.SSC_SYNC_ENC_POLICY) {
		iv = this.crypto.encrypt(this.encKey, this.encMechanism, this.macSendSequenceCounter, iv);
	} else if (this.policy == IsoSecureChannel.SSC_SYNC_POLICY) {
		iv = this.macSendSequenceCounter;
	} else {
		if (typeof(this.encSendSequenceCounter) != "undefined") {
			iv = this.encSendSequenceCounter
		}
	}
	return iv;
}



/**
 * Unwrap a secure messaging APDU recovering the content
 *
 * @param {APDU} apdu the APDU to unwrap
 */
SecureChannel.prototype.unwrap = function(apdu) {
	var decoder = new SecureMessagingCommandAPDUDecoder(this, apdu);
	if (!decoder.verifyMAC(this.macKey)) {
		throw new GPError("SecureChannel", GPError.CRYPTO_FAILED, APDU.SW_INCSMDATAOBJECT, "MAC verification failed");
	}
	var plain = decoder.decryptBody(this.encKey);
	apdu.setCData(plain);
}



/**
 * Wrap an APDU for secure messaging
 *
 * @param {APDU} apdu the APDU to wrap
 */
SecureChannel.prototype.wrap = function(apdu) {
	var rdata = new ByteBuffer();
	
	var macinp = new ByteBuffer();

	if (typeof(this.macSendSequenceCounter) != "undefined") {
		var ssc = this.macSendSequenceCounter.add(1);
		this.macSendSequenceCounter = ssc;
		macinp.append(ssc);
	}

	if (apdu.hasRData()) {
		var padbuff = new ByteBuffer(apdu.getRData());
		SecureChannel.pad(padbuff, this.encBlockSize);
		var iv = this.getIV();
		var cryptogram = this.crypto.encrypt(this.encKey, this.encMechanism, padbuff.toByteString(), iv);
		var padind = new ByteString("01", HEX);
		
		var do87 = new TLV(0x87, padind.concat(cryptogram), TLV.EMV);
		rdata.append(do87.getTLV());
	}
	
	rdata.append(0x99);
	rdata.append(2);
	rdata.append(apdu.getSW() >> 8);
	rdata.append(apdu.getSW() & 0xFF);
	
	macinp.append(rdata);
	
	SecureChannel.pad(macinp, this.macBlockSize);
	var mac = this.crypto.sign(this.macKey, this.macMechanism, macinp.toByteString());
	
	rdata.append(0x8E);
	rdata.append(0x08);
	rdata.append(mac.left(8));
	
	apdu.setRData(rdata.toByteString());
}



/**
 * Applies ISO padding to the input buffer
 *
 * @param {ByteBuffer} buffer the input buffer
 * @param {Number} blocksize the block size
 * @type ByteBuffer
 * @return the buffer argument
 */
SecureChannel.pad = function(buffer, blocksize) {
	buffer.append(0x80);
	while (buffer.length % blocksize) {
		buffer.append(0x00);
	}
	return buffer;
}



/**
 * Removes the ISO padding
 *
 * @param {ByteString} buffer the input with with padding
 * @type ByteString
 * @return the buffer without padding
 */
SecureChannel.removePadding = function(buffer) {
	var i = buffer.length - 1;
	
	while ((i >= 0) && (buffer.byteAt(i) == 0x00)) {
		i--;
	}
	
	if ((i < 0) || (buffer.byteAt(i) != 0x80)) {
		throw new GPError("SecureMessagingCommandAPDUDecoder", GPError.CRYPTO_FAILED, APDU.SW_INCSMDATAOBJECT, "Invalid ISO padding");
	}
	
	return buffer.left(i);
}



/**
 * Creates a decoder for a single secure messaging command APDU
 *
 * @class Decoder for a secure messaging APDU
 * @constructor
 * @param {SecureChannel} channel the secure channel object
 * @param {APDU} apdu the secure messaging APDU
 */
function SecureMessagingCommandAPDUDecoder(channel, apdu) {
	this.channel = channel;
	this.apdu = apdu;
	this.tlvlist = apdu.getCDataAsTLVList();
}



/**
 * Verify the message authentication code (MAC)
 *
 * @type boolean
 * @return true if the MAC is valid
 */
SecureMessagingCommandAPDUDecoder.prototype.verifyMAC = function() {
	var macinp = this.buildMACInput();
	
	var mac = this.tlvlist.find(0x8E);

	if (mac == null) {
		throw new GPError("SecureMessagingCommandAPDUDecoder", GPError.INVALID_DATA, APDU.SW_SMOBJMISSING, "MAC data object (8E) not found");
	}

	return this.channel.crypto.verify(this.channel.macKey, this.channel.macMechanism, macinp, mac.getValue());
}



/**
 * Build the MAC input block
 *
 * @type ByteString
 * @return the MAC calculation input block
 */
SecureMessagingCommandAPDUDecoder.prototype.buildMACInput = function() {
	var macinp = new ByteBuffer();
	
	if (typeof(this.channel.macSendSequenceCounter) != "undefined") {
		var ssc = this.channel.macSendSequenceCounter.add(1);
		this.channel.macSendSequenceCounter = ssc;
		macinp.append(ssc);
	}
	
	if (this.apdu.isAuthenticatedHeader()) {
		macinp.append(this.apdu.getCLA());
		macinp.append(this.apdu.getINS());
		macinp.append(this.apdu.getP1());
		macinp.append(this.apdu.getP2());
		SecureChannel.pad(macinp, this.channel.macBlockSize);
	}

	var someadded = false;
	for (var i = 0; i < this.tlvlist.length; i++) {
		var tlv = this.tlvlist.index(i);
		
		if (tlv.getTag() & 0x01) {
			macinp.append(tlv.getTLV());
			someadded = true;
		}
	}
	if (someadded) {
		SecureChannel.pad(macinp, this.channel.macBlockSize);
	}
	return macinp.toByteString();
}



/**
 * Decrypt the body of a secure messaging APDU
 *
 * @param {Key} key the encryption key
 * @type ByteString
 * @return the plain body
 */
SecureMessagingCommandAPDUDecoder.prototype.decryptBody = function(key) {
	var body = this.tlvlist.find(0x87);
	var ofs = 1;
	if (body == null) {
		var body = this.tlvlist.find(0x85);
		if (body == null) {
			return null;
		}
		var ofs = 0;
	} else {
		var paddingIndicator = body.getValue().byteAt(0);
		if (paddingIndicator != 0x01) {
			throw new GPError("SecureMessagingCommandAPDUDecoder", GPError.INVALID_DATA, APDU.SW_INCSMDATAOBJECT, "Padding indicator " + paddingIndicator + " not supported");
		}
	}
	
	var cryptogram = body.getValue().bytes(ofs);
	
	var iv = this.channel.getIV();
	var plain = this.channel.crypto.decrypt(this.channel.encKey, this.channel.encMechanism, cryptogram, iv);
	
	plain = SecureChannel.removePadding(plain);
	
	return plain;
}
