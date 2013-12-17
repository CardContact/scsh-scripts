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
 * @fileoverview Script classes to access Mifare DESFire cards
 */



/**
 * Create a DESFire card object
 * @class Class encapsulating access to a Mifare DESFire EV1 card
 * @constructor 
 * @param {card} card the card object
 */
function DESFire(card) {
	this.card = card;
	this.crypto = new Crypto();
	
	var fci = card.sendApdu(0x00, 0xA4, 0x04, 0x00, DESFire.AID, 0, [0x9000]);
	
	this.key = new Key();
	this.key.setComponent(Key.DES, new ByteString("01010101010101010101010101010101", HEX));
}

DESFire.AID = new ByteString("D2760000850100", HEX);

DESFire.AUTHENTICATE = 0x0A;
DESFire.AUTHENTICATE_ISO = 0x1A;
DESFire.AUTHENTICATE_AES = 0xAA;

DESFire.AUTHENTICATE = 0x0A;
DESFire.GET_VERSION = 0x60;
DESFire.NEXT_FRAME = 0xAF;



DESFire.prototype.cmd = function(cmd, data) {

	if (typeof(data) != "undefined") {
		var rsp = this.card.sendApdu(0x90, cmd, 0x00, 0x00, data, 0);
	} else {
		var rsp = this.card.sendApdu(0x90, cmd, 0x00, 0x00, 0);
	}

	if (this.card.SW == 0x91AF) {
		var rsp = [ rsp ];
		
		while (this.card.SW == 0x91AF) {
			rsp.push(this.card.sendApdu(0x90, DESFire.NEXT_FRAME, 0x00, 0x00, 0));
		}
	}
	return rsp;
}



DESFire.prototype.authenticate = function() {

	var rnd_ifd = this.crypto.generateRandom(8);
	var rnd_icc = this.card.sendApdu(0x00, 0x84, 0x00, 0x00, 8);
	
	var plain = rnd_ifd.concat(rnd_icc);
	var cryptogram = this.crypto.encrypt(this.key, Crypto.DES_CBC, plain);
	
	var rnd_icc = this.card.sendApdu(0x00, 0x82, 0x09, 0x00, cryptogram, 0);

}



DESFire.prototype.nativeAuthenticate = function(cmd, keyid) {

	var dfc = new DESFireCipher(this.crypto, this.key, Crypto.DES);

	var enc_rnd_icc = this.card.sendApdu(0x90, cmd, 0x00, 0x00, ByteString.valueOf(keyid), 0, [0x91AF, 0x9000] );

	dfc.resetIV();
	var rnd_icc = dfc.decryptReceived(enc_rnd_icc);

//	print("rnd_icc  : " + rnd_icc);

	rnd_icc = rnd_icc.bytes(1).concat(rnd_icc.bytes(0, 1));
//	print("rnd_icc' : " + rnd_icc);

	var rnd_ifd = this.crypto.generateRandom(8);
//	print("rnd_ifd  : " + rnd_ifd);
	
	if (cmd == DESFire.AUTHENTICATE) {
		dfc.resetIV();
		var enc_ifd = dfc.decryptSend(rnd_ifd.concat(rnd_icc));
		dfc.resetIV();
	} else {
		var enc_ifd = dfc.encryptSend(rnd_ifd.concat(rnd_icc));
	}

	var encicc = this.cmd(DESFire.NEXT_FRAME, enc_ifd);
	if ((this.card.SW != 0x9100) && (this.card.SW != 0x9000)) {
		GPSystem.trace("Authentication failed, cryptogram not accepted by card");
		return false;
	}
	
	var plain = dfc.decryptReceived(encicc);
//	print("rnd_ifd' : " + plain);

	var rnd_ifd2 = plain.bytes(7).concat(plain.bytes(0, 7));
	return rnd_ifd.equals(rnd_ifd2);
}



DESFire.prototype.dump = function() {
	var rsp = this.cmd(DESFire.GET_VERSION);
	
	for (var i = 0; i < rsp.length; i++) {
		print(rsp[i]);
	}
	// Get Mode
//	var mode = this.card.sendApdu(0x90, 0x60, 0x00, 0x00, 0);
}



function DESFireCipher(crypto, key, algorithm, iv) {
	this.crypto = crypto;
	this.key = key;
	this.algorithm = algorithm;
	if (typeof(iv) == "undefined") {
		this.iv = new ByteString("0000000000000000", HEX);
	} else {
		this.iv = iv;
	}
}



DESFireCipher.prototype.isAES = function() {
	return this.algorithm == Crypto.AES;
}



DESFireCipher.prototype.resetIV = function(iv) {
	if (typeof(iv) == "undefined") {
		this.iv = new ByteString("0000000000000000", HEX);
	} else {
		this.iv = iv;
	}
}



DESFireCipher.prototype.encryptSend = function(plain) {
	if (this.isAES()) {
		var cipher = this.crypto.encrypt(this.key, Crypto.AES_CBC, plain, this.iv);
		this.iv = cipher.right(16);
	} else {
		var cipher = this.crypto.encrypt(this.key, Crypto.DES_CBC, plain, this.iv);
		this.iv = cipher.right(8);
	}
	return cipher;
}



DESFireCipher.prototype.decryptReceived = function(cipher) {
	if (this.isAES()) {
		var plain = this.crypto.decrypt(this.key, Crypto.AES_CBC, cipher, this.iv);
		this.iv = cipher.right(16);
	} else {
		var plain = this.crypto.decrypt(this.key, Crypto.DES_CBC, cipher, this.iv);
		this.iv = cipher.right(8);
	}
	return plain;
}



DESFireCipher.prototype.decryptSend = function(cipher) {
	var blksize = this.isAES() ? 16 : 8;
	var obuf = new ByteBuffer();

	for (var ofs = 0; ofs < cipher.length; ofs += blksize) {
		var blk = cipher.bytes(ofs, blksize);

		blk = blk.xor(this.iv);

		plain = this.crypto.decrypt(this.key, this.isAES() ? Crypto.AES_ECB : Crypto.DES_ECB, blk);

		this.iv = plain;
		obuf.append(plain);
	}
	return obuf.toByteString();
}



DESFireCipher.prototype.encryptReceived = function(plain) {
	var blksize = this.isAES() ? 16 : 8;
	var obuf = new ByteBuffer();

	for (var ofs = 0; ofs < plain.length; ofs += blksize) {
		var blk = plain.bytes(ofs, blksize);

		plain = this.crypto.encrypt(this.key, this.isAES() ? Crypto.AES_ECB : Crypto.DES_ECB, blk);

		plain = plain.xor(this.iv);

		this.iv = blk;
		obuf.append(plain);
	}
	return obuf.toByteString();
}



var card = new Card(_scsh3.reader);

card.reset(Card.RESET_COLD);

var desfire = new DESFire(card);

desfire.dump();

desfire.cmd(0x45);
desfire.cmd(0x6A);
desfire.cmd(0x6F);

var result = desfire.nativeAuthenticate(DESFire.AUTHENTICATE, 0);

print("Authentication " + (result ? "OK" : "FAILED"));

