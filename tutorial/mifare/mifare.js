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
 * @fileoverview Script classes to access Mifare cards
 */



/**
 * Create a Mifare card object
 * @class Class encapsulating access to a Mifare classic 1K/4K card
 * @constructor 
 * @param {card} card the card object
 */
function Mifare(card) {
	this.card = card;
}


/**
 * Identifier for Key A
 */
Mifare.KEY_A = 0x60;

/**
 * Identifier for Key B
 */
Mifare.KEY_B = 0x61;


/**
 * Read UID using Get Data command as defined in PCSC Part 3, chapter 3.2.2.1.3
 *
 * @type ByteString
 * @return the 4 byte UID
 */
Mifare.prototype.getUID = function() {
	return this.card.sendApdu(0xFF, 0xCA, 0x00, 0x00, 0, [0x9000]);
}



/**
 * Load key value into reader using Load Key command as defined in PCSC Part 3, chapter 3.2.2.1.4
 *
 * @param {Number} keyid the key identifier under which the key should be refered to in the reader
 * @param {ByteString} key the 6 byte key value
 */
Mifare.prototype.loadKey = function(keyid, key) {
	assert(typeof(keyid) == "number");
	assert(key.length == 6);
	
	this.card.sendApdu(0xFF, 0x82, 0x20,keyid, key, [0x9000]);
}



/**
 * Read a block using the Read Binary command as defined in PCSC Part 3, chapter 3.2.2.1.8
 *
 * @param {Number} block the block to read, starting at 0 for the first block in the first sector.
 * @type ByteString
 * @return the 16 byte block content read from the card
 */
Mifare.prototype.readBlock = function(block) {
	return this.card.sendApdu(0xFF, 0xB0, block >> 8, block & 0xFF, 0, [0x9000]);
}



/**
 * Update a block using the Update Binary command as defined in PCSC Part 3, chapter 3.2.2.1.9
 *
 * @param {Number} block the block to read, starting at 0 for the first block in the first sector.
 * @param {ByteString} data the 16 bytes of the data block to write
 */
Mifare.prototype.updateBlock = function(block, data) {
	assert(data.length == 16);
	return this.card.sendApdu(0xFF, 0xD6, block >> 8, block & 0xFF, data, [0x9000]);
}



/**
 * Perform authentication procedure using General Authenticate command as defined in PCSC Part 3, chapter 3.2.2.1.6
 *
 * @param {Number} block the block to authenticate against
 * @param {Number} keytype must be either Mifare.KEY_A or Mifare.KEY_B
 * @param {Number} keyid the key id of the key in the reader
 */
Mifare.prototype.authenticate = function(block, keytype, keyid) {
	var bb = new ByteBuffer();
	bb.append(0x01);							// Version
	bb.append(ByteString.valueOf(block, 2));
	bb.append(keytype);
	bb.append(keyid);
	this.card.sendApdu(0xFF,0x86,0x00,0x00, bb.toByteString(), [0x9000]);
}



/**
 * Create a sector object bound to the current Mifare instance
 *
 * @param {Number} no the sector number
 */
Mifare.prototype.newSector = function(no) {
	return new Sector(this, no);
}



/**
 * Create an object representing an on card sector. Do not call directly but use Mifare.prototype.newSector() instead,
 * @class Class representing a sector on a Mifare card
 * @constructor
 * @param {Mifare} mifare the card
 * @param {Number} no the sector number
 */
function Sector(mifare, no) {
	this.mifare = mifare;
	this.no = no;
	this.blocks = [];
	this.keyid = no << 1;
}


Sector.MASK = [ 0x00E0EE, 0x00D0DD, 0x00B0BB, 0x007077 ];
Sector.AC_TRAILER = [
	"Key A: Write Key A | AC: Write Never | Key B: Read Key A / Write Key A",		// 000
	"Key A: Write Key A | AC: Write Key A | Key B: Read Key A / Write Key A",		// 001
	"Key A: Write Never | AC: Write Never | Key B: Read Key A / Write Never",		// 010
	"Key A: Write Key B | AC: Write Key B | Key B: Never      / Write Key B",		// 011
	"Key A: Write Key B | AC: Write Never | Key B: Never      / Write Key B",		// 100
	"Key A: Write Never | AC: Write Key B | Key B: Never      / Write Never",		// 101
	"Key A: Write Never | AC: Write Never | Key B: Never      / Write Never",		// 110
	"Key A: Write Never | AC: Write Never | Key B: Never      / Write Never",		// 111
	];

Sector.AC_FIXED_AC_NOKEY_B = 0;
Sector.AC_UPDATE_AC_NOKEY_B = 1;
Sector.AC_READONLY_NOKEY_B = 2;
Sector.AC_UPDATE_WITH_KEYB = 3;
Sector.AC_FIXED_AC_UPDATE_WITH_KEYB = 4;
Sector.AC_UPDATE_AC_FIXED_KEYS = 5;
Sector.AC_NEVER2 = 6;

Sector.AC_DATA = [
	"Read: Key AB | Write: Key AB | Inc: Key AB | Dec: Key AB",		// 000
	"Read: Key AB | Write: Never  | Inc: Never  | Dec: Key AB",		// 001
	"Read: Key AB | Write: Never  | Inc: Never  | Dec: Never ",		// 010
	"Read: Key B  | Write: Key B  | Inc: Never  | Dec: Never ",		// 011
	"Read: Key AB | Write: Key B  | Inc: Never  | Dec: Never ",		// 100
	"Read: Key B  | Write: Never  | Inc: Never  | Dec: Never ",		// 101
	"Read: Key AB | Write: Key B  | Inc: Key B  | Dec: Key AB",		// 110
	"Read: Never  | Write: Never  | Inc: Never  | Dec: Never ",		// 111
	];

Sector.AC_ALWAYS = 0;					// All conditions with Key A or Key B
Sector.AC_NONRECHARGEABLE = 1;			// Only decrement on read only application
Sector.AC_READONLY = 2;					// Read only application
Sector.AC_KEYBONLY = 3;					// Only using Key B
Sector.AC_UPDATEKEYB = 4;				// Use Key B to update
Sector.AC_KEYBREADONLY = 5;				// Read only application with only Key B
Sector.AC_RECHARGEABLE = 6;				// Rechargable counter
Sector.AC_NEVER  = 7;					// No access at all



/**
 * Overwrite internal key id
 * <p>The key id for sectors is preset with twice the sector number</p>
 * @param {Number} keyId the key id for Key A. Key B is the id of Key A + 1
 */
Sector.prototype.setKeyId = function(keyId) {
	this.keyid = keyid;
}



/**
 * Read a block within the sector
 *
 * @param {Number} block the block number between 0 and 3
 * @type ByteString
 * @return the data read from the block
 */
Sector.prototype.read = function(block) {
	assert(block >= 0);
	assert(block <= 3);
	var blockoffs = (this.no << 2) + block;
	this.blocks[block] = this.mifare.readBlock(blockoffs);
	return this.blocks[block];
}



/**
 * Update a block within the sector
 *
 * @param {Number} block the block number between 0 and 3
 * @param {ByteString} data the data to write (Optional for sector trailer)
 */
Sector.prototype.update = function(block, data) {
	if (typeof(data) == "undefined") {
		data = this.blocks[block];
	} else {
		this.blocks[block] = data
	}
	var blockoffs = (this.no << 2) + block;
	this.mifare.updateBlock(blockoffs, data);
}



/**
 * Authenticate against block
 * <p>Uses the internal key id for this sector for key A and the internal key id + 1 for key B.</p>
 * @param {Number} block the block number between 0 and 3
 * @param {Number} keytype must be either Mifare.KEY_A or Mifare.KEY_B
 */
Sector.prototype.authenticate = function(block, keytype) {
	this.mifare.authenticate((this.no << 2) + block, keytype, this.keyid + (keytype - Mifare.KEY_A));
}



/**
 * Read all blocks from a sector
 */
Sector.prototype.readAll = function() {
	var bb = new ByteBuffer();
	this.authenticate(0, Mifare.KEY_A);
	for (var i = 0; i < 4; i++) {
		bb.append(this.read(i));
	}
	return bb.toByteString();
}



/**
 * Return access conditions for a block within the sector
 *
 * @param {Number} block the block number between 0 and 3
 * @type Number
 * @return one of the Sector.AC_ constants
 */
Sector.prototype.getACforBlock = function(block) {
	var c = this.blocks[3].bytes(6, 3).toUnsigned();
	return ((((c >> (12 + block)) & 0x01) << 2) +
			(((c >> ( 0 + block)) & 0x01) << 1) +
			((c >> (4  + block)) & 0x01));
}



/**
 * Set the access condition for a block within the sector
 *
 * @param {Number} block the block number between 0 and 3
 * @param {Number} ac one of the Sector.AC_ constants
 */
Sector.prototype.setACforBlock = function(block, ac) {
	var c = this.blocks[3].bytes(6, 3).toUnsigned();
	c &= Sector.MASK[block];
	
	c |= ((((ac >> 2) & 0x01) << (12 + block)) +
		  (((ac >> 1) & 0x01) << ( 0 + block)) +
		  (( ac       & 0x01) << ( 4 + block)));

	c |= (((~c &    0xF) << 20) +
		  ((~c &   0xF0) <<  4) +
		  ((~c & 0xF000) <<  4));

	var d = this.blocks[3];
	this.blocks[3] = d.bytes(0, 6).concat(ByteString.valueOf(c, 3).concat(d.bytes(9)));
}



/**
 * Set the value for Key A
 *
 * @param {ByteString} key the key value (6 bytes)
 */
Sector.prototype.setKeyA = function(key) {
	var d = this.blocks[3];
	this.blocks[3] = key.concat(d.bytes(6));
}



/**
 * Set the value for Key B
 *
 * @param {ByteString} key the key value (6 bytes)
 */
Sector.prototype.setKeyB = function(key) {
	var d = this.blocks[3];
	this.blocks[3] = d.bytes(0, 10).concat(key);
}



/**
 * Set the data byte in the sector trailer
 *
 * @param {ByteString} db the data byte (1 bytes)
 */
Sector.prototype.setHeaderDataByte = function(db) {
	var d = this.blocks[3];
	this.blocks[3] = d.bytes(0, 9).concat(db).concat(d.bytes(10));
}



/**
 * Return a human readable presentation of the sector
 */
Sector.prototype.toString = function() {
	var str = "";
	for (var i = 0; i < 4; i++) {
		str += "Block " + i + " - ";
		
		var ac = this.getACforBlock(i);
		if (i == 3) {
			str += Sector.AC_TRAILER[ac];
		} else {
			str += Sector.AC_DATA[ac];
		}
		
		str += "\n  " + this.blocks[i].toString(HEX) + "\n";
	}
	return str;
}
