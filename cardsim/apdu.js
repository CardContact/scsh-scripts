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
 * @fileoverview Implementation of ISO 7816-4 APDU processing
 */



/**
 * Create an APDU
 * 
 * <p>This constructor supports the signatures</p>
 * <ul>
 *  <li>APDU(ByteString command)</li>
 *  <li>APDU(Number cla, Number ins, Number p1, Number p2)</li>
 *  <li>APDU(Number cla, Number ins, Number p1, Number p2, data)</li>
 *  <li>APDU(Number cla, Number ins, Number p1, Number p2, data, Ne)</li>
 * </ul>
 * @class Class implementing support for command and response APDUs
 * @constructor
 * @param {ByteString} command the command APDU
 * @param {Number} cla the class byte
 * @param {Number} ins the instruction byte
 * @param {Number} p1 the first parameter
 * @param {Number} p2 the second parameter
 * @param {ByteString} data the data field (optional)
 * @param {Number} Ne the number of expected bytes (optional)
 */
function APDU() {
	if (arguments.length > 0) {
		var arg = arguments[0];
		if (arg instanceof ByteString) {
			if (arguments.length != 1) {
				throw new GPError("APDU", GPError.INVALID_ARGUMENTS, APDU.SW_GENERALERROR, "Only one argument of type ByteString expected");
			}
			this.fromByteString(arg);
		} else {
			if ((arguments.length < 4) || (arguments.length > 6)) {
				throw new GPError("APDU", GPError.INVALID_ARGUMENTS, APDU.SW_GENERALERROR, "4 to 6 arguments expected");
			}
			
			for (var i = 0; i < 4; i++) {
				if (typeof(arguments[i]) != "number") {
					throw new GPError("APDU", GPError.INVALID_TYPE, APDU.SW_GENERALERROR, "Argument must be of type Number");
				}
			}
			this.cla = arguments[0];
			this.ins = arguments[1];
			this.p1 = arguments[2];
			this.p2 = arguments[3];

			var i = 4;
			if (arguments.length > i) {
				if (arguments[i] instanceof ByteString) {
					this.cdata = arguments[i];
					i++;
				}
			}
			
			if (arguments.length > i) {
				if (typeof(arguments[i]) != "number") {
					throw new GPError("APDU", GPError.INVALID_TYPE, APDU.SW_GENERALERROR, "Argument must be of type Number");
				}
				this.ne = arguments[i];
			}
		}
	}
	this.rapdu = null;
	this.SW = APDU.SW_GENERALERROR;
}

APDU.INS_DEACTIVATE				= 0x04;
APDU.INS_VERIFY					= 0x20;
APDU.INS_MANAGE_SE				= 0x22;
APDU.INS_CHANGE_REFERENCE_DATA	= 0x24;
APDU.INS_PSO					= 0x2A;
APDU.INS_RESET_RETRY_COUNTER	= 0x2C;
APDU.INS_ACTIVATE				= 0x44;
APDU.INS_GENERATE_KEY_PAIR		= 0x46;
APDU.INS_EXTERNAL_AUTHENTICATE	= 0x82;
APDU.INS_GET_CHALLENGE			= 0x84;
APDU.INS_GENERAL_AUTHENTICATE	= 0x86;
APDU.INS_COMPUTE_DIGITAL_SIGN	= 0x9E;
APDU.INS_SELECT					= 0xA4;
APDU.INS_READBINARY				= 0xB0;
APDU.INS_READ_BINARY			= 0xB0;
APDU.INS_READ_RECORD			= 0xB2;
APDU.INS_VERIFY_CERTIFICATE		= 0xBE;
APDU.INS_UPDATE_BINARY			= 0xD6;
APDU.INS_TERMINATE				= 0xE6;

APDU.SW_OK                 = 0x9000;      	/* Process completed                 */

APDU.SW_TIMEOUT            = 0x6401;      	/* Exec error: Command timeout       */

APDU.SW_OKMOREDATA         = 0x6100;      	/*-Process completed, more data available*/
APDU.SW_WARNING            = 0x6200;      	/*-Warning: NV-Ram not changed       */
APDU.SW_WARNING1           = 0x6201;      	/*-Warning: NV-Ram not changed 1     */
APDU.SW_DATAINV            = 0x6281;      	/*-Warning: Part of data corrupted   */
APDU.SW_EOF                = 0x6282;      	/*-Warning: End of file reached      */
APDU.SW_INVFILE            = 0x6283;      	/* Warning: Invalidated file         */
APDU.SW_INVFORMAT          = 0x6284;      	/* Warning: Invalid file control     */
APDU.SW_WARNINGNVCHG       = 0x6300;      	/*-Warning: NV-Ram changed           */
APDU.SW_WARNINGCOUNT       = 0x63C0;      	/*-Warning: Warning with counter     */
APDU.SW_WARNING0LEFT       = 0x63C0;      	/*-Warning: Verify fail, no try left */
APDU.SW_WARNING1LEFT       = 0x63C1;      	/*-Warning: Verify fail, 1 try left  */
APDU.SW_WARNING2LEFT       = 0x63C2;      	/*-Warning: Verify fail, 2 tries left*/
APDU.SW_WARNING3LEFT       = 0x63C3;      	/*-Warning: Verify fail, 3 tries left*/
APDU.SW_EXECERR            = 0x6400;      	/*-Exec error: NV-Ram not changed    */
APDU.SW_MEMERR             = 0x6501;      	/*-Exec error: Memory failure        */
APDU.SW_MEMERRWRITE        = 0x6581;      	/*-Exec error: Memory failure        */
APDU.SW_WRONGLENGTH        = 0x6700;      	/*-Checking error: Wrong length      */

APDU.SW_CLANOTSUPPORTED    = 0x6800;      	/*-Checking error: Function in CLA byte not supported */
APDU.SW_LCNOTSUPPORTED     = 0x6881;      	/*-Checking error: Logical channel not supported */
APDU.SW_SMNOTSUPPORTED     = 0x6882;      	/*-Checking error: Secure Messaging not supported */
APDU.SW_LASTCMDEXPECTED    = 0x6883;      	/*-Checking error: Last command of the chain expected */
APDU.SW_CHAINNOTSUPPORTED  = 0x6884;      	/*-Checking error: Command chaining not supported */

APDU.SW_COMNOTALLOWED      = 0x6900;      	/*-Checking error: Command not allowed */
APDU.SW_COMINCOMPATIBLE    = 0x6981;      	/*-Checking error: Command incompatible with file structure */
APDU.SW_SECSTATNOTSAT      = 0x6982;      	/*-Checking error: Security condition not satisfied */
APDU.SW_AUTHMETHLOCKED     = 0x6983;      	/*-Checking error: Authentication method locked */
APDU.SW_REFDATANOTUSABLE   = 0x6984;      	/*-Checking error: Reference data not usable */
APDU.SW_CONDOFUSENOTSAT    = 0x6985;      	/*-Checking error: Condition of use not satisfied */
APDU.SW_COMNOTALLOWNOEF    = 0x6986;      	/*-Checking error: Command not allowed (no current EF) */
APDU.SW_SMOBJMISSING       = 0x6987;      	/*-Checking error: Expected secure messaging object missing */
APDU.SW_INCSMDATAOBJECT    = 0x6988;      	/*-Checking error: Incorrect secure messaging data object */

APDU.SW_INVPARA            = 0x6A00;      	/*-Checking error: Wrong parameter P1-P2 */
APDU.SW_INVDATA            = 0x6A80;      	/*-Checking error: Incorrect parameter in the command data field*/
APDU.SW_FUNCNOTSUPPORTED   = 0x6A81;      	/*-Checking error: Function not supported */
APDU.SW_NOAPPL             = 0x6A82;      	/*-Checking error: File not found    */
APDU.SW_FILENOTFOUND       = 0x6A82;      	/*-Checking error: File not found    */
APDU.SW_RECORDNOTFOUND     = 0x6A83;      	/*-Checking error: Record not found    */
APDU.SW_OUTOFMEMORY        = 0x6A84;      	/*-Checking error: Not enough memory space in the file   */
APDU.SW_INVLCTLV           = 0x6A85;      	/*-Checking error: Nc inconsistent with TLV structure */
APDU.SW_INVACC             = 0x6A85;      	/*-Checking error: Access cond. n/f  */
APDU.SW_INCP1P2            = 0x6A86;      	/*-Checking error: Incorrect P1-P2   */
APDU.SW_INVLC              = 0x6A87;      	/*-Checking error: Lc inconsistent with P1-P2 */
APDU.SW_RDNOTFOUND         = 0x6A88;      	/*-Checking error: Reference data not found*/
APDU.SW_FILEEXISTS         = 0x6A89;      	/*-Checking error: File already exists */
APDU.SW_DFNAMEEXISTS       = 0x6A8A;      	/*-Checking error: DF name already exists */

APDU.SW_INVP1P2            = 0x6B00;      	/*-Checking error: Wrong parameter P1-P2 */
APDU.SW_INVLE              = 0x6C00;      	/*-Checking error: Invalid Le        */
APDU.SW_INVINS             = 0x6D00;      	/*-Checking error: Wrong instruction */
APDU.SW_INVCLA             = 0x6E00;      	/*-Checking error: Class not supported */
APDU.SW_ACNOTSATISFIED     = 0x9804;      	/* Access conditions not satisfied   */
APDU.SW_NOMORESTORAGE      = 0x9210;      	/* No more storage available         */
APDU.SW_GENERALERROR       = 0x6F00;      	/*-Checking error: No precise diagnosis */


/**
 * Create an APDU object from the encoded form (Called internally)
 *
 * @param {ByteString} bs
 */
APDU.prototype.fromByteString = function(bs) {
	if (bs.length < 4) {
		throw new GPError("APDU", GPError.INVALID_DATA, APDU.SW_GENERALERROR, "Command APDU must be at least 4 bytes long");
	}
	this.cla = bs.byteAt(0);
	this.ins = bs.byteAt(1);
	this.p1 = bs.byteAt(2);
	this.p2 = bs.byteAt(3);
	
	if (bs.length > 4) {
		var extended = false;
		
		var i = 4;
		var l = bs.length - i;
		var n = bs.byteAt(i++);
		l--;
		
		if ((n == 0) && (l > 0)) {
			extended = true;
			if (l < 2) {
				throw new GPError("APDU", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Extended length APDU too short");
			}
			n = (bs.byteAt(i) << 8) + bs.byteAt(i + 1);
			i += 2;
			l -= 2;
		}
		
		if (l > 0) {	// Case 3s / Case 3e / Case 4s / Case 4e
			if (l < n) {
				throw new GPError("APDU", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Invalid Lc in APDU");
			}
			this.cdata = bs.bytes(i, n);
			i += n;
			l -= n;
			
			if (l > 0) {	// Case 4s / Case 4e
				n = bs.byteAt(i++);
				l--;
				if (extended) {
					if (l < 1) {
						throw new GPError("APDU", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Invalid Le in extended APDU");
					}
					n = (n << 8) + bs.byteAt(i++);
					l--;
				}
				this.ne = (extended && (n == 0) ? 65536 : n);
			}
		} else {
			this.ne = (extended && (n == 0) ? 65536 : n);
		}
		
		if (l > 0) {
			throw new GPError("APDU", GPError.INVALID_DATA, APDU.SW_WRONGLENGTH, "Too many bytes in APDU");
		}
	}
}



/**
 * Get encoded command APDU
 *
 * @type ByteString
 * @return the encoded command APDU
 */
APDU.prototype.getCommandAPDU = function() {
	var bb = new ByteBuffer();
	
	bb.append(this.cla);
	bb.append(this.ins);
	bb.append(this.p1);
	bb.append(this.p2);

	var hasCData = (typeof(this.cdata) != "undefined");
	var hasNe = (typeof(this.ne) != "undefined");
	
	var extended = ((hasCData && this.cdata.length > 255) || 
					(hasNe && this.ne > 256));

	if (extended) {
		bb.append(0);
	}

	if (hasCData && this.cdata.length > 0) {
		if (extended) {
			bb.append(this.cdata.length >> 8);
		}
		bb.append(this.cdata.length & 0xFF);
		bb.append(this.cdata);
	}
	
	if (hasNe) {
		if (extended) {
			bb.append(this.ne >> 8);
		}
		bb.append(this.ne & 0xFF);
	}
	
	return bb.toByteString();
}



/**
 * Get encoded response APDU
 *
 * @type ByteString
 * @return the encoded response APDU
 */
APDU.prototype.getResponseAPDU = function() {
	var bb = new ByteBuffer();
	
	if (this.rdata) {
		bb.append(this.rdata);
	}
		
	bb.append(this.SW >> 8);
	bb.append(this.SW & 0xFF);
	
	return bb.toByteString();
}



/**
 * Gets the class byte
 *
 * @type Number
 * @return the class byte
 */
APDU.prototype.getCLA = function() {
	return this.cla;
}



/**
 * Test if command chaining is indicated
 *
 * @type boolean
 * @return true if chaining bit is set
 */
APDU.prototype.isChained = function() {
	return (this.cla & 0x10) == 0x10;
}



/**
 * Test if command is send using secure messaging
 *
 * @type boolean
 * @return true if secure messaging is indicated in CLA byte
 */
APDU.prototype.isSecureMessaging = function() {
	return (this.cla & 0x08) == 0x08;
}



/**
 * Test if command is send using secure messaging
 *
 * @type boolean
 * @return true if secure messaging is using an authenticated header
 */
APDU.prototype.isAuthenticatedHeader = function() {
	return (this.cla & 0x0C) == 0x0C;
}



/**
 * Gets the instruction byte
 *
 * @type Number
 * @return the instruction byte
 */
APDU.prototype.getINS = function() {
	return this.ins;
}



/**
 * Gets the P1 byte
 *
 * @type Number
 * @return the P1 byte
 */
APDU.prototype.getP1 = function() {
	return this.p1;
}



/**
 * Gets the P2 byte
 *
 * @type Number
 * @return the P2 byte
 */
APDU.prototype.getP2 = function() {
	return this.p2;
}



/**
 * Set the command data
 *
 * @param {ByteString} cdata the command data
 */
APDU.prototype.setCData = function(cdata) {
	this.cdata = cdata;
}



/**
 * Gets the command data
 *
 * @type ByteString
 * @return the command data, if any else undefined
 */
APDU.prototype.getCData = function() {
	return this.cdata;
}



/**
 * Check if APDU has command data
 *
 * @type boolean
 * @return true if command APDU has data field
 */
APDU.prototype.hasCData = function() {
	return ((typeof(this.cdata) != "undefined") && (this.cdata != null));
}



/**
 * Gets the command data as a list of TLV objects
 *
 * @type TLVList
 * @return the command data as TLV list, if any else undefined
 */
APDU.prototype.getCDataAsTLVList = function() {
	if (typeof(this.cdata) == "undefined") {
		throw new GPError("APDU", GPError.INVALID_DATA, APDU.SW_INVDATA, "No data in command APDU");
	}
	
	try	{
		var a = new TLVList(this.cdata, TLV.EMV);
	}
	catch(e) {
		throw new GPError("APDU", GPError.INVALID_DATA, APDU.SW_INVDATA, "Invalid TLV data in command APDU");
	}

	return a;
}



/**
 * Gets the number of expected bytes
 *
 * @type Number
 * @return the number of expected bytes or undefined 
 */
APDU.prototype.getNe = function() {
	return this.ne;
}



/**
 * Check if APDU has Le field
 *
 * @type boolean
 * @return true if command APDU has Le field
 */
APDU.prototype.hasLe = function() {
	return typeof(this.ne) != "undefined";
}



/**
 * Set secure channel object to be used in wrap and unwrap methods
 *
 * @param {SecureChannel} secureChannel the channel
 */
APDU.prototype.setSecureChannel = function(secureChannel) {
	this.secureChannel = secureChannel;
}



/**
 * Return the secure channel, if any
 *
 * @type SecureChannel
 * @return the secure channel
 */
APDU.prototype.getSecureChannel = function() {
	return this.secureChannel;
}



/**
 * Test if a secure channel is defined for this APDU
 *
 * @type boolean
 * @return true, if secure channel is set
 */
APDU.prototype.hasSecureChannel = function() {
	return (typeof(this.secureChannel) != "undefined") && (this.secureChannel != null);
}



/**
 * Wrap APDU using secure channel
 */
APDU.prototype.wrap = function() {
	if (this.hasSecureChannel()) {
		this.secureChannel.wrap(this);
	}
}



/**
 * Unwrap APDU using secure channel
 */
APDU.prototype.unwrap = function() {
	if (this.hasSecureChannel()) {
		this.secureChannel.unwrap(this);
	}
}



/**
 * Sets the response data field for the response APDU
 *
 * @param {ByteString} data the response data field
 */
APDU.prototype.setRData = function(data) {
	this.rdata = data;
}



/**
 * Get the response data
 *
 * @type ByteString
 * @return the response data
 */
APDU.prototype.getRData = function() {
	return this.rdata;
}



/**
 * Check if APDU has response data
 *
 * @type boolean
 * @return true if response APDU has data field
 */
APDU.prototype.hasRData = function() {
	return ((typeof(this.rdata) != "undefined") && (this.rdata != null));
}



/**
 * Sets the status word for the response ADPU
 *
 * @param {Number} sw the status word
 */
APDU.prototype.setSW = function(sw) {
	this.SW = sw;
}



/**
 * Get the status word
 *
 * @type Number
 * @return the status word
 */
APDU.prototype.getSW = function() {
	return this.SW;
}



/**
 * Return a human readable form of this object
 */
APDU.prototype.toString = function() {
	return this.getCommandAPDU().toString(HEX) + " : " + this.getResponseAPDU().toString(HEX);
}



/**
 * Simple unit test
 */
APDU.test = function() {
	// Case 1
	var a = new APDU(0x00, 0xA4, 0x00, 0x0C);
	print(a);
	var b = a.getCommandAPDU();
	assert(b.toString(HEX) == "00A4000C");
	var c = new APDU(b);
	assert(a.toString() == c.toString());

	// Case 2 Short
	var a = new APDU(0x00, 0xA4, 0x00, 0x0C, 0);
	print(a);
	var b = a.getCommandAPDU();
	assert(b.toString(HEX) == "00A4000C00");
	var c = new APDU(b);
	assert(a.toString() == c.toString());

	// Case 2 Extended
	var a = new APDU(0x00, 0xA4, 0x00, 0x0C, 65536);
	print(a);
	var b = a.getCommandAPDU();
	assert(b.toString(HEX) == "00A4000C000000");
	var c = new APDU(b);
	print(c);
	assert(a.toString() == c.toString());

	// Case 3 Short
	var a = new APDU(0x00, 0xA4, 0x00, 0x0C, new ByteString("3F00", HEX));
	print(a);
	var b = a.getCommandAPDU();
	assert(b.toString(HEX) == "00A4000C023F00");
	var c = new APDU(b);
	assert(a.toString() == c.toString());

	// Case 3 Extended
	var data = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
	var a = new APDU(0x00, 0xA4, 0x00, 0x0C, new ByteString(data, HEX));
	print(a);
	var b = a.getCommandAPDU();
	assert(b.toString(HEX) == "00A4000C000100" + data);
	var c = new APDU(b);
	assert(a.toString() == c.toString());

	// Case 4 Short
	var a = new APDU(0x00, 0xA4, 0x00, 0x0C, new ByteString("3F00", HEX), 0);
	print(a);
	var b = a.getCommandAPDU();
	assert(b.toString(HEX) == "00A4000C023F0000");
	var c = new APDU(b);
	assert(a.toString() == c.toString());
	
	// Case 4b Extended
	var a = new APDU(0x00, 0xA4, 0x00, 0x0C, new ByteString(data, HEX), 0);
	print(a);
	var b = a.getCommandAPDU();
	assert(b.toString(HEX) == "00A4000C000100" + data + "0000");
	var c = new APDU(b);
	assert(a.toString() == c.toString());

	// Case 4b Extended
	var a = new APDU(0x00, 0xA4, 0x00, 0x0C, new ByteString("3F00", HEX), 65536);
	print(a);
	var b = a.getCommandAPDU();
	assert(b.toString(HEX) == "00A4000C0000023F000000");
	var c = new APDU(b);
	assert(a.toString() == c.toString());
	
}



/**
 * Create an adapter to decode a APDU for data unit handling
 *
 * @class Adapter class to decode APDUs for data unit handling
 * @constructor
 * @param {APDU} apdu the APDU to decode
 */ 
function DataUnitAPDU(apdu) {
	this.apdu = apdu;

	var p1 = apdu.getP1();
	
	if ((this.apdu.getINS() & 1) == 0) {		// Even instruction
		if ((p1 & 0x80) == 0x80) {				// SFI in P1
			this.offset = this.apdu.getP2();
			this.sfi = p1 & 0x1F;
		} else {
			this.offset = (p1 << 8) + this.apdu.getP2();
		}
		this.data = apdu.getCData();
	} else {									// Odd instruction
		var p2 = apdu.getP2();
		var fid = (p1 << 8) + p2;				// FID in P1 P2
		// If bits b16 - b6 are all 0 and b5 - b1 are not all equal, then we have an SFI 
		if (((fid & 0xFFE0) == 0) && ((fid & 0x1F) >= 1) && ((fid & 0x1F) <= 30)) {
			this.sfi = fid & 0x1F;
		} else if (fid != 0) {					// FID = 0000 means current file
			var bb = new ByteBuffer();
			bb.append(p1);
			bb.append(p2);
			this.fid = bb.toByteString();
		}

		var a = this.apdu.getCDataAsTLVList();

		if ((a.length < 1) || (a.length > 2)) {
			throw new GPError("DataUnitAPDU", GPError.INVALID_DATA, APDU.SW_INVDATA, "Invalid data for odd instruction data handling command, less than one or more than two elements in TLV");
		}

		var o = a.index(0);
		if (o.getTag() != 0x54) {
			throw new GPError("DataUnitAPDU", GPError.INVALID_DATA, APDU.SW_INVDATA, "Invalid data for odd instruction data handling command, first tag must be '54' offset");
		}
		
		this.offset = o.getValue().toUnsigned();
		
		if (a.length == 2) {
			var o = a.index(1);
			var t = o.getTag();
			if ((t != 0x53) && (t != 0x73)) {
				throw new GPError("DataUnitAPDU", GPError.INVALID_DATA, APDU.SW_INVDATA, "Invalid data for odd instruction data handling command, second tag must be '53' or '73'");
			}
		
			this.data = o.getValue();
		}
	}
}



/**
 * Gets the short file identifier, if one defined
 * 
 * @type Number
 * @return the short file identifier in the range 1 to 30 or -1 if not defined
 */
DataUnitAPDU.prototype.getSFI = function() {
	if (typeof(this.sfi) == "undefined") {
		return -1;
	}
	return this.sfi;
}



/**
 * Gets the file identifier, if one defined
 * 
 * @type ByteString
 * @return the file identifier or null if not defined
 */
DataUnitAPDU.prototype.getFID = function() {
	if (typeof(this.fid) == "undefined") {
		return null;
	}
	return this.fid;
}



/**
 * Gets the offset
 * 
 * @type Number
 * @return the offset to read from or write to
 */
DataUnitAPDU.prototype.getOffset = function() {
	return this.offset;
}



/**
 * Get the command data
 *
 * @type ByteString
 * @return the command data
 */
DataUnitAPDU.prototype.getCData = function() {
	if (!this.hasCData()) {
		throw new GPError("APDU", GPError.INVALID_DATA, APDU.SW_INVDATA, "No data in command APDU");
	}
	return this.data;
}



/**
 * Returns true if command data in contained in the APDU
 *
 * @type boolean
 * @returns true if command data contained
 */
DataUnitAPDU.prototype.hasCData = function() {
	return ((typeof(this.data) != "undefined") && (this.data != null));
}



/**
 * Simple Unit Test
 */
DataUnitAPDU.test = function() {
	var apdu = new APDU(0x00, 0xB0, 0, 0, 0);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0);
	assert(!dh.hasCData());
	
	var apdu = new APDU(0x00, 0xB0, 0x7F, 0xFF, 0);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0x7FFF);
	assert(!dh.hasCData());

	var apdu = new APDU(0x00, 0xB0, 0x80, 0, 0);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0);
	assert(!dh.hasCData());

	var apdu = new APDU(0x00, 0xB0, 0x80, 0xFF, 0);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0xFF);
	assert(!dh.hasCData());

	var apdu = new APDU(0x00, 0xB1, 0, 0, new ByteString("540100", HEX), 0);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0);
	assert(!dh.hasCData());

	var apdu = new APDU(0x00, 0xB1, 0, 0, new ByteString("5401FF", HEX), 0);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0xFF);
	assert(!dh.hasCData());

	var apdu = new APDU(0x00, 0xB1, 0, 0, new ByteString("540401000000", HEX), 0);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0x01000000);
	assert(!dh.hasCData());

	var data = new ByteString("1234", ASCII);
	
	var apdu = new APDU(0x00, 0xD6, 0, 0, data);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0);
	assert(dh.hasCData());
	assert(dh.getCData().equals(data));
	
	var apdu = new APDU(0x00, 0xD6, 0x7F, 0xFF, data);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0x7FFF);
	assert(dh.hasCData());
	assert(dh.getCData().equals(data));

	var apdu = new APDU(0x00, 0xD6, 0x80, 0, data);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0);
	assert(dh.hasCData());
	assert(dh.getCData().equals(data));

	var apdu = new APDU(0x00, 0xD6, 0x80, 0xFF, data);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0xFF);
	assert(dh.hasCData());
	assert(dh.getCData().equals(data));

	var apdu = new APDU(0x00, 0xD7, 0, 0, (new ByteString("5401005304", HEX)).concat(data), 0);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0);
	assert(dh.hasCData());
	assert(dh.getCData().equals(data));

	var apdu = new APDU(0x00, 0xD7, 0, 0, (new ByteString("5401FF5304", HEX)).concat(data), 0);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0xFF);
	assert(dh.hasCData());
	assert(dh.getCData().equals(data));

	var apdu = new APDU(0x00, 0xD7, 0, 0, (new ByteString("5404010000005304", HEX)).concat(data), 0);
	var dh = new DataUnitAPDU(apdu);
	assert(dh.getOffset() == 0x01000000);
	assert(dh.hasCData());
	assert(dh.getCData().equals(data));
}
