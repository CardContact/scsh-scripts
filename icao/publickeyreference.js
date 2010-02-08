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
 * @fileoverview Public Key Reference, the value stored in CAR and CHR of CV-Certificates
 */
 



/**
 * <p>Create a public key reference (CAR/CHR) from binary representation or individual fields.</p>
 *
 * <p>Use one of the following signatures:</p>
 *
 * <ul>
 *  <li>PublicKeyReference(ByteString value) - binary public key reference</li>
 *  <li>PublicKeyReference(String value) - string encoded public key reference</li>
 *  <li>PublicKeyReference(String countryCode, String holderMnemonic, String sequenceNumber) - string encoded public key reference</li>
 * </ul>
 * <p>@see PublicKeyReference.test() for an example.</P>
 *
 * @class <p>A class that implements a public key reference to be used as CAR and CHR in
 *        card verifiable certificates (CVC).</p>
 * @constructor
 */
function PublicKeyReference() {
	if (arguments.length > 0) {
		if (arguments.length == 1) {
			if (typeof(arguments[0]) == "string") {
				this.bin = new ByteString(arguments[0], ASCII);
			} else {
				this.bin = arguments[0];
			}
		} else {
			var cc = arguments[0];
			var mn = arguments[1];
			var sq = arguments[2];
			this.bin = new ByteString(cc + mn + sq, ASCII);
		}
	}
}



/**
 * Returns the 2 character country code
 *
 * @return the country code
 * @type String
 */
PublicKeyReference.prototype.getCountryCode = function() {
	return this.bin.bytes(0, 2).toString(ASCII);
}



/**
 * Returns the variable length holder mnemonic
 *
 * @return the holder mnemonic
 * @type String
 */
PublicKeyReference.prototype.getMnemonic = function() {
	return this.bin.bytes(2, this.bin.length - 7).toString(ASCII);
}



/**
 * Returns the 5 character sequence number
 *
 * @return the sequence number
 * @type String
 */
PublicKeyReference.prototype.getSequenceNo = function() {
	return this.bin.bytes(this.bin.length - 5, 5).toString(ASCII);
}



/**
 * Returns the certificate holder name, which is the concatenation of the country code and the
 * holder mnemonic.
 *
 * @return the holder name
 * @type String
 */
PublicKeyReference.prototype.getHolder = function() {
	return this.getCountryCode() + this.getMnemonic();
}



/**
 * Returns the binary encoded public key reference
 *
 * @return the public key reference
 * @type ByteString
 */
PublicKeyReference.prototype.getBytes = function() {
	return this.bin;
}



/**
 * Returns the string representation of the public key reference
 *
 * @return the public key reference
 * @type String
 */
PublicKeyReference.prototype.toString = function() {
	return this.bin.toString(ASCII);
}



/**
 * Test function
 */
PublicKeyReference.test = function() {
	var p = new PublicKeyReference(new ByteString("UTABCDF0000", ASCII));
	assert(p.getCountryCode() == "UT");
	assert(p.getMnemonic() == "ABCD");
	assert(p.getSequenceNo() == "F0000");
	assert(p.getHolder() == "UTABCD");
	
	var p = new PublicKeyReference("UT", "ABCD", "F0000");
	assert(p.getCountryCode() == "UT");
	assert(p.getMnemonic() == "ABCD");
	assert(p.getSequenceNo() == "F0000");
	assert(p.getHolder() == "UTABCD");
	
	var p = new PublicKeyReference("UTABCDF0000");
	assert(p.getCountryCode() == "UT");
	assert(p.getMnemonic() == "ABCD");
	assert(p.getSequenceNo() == "F0000");
	assert(p.getHolder() == "UTABCD");
	
	assert(p.getBytes().toString(ASCII) == "UTABCDF0000");
}

