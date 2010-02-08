/*
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2010 CardContact Software & System Consulting
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
 * @fileoverview Implementation of Simple CV request generator based on 
 * TR-03110 "Advanced Security Mechanisms for Machine Readable Travel Documents", Version 2.0
 *
 * For now we only support ECC crypto
 *
 */

load("tools/eccutils.js");



/*
 * Convert x/y coordinates to uncompressed format
 *
 * x/y - coordinates of EC point
 * 
 * return ByteString containing compressed format
 *
 * TODO: Move to ECUtils
 */ 
EAC2CVRequestGenerator.encodeUncompressedECPoint = function(x, y) {
    
    bb = new ByteBuffer();
    
    // uncompressed encoding
    bb.append(new ByteString("04", HEX));
    bb.append(new ByteString(x, HEX));
    bb.append(new ByteString(y, HEX));
    
    return bb.toByteString();
}
 


/**
 * Strips leading zeros of a ByteString
 *
 * @param {ByteString} value the ByteString value
 * @return the stripped ByteString object, may be an empty ByteString
 * @type ByteString
 *
 * TODO: Move to Utils
 */
EAC2CVRequestGenerator.stripLeadingZeros = function(value) {
	var i = 0;
	for (; (i < value.length) && (value.byteAt(i) == 0); i++);
	
	return value.right(value.length - i);
}



/**
 * Constructor for request generator
 *
 * @param {Crypto} Crypto object to use
 *
 * @constructor
 */
function EAC2CVRequestGenerator(crypto) {
	this.crypto = crypto;
}



/**
 * Set the public key that should be encoded within the request
 *
 * @param {Key} Public Key
 */
EAC2CVRequestGenerator.prototype.setPublicKey = function(publicKey) {
	this.publicKey = publicKey;
}



/**
 * Set the certficate holder reference (CHR) for the request
 *
 * @param {String} CHR for the request
 */
EAC2CVRequestGenerator.prototype.setCHR = function(CHR) {
	this.CHR = CHR;
}



/**
 * Reset the current generator object
 *
 * TODO: Implement me
 */
EAC2CVRequestGenerator.prototype.reset = function() {
}



/**
 * Set the certificate profile identifier (CPI) for the request
 *
 * @param {Number} CPI for the request
 */
EAC2CVRequestGenerator.prototype.setProfileIdentifier = function(profileID) {
	this.profileIdentifier = profileID;
}



/**
 * Set the certficate authorization reference (CAR) for the request
 *
 * The usage of this method is optional - if no CAR is set, there will be no
 * "inner" CAR included within the certficate request
 *
 * @param {String} CHR for the request
 */
EAC2CVRequestGenerator.prototype.setCAR = function(CAR) {
	this.CAR = CAR;
}



/**
 * Set the extension values that should be included within the request
 *
 * @param {ByteString[]} Array of DER-encoded extensions
 */
EAC2CVRequestGenerator.prototype.setExtensions = function(extensions) {
	this.extensions = extensions;
}



/**
 * Set the object identifier that should be included in the public key domain parameters
 *
 * @param {ByteString} Object identifier as specified in appendix A.6.4
 */
EAC2CVRequestGenerator.prototype.setTAAlgorithmIdentifier = function(oid) {
	this.taOID = oid;
}



/**
 * Get the CAR as ByteString object
 *
 * @private
 */
EAC2CVRequestGenerator.prototype.getCAR = function() {
    var t = new ASN1("Certification Authority Reference", 0x42, new ByteString(this.CAR, ASCII));
    return t;
}



/**
 * Get the CHR as ByteString object
 *
 * @private
 */
EAC2CVRequestGenerator.prototype.getCHR = function() {
	var t = new ASN1("Certification Holder Reference", 0x5F20, new ByteString(this.CHR, ASCII));
	return t;
}



/**
 * Get the encoded public key including domain parameters
 *
 * @private
 */
EAC2CVRequestGenerator.prototype.getPublicKey = function() {

	var t = new ASN1("Public Key", 0x7F49);
    	
    // Create empty public key object - this is just used to extract the domain parameters
    var key = new Key();
    key.setType(Key.PUBLIC);
	key.setComponent(Key.ECC_CURVE_OID, this.publicKey.getComponent(Key.ECC_CURVE_OID)); 
    
    t.add(new ASN1("Object Identifier", 0x06, this.taOID));
    t.add(new ASN1("Prime Modulus", 0x81, key.getComponent(Key.ECC_P)));
    t.add(new ASN1("First coefficient a", 0x82, key.getComponent(Key.ECC_A)));
    t.add(new ASN1("Second coefficient b", 0x83, key.getComponent(Key.ECC_B)));
    t.add(new ASN1("Base Point G", 0x84, EAC2CVRequestGenerator.encodeUncompressedECPoint(key.getComponent(Key.ECC_GX), key.getComponent(Key.ECC_GY))));
    t.add(new ASN1("Order of the base point", 0x85, key.getComponent(Key.ECC_N)));
    
    t.add(new ASN1("Public Point y", 0x86, EAC2CVRequestGenerator.encodeUncompressedECPoint(this.publicKey.getComponent(Key.ECC_QX), this.publicKey.getComponent(Key.ECC_QY))));
    
    t.add(new ASN1("Cofactor f", 0x87, EAC2CVRequestGenerator.stripLeadingZeros(key.getComponent(Key.ECC_H))));
        
    return t;
}



/**
 * Get the encoded CPI as ByteString
 *
 * @private
 */
EAC2CVRequestGenerator.prototype.getProfileIdentifier = function() {
	var bb = new ByteBuffer();
	bb.append(this.profileIdentifier);
	
	var t = new ASN1("Certificate Profile Identifier", 0x5F29, bb.toByteString());
	return t;
}



/**
 * Get the DER-encoded extension vector
 *
 * @private
 */
EAC2CVRequestGenerator.prototype.getExtensions = function() {
    var t = new ASN1("Certificate Extensions", 0x7F49);
    for (var i = 0; i < this.extensions.length; i++)
    	t.add(this.extensions[i]);
    return t;
}



/**
 * Get the encoded certificate request body
 *
 * @private
 */
EAC2CVRequestGenerator.prototype.getCertificateBody = function() {
	
    var t = new ASN1("Certificate Body", 0x7F4E);
    t.add(this.getProfileIdentifier());
    
    if (this.CAR) {
        t.add(this.getCAR());
    }
    
    t.add(this.getPublicKey());
    t.add(this.getCHR());
    
    if (this.extensions) {
        t.add(this.getExtensions());
	}
    return t;
}



/**
 * Generate initial certificate request using the specified private key for signing
 *
 * @param {Key} Private key for signature creation
 * @return The DER-encoded CV request
 * @type ASN1
 */
EAC2CVRequestGenerator.prototype.generateCVRequest = function(privateKey) {
	var request = new ASN1("CV Certificate", 0x7F21);
	
	var body = this.getCertificateBody();
    
	request.add(body);
	
	var signature = this.crypto.sign(privateKey, Crypto.ECDSA, body.getBytes());
	var signatureValue = new ASN1("Signature", 0x5F37, ECCUtils.unwrapSignature(signature));
	
    request.add(signatureValue);
	
	return request;
}



/**
 * Generate authenticated request
 *
 * @param {Key} Private key for the request signature
 * @param {Key} Private key for used for signing and authenticating the request
 * @param (String) CHR of the authenticating authority 
 *
 * @return The DER-encoded authenticated CV request
 * @type ASN1
 */
EAC2CVRequestGenerator.prototype.generateAuthenticatedCVRequest = function(requestKey, authenticationKey, authCHR) {
	var authRequest = new ASN1("Authentication", 0x67);
	
	var request = this.generateCVRequest(requestKey);
    
    var signature = this.crypto.sign(requestKey, Crypto.ECDSA, request.getBytes());
	var signatureValue = new ASN1("Signature", 0x5F37, ECCUtils.unwrapSignature(signature));
	
	var chr = new ASN1("Certification Authority Reference", 0x42, new ByteString(authCHR, ASCII));
	
	var signature = this.crypto.sign(authenticationKey, Crypto.ECDSA, request.getBytes());
	var signatureValue = new ASN1("Signature", 0x5F37, ECCUtils.unwrapSignature(signature));
	
    authRequest.add(request);
    authRequest.add(chr);
    authRequest.add(signatureValue);
    
	return authRequest;
}