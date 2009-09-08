/*
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2006 CardContact Software & System Consulting
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
 * @fileoverview
 * EAC2CVCertificateGenerator - Simple CV certificate generator class
 * based on "Advanced Security Mechanisms for Machine Readable Travel Documents", Version 2.0
 *
 *
 * TODO: For now we only support ECC crypto
 *
 */


/**
 * Find a tag within the given TLV structure and returns the corresponding TLV object.
 *
 * @param {TLV} tlv the TLV structure
 * @param {Number} tagNumber the number of the tag to search for
 * @return the TLV object found
 * @type TLV
 */
function findTag(tlv, tagNumber) {
	
	for(var i = 0; (i < tlv.elements) && (tlv.get(i).tag != tagNumber); i++) {		
	}
	
	if (i == tlv.elements) {
		throw new GPError("CVCertificateGenerator", TAG_NOT_FOUND, TAG_NOT_FOUND, "Tag " + tagNumber + "not in structure.");

	}
	
	return tlv.get(i)
}


/**
 * Convert x/y coordinates to uncompressed format
 *
 * @param {ByteString} x the x-coordinate of the point
 * @param {ByteString} y the y-coordinate of the point
 * @return the point in uncompressed format
 * @type ByteString
 */
function encodeUncompressedECPoint(x,y) {
    
    bb = new ByteBuffer();
    
    // uncompressed encoding
    bb.append(new ByteString("04", HEX));
    bb.append(new ByteString(x, HEX));
    bb.append(new ByteString(y, HEX));
    
    return bb.toByteString();
}


/**
 * Decode x/y coordinates from uncompressed format
 *
 * @param {ByteString} uncompressedPoint the uncompressed point
 * @return the x-/y-coordinate of the point
 * @type ByteString
 */

function decodeUncompressedECPoint(uncompressedPoint) {
    
    // Determine the size of the coordinates ignoring the indicator byte '04'
    var length = uncompressedPoint.length - 1;
    
    var sizeOfCoordinate = length / 2;
    
    var xValue = uncompressedPoint.bytes(1, sizeOfCoordinate);
    var yValue = uncompressedPoint.bytes(1 + sizeOfCoordinate, sizeOfCoordinate);
    
    return { x:xValue, y:yValue };
} 



/*
 * Define a generator object for CV certificates
 */
// Constructor
function EAC2CVCertificateGenerator(crypto) {
	this.crypto = crypto;
}


EAC2CVCertificateGenerator.prototype.reset = function() {
}


/**
 * Set the profile identifier
 *
 * @param {Number} profileID the profile identifier
 */
EAC2CVCertificateGenerator.prototype.setProfileIdentifier = function(profileID) {
	this.profileIdentifier = profileID;
}


/**
 * Set the certification authority reference
 *
 * @param {String} CAR the CAR value
 */
EAC2CVCertificateGenerator.prototype.setCAR = function(CAR) {
	this.CAR = CAR;
}


/**
 * Set the certificate holder reference
 *
 * @param {String} CHR the CHR value
 */
EAC2CVCertificateGenerator.prototype.setCHR = function(CHR) {
	this.CHR = CHR;
}


/**
 * Set the effective date
 *
 * @param {String} effectiveDate the effective date
 */
EAC2CVCertificateGenerator.prototype.setEffectiveDate = function(effectiveDate) {
	this.effectiveDate = effectiveDate;
}


/**
 * Set the expiry date
 *
 * @param {String} expiryDate the expiry date
 */
EAC2CVCertificateGenerator.prototype.setExpiryDate = function(expiryDate) {
	this.expiryDate = expiryDate;
}


/**
 * Set the object identifier of the authorization template for the generated certificate
 *
 * @param {ByteString} oid the object identifier for the chat
 */
EAC2CVCertificateGenerator.prototype.setChatOID = function(oid) {
	this.chatOID = oid;
}


/**
 * Set the authorization level of the authorization template for the generated certificate
 *
 * @param {ByteString} authLevel the encoded authorization level
 */
EAC2CVCertificateGenerator.prototype.setChatAuthorizationLevel = function(authLevel) {
	this.chatAuthorizationLevel = authLevel;
}


/**
 * Set the algorithm identifier for terminal authentication
 *
 * @param {ByteString} oid the object identifier as specified in appendix A.6.4
 */
EAC2CVCertificateGenerator.prototype.setTAAlgorithmIdentifier = function(oid) {
	this.taOID = oid;
}


/**
 * Set some additional extensions 
 *
 * @param {Array of ASN.1 objects} extensions array containing the ASN.1 encoded extensions for the certificate
 */
EAC2CVCertificateGenerator.prototype.setExtensions = function(extensions) {
	this.extensions = extensions;
}


/**
 * Set whether to include domain parameters in the certificate or not
 *
 * @param {Boolean} value the flag indicator
 */
EAC2CVCertificateGenerator.prototype.setIncludeDomainParameters = function(value) {
	this.includeDomainParameters = value;
}


// Internal functions for the generation of a certificate

EAC2CVCertificateGenerator.prototype.getCAR = function() {
    var t = new ASN1("Certification Authority Reference", 0x42, new ByteString(this.CAR, ASCII));
    return t;
}


EAC2CVCertificateGenerator.prototype.getCHR = function() {
		
	var t = new ASN1("Certification Holder Reference", 0x5F20, new ByteString(this.CHR, ASCII));
	return t;
}


function convertDate(date) {

	var temp = new ByteString(date, ASCII);
	var bb = new ByteBuffer();
	var singleByte;
	
	for (i=0; i < temp.length; i++) {
		bb.append(temp.byteAt(i) - 0x30);
	}
	
	return bb.toByteString();
}


EAC2CVCertificateGenerator.prototype.getEffectiveDate = function() {
    var t = new ASN1("Certificate Effective Date", 0x5F25, convertDate(this.effectiveDate));
    return t;
}


EAC2CVCertificateGenerator.prototype.getExpiryDate = function() {
    var t = new ASN1("Certificate Expiration Date", 0x5F24, convertDate(this.expiryDate));
    return t;
}


EAC2CVCertificateGenerator.prototype.getCHAT = function() {
    var t = new ASN1("Certificate Holder Authorization Template", 0x7F4C);
    
    var oid = new ASN1("Object Identifier", ASN1.OBJECT_IDENTIFIER, this.chatOID);
    var authLevel = new ASN1("Authorization Level", 0x53, this.chatAuthorizationLevel);
    
    t.add(oid);
    t.add(authLevel);
    
    return t;
}


/**
 * Strips leading zeros of a ByteString
 *
 * @param {ByteString} value the ByteString value
 * @return the stripped ByteString object, may be an empty ByteString
 * @type ByteString
 */
EAC2CVCertificateGenerator.prototype.stripLeadingZeros = function(value) {
	var i = 0;
	for (; (i < value.length) && (value.byteAt(i) == 0); i++);
	
	return value.right(value.length - i);
}


EAC2CVCertificateGenerator.prototype.getPublicKey = function() {

	var t = new ASN1("Public Key", 0x7F49);
    	
    // Create empty public key object- this is just used to extract the domain parameters
    var key = new Key();
    key.setType(Key.PUBLIC);
	key.setComponent(Key.ECC_CURVE_OID, this.publicKey.getComponent(Key.ECC_CURVE_OID)); 
    
    t.add(new ASN1("Object Identifier", 0x06, this.taOID));
    
    if (this.includeDomainParameters == true) {
    
    	t.add(new ASN1("Prime Modulus", 0x81, key.getComponent(Key.ECC_P)));
    	t.add(new ASN1("First coefficient a", 0x82, key.getComponent(Key.ECC_A)));
    	t.add(new ASN1("Second coefficient b", 0x83, key.getComponent(Key.ECC_B)));
    
    	t.add(new ASN1("Base Point G", 0x84, encodeUncompressedECPoint(key.getComponent(Key.ECC_GX), key.getComponent(Key.ECC_GY))));
    
    	t.add(new ASN1("Order of the base point", 0x85, key.getComponent(Key.ECC_N)));
    
    	t.add(new ASN1("Public Point y", 0x86, encodeUncompressedECPoint(this.publicKey.getComponent(Key.ECC_QX), this.publicKey.getComponent(Key.ECC_QY))));
    
    	t.add(new ASN1("Cofactor f", 0x87, this.stripLeadingZeros(key.getComponent(Key.ECC_H))));
    }
        
    return t;
}


EAC2CVCertificateGenerator.prototype.getProfileIdentifier = function() {

	var bb = new ByteBuffer();
	bb.append(this.profileIdentifier);
	
	var t = new ASN1("Certificate Profile Identifier", 0x5F29, bb.toByteString());
	return t;
}


EAC2CVCertificateGenerator.prototype.getExtensions = function() {
    var t = new ASN1("Certificate Extentions", 0x65);
    for (var i = 0; i < this.extensions.length; i++)
    	t.add(this.extensions[i]);
    return t;
}


EAC2CVCertificateGenerator.prototype.getCertificateBody = function() {
	
    var t = new ASN1("Certificate Body", 0x7F4E);
    
    t.add(this.getProfileIdentifier());
    
    t.add(this.getCAR());
    
    t.add(this.getPublicKey());
    
    t.add(this.getCHR());
    
    t.add(this.getCHAT());
    
    t.add(this.getEffectiveDate());
    
    t.add(this.getExpiryDate());
    
    if (this.extensions) {
        t.add(this.getExtensions());
	}
	
    return t;
}


EAC2CVCertificateGenerator.prototype.setPublicKey = function(publicKey) {
	this.publicKey = publicKey;
}


/*
EAC2CVCertificateGenerator.prototype.generateCVCertificate = function(request) {
	
	// requestInfos = this.verifyRequest(request);
	
	var certificate = new ASN1("CV Certificate", 0x7F21);
	
	var body = this.getCertificateBody(requestInfos.publicKey);
    
	certificate.add(body);
	
	var signature = this.crypto.sign(this.privateKey, Crypto.ECDSA_SHA256, body.getBytes());
	var signatureValue = new ASN1("Signature", 0x5F37, signature);
	
    certificate.add(signatureValue);
	
    print(certificate);
	return certificate.getBytes();
}
*/


EAC2CVCertificateGenerator.prototype.generateCVCertificate = function(signingKey) {
	
	var certificate = new ASN1("CV Certificate", 0x7F21);
	
	var body = this.getCertificateBody();
	
	var signature = this.crypto.sign(signingKey, Crypto.ECDSA_SHA256, body.getBytes());
	var signatureValue = new ASN1("Signature", 0x5F37, signature);
	
    certificate.add(body);
    	
	certificate.add(signatureValue);
	
	// assert(crypto.verify(this.publicKey, Crypto.ECDSA_SHA256, body.getBytes(), signature));
		
    return certificate.getBytes();
}