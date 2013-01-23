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
 * @fileoverview TrustAnchor Based class for card verifiable certificate based access controller
 */

 
/**
 * Create a TrustAnchor object that handles certificate validation, terminal authentication and access control
 *
 * @constructor
 * @class Class implementing a CVC based access controller
 * @param {CVC} root the root certificate
 */
function TrustAnchor(root) {
	if (typeof(root) == "undefined") {
		return;
	}

	this.root = root;

	// Save in file system under id, which is the last byte in the CHAT OID
	var chat = root.getCHAT();
	var id = chat.get(0).value.right(1).toUnsigned();
	var name = root.getCHR().getHolder();		// Use the name of the CVCA
	FileSystemIdObject.call(this, name, id);
}

TrustAnchor.prototype = new FileSystemIdObject();
TrustAnchor.prototype.constructor = TrustAnchor;

TrustAnchor.TYPE = "TrustAnchor";



TrustAnchor.prototype.getType = function() {
	return TrustAnchor.TYPE;
}



TrustAnchor.prototype.isIssuer = function(chr) {
	return this.root.getCHR().toString() == chr;
}



TrustAnchor.prototype.getPublicKeyFor = function(chr) {
	return this.root.getPublicKey();
}



TrustAnchor.prototype.getCertificateFor = function(chr) {
	return this.root;
}



TrustAnchor.prototype.checkCertificate = function(issuer, subject) {
	var chatissuer = issuer.getCHAT();
	var chatsubject = subject.getCHAT();
	
	if (!chatissuer.get(0).value.equals(chatsubject.get(0).value)) {
		throw new GPError("TrustAnchor", GPError.INVALID_DATA, APDU.SW_INVDATA, "Role mismatch");
	}

	rightsissuer = chatissuer.get(1).value;
	rightssubject = chatsubject.get(1).value;
	
	if (rightsissuer.length != rightssubject.length) {
		throw new GPError("TrustAnchor", GPError.INVALID_DATA, APDU.SW_INVDATA, "Different size in rights mask of chat");
	}

	typeissuer = rightsissuer.byteAt(0) & 0xC0;
	typesubject = rightssubject.byteAt(0) & 0xC0;

	// C0 - CVCA, 80 - DV domestic, 40 - DV foreign, 00 - Terminal
	if (typeissuer == 0x40) {		// Ignore domestic and foreign
		typeissuer = 0x80;
	}
	if (typesubject == 0x40) {
		typesubject = 0x80;
	}
//	print("issuer " + typeissuer);
//	print("subject " + typesubject);
	
	if (((typesubject >= typeissuer) && (typeissuer != 0xC0)) || 
		((typesubject == 0x00) && (typeissuer == 0xC0))) {
		throw new GPError("TrustAnchor", GPError.INVALID_DATA, APDU.SW_INVDATA, "Certificate hierachie invalid");
	}
	
	if (!issuer.getPublicKeyOID().equals(subject.getPublicKeyOID())) {
		throw new GPError("TrustAnchor", GPError.INVALID_DATA, APDU.SW_INVDATA, "Public key algorithm mismatch");
	}
}



TrustAnchor.prototype.validateCertificateIssuedByCVCA = function(crypto, cert) {
	cc = this.getCertificateFor(cert.getCAR());
	puk = this.getPublicKeyFor(cert.getCAR());
	if (!cert.verifyWith(crypto, puk, cc.getPublicKeyOID())) {
		throw new GPError("TrustAnchor", GPError.INVALID_DATA, APDU.SW_INVDATA, "Could not verify certificate signature");
	}
	this.checkCertificate(cc, cert);
}



TrustAnchor.prototype.validateCertificateIssuedByDVCA = function(crypto, cert, dvca) {
	var dp = this.getPublicKeyFor(dvca.getCAR());
	if (!cert.verifyWith(crypto, dvca.getPublicKey(dp), dvca.getPublicKeyOID())) {
		throw new GPError("TrustAnchor", GPError.INVALID_DATA, APDU.SW_INVDATA, "Could not verify certificate signature");
	}
	this.checkCertificate(dvca, cert);
}



function TrustAnchorIS(root) {
	TrustAnchor.call(this, root);
}

TrustAnchorIS.prototype = new TrustAnchor();
TrustAnchorIS.prototype.constructor = TrustAnchor;



function TrustAnchorAT(root) {
	TrustAnchor.call(this, root);
}

TrustAnchorAT.prototype = new TrustAnchor();
TrustAnchorAT.prototype.constructor = TrustAnchor;



function TrustAnchorST(root) {
	TrustAnchor.call(this, root);
}

TrustAnchorST.prototype = new TrustAnchor();
TrustAnchorST.prototype.constructor = TrustAnchor;
