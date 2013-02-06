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
 * @fileoverview TrustAnchor Base class for card verifiable certificate based access controller
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

	this.chain = [];
	this.chain.push(root);

	// Save in file system under id, which is the last byte in the CHAT OID
	var chat = root.getCHAT();
	var id = chat.get(0).value.right(1).toUnsigned();
	var name = root.getCHR().getHolder();		// Use the name of the CVCA
	FileSystemIdObject.call(this, name, id);
}

TrustAnchor.prototype = new FileSystemIdObject();
TrustAnchor.prototype.constructor = TrustAnchor;

TrustAnchor.TYPE = "TrustAnchor";
TrustAnchor.idIS = new ByteString("id-IS", OID);



/**
 * Return type of file system object
 *
 * @type String
 * @return the type string
 */
TrustAnchor.prototype.getType = function() {
	return TrustAnchor.TYPE;
}




/**
 * Add recent trust anchor to PACE response
 *
 * @param {ASN1} response the response object to receive tag 87 and 88
 */
TrustAnchor.prototype.addCARforPACE = function(response) {
	var cl = this.chain.length;
	response.add(new ASN1(0x87, this.chain[cl - 1].getCHR().getBytes()));
	if (cl > 1) {
		response.add(new ASN1(0x88, this.chain[cl - 2].getCHR().getBytes()));
	}
}



/**
 * Is a recent trust anchor issuer of the certificate chr in question
 *
 * @param {PublicKeyReference} chr the certificate holder
 * @type boolean
 * @return true if trust anchor issued certificate
 */
TrustAnchor.prototype.isIssuer = function(chr) {
	var cvc = this.getCertificateFor(chr);
//	print("isIssuer(" + chr + "):");
//	print(cvc);
	return cvc != null;
}



/**
 * Get public key from certificate, possibly determine the domain parameter from previous trust anchors
 *
 * @param {PublicKeyReference} chr the certificate holder
 * @type Key
 * @return the public key or null
 */
TrustAnchor.prototype.getPublicKeyFor = function(chr) {
//	print("Get public key for " + chr);
	var cl = this.chain.length - 1;
	for (; (cl >= 0) && !this.chain[cl].getCHR().equals(chr); cl--) {
	}

	if (cl < 0) {
//		print("chr not found");
		return null;
	}

	var i = cl;
	if (CVC.isECDSA(this.chain[cl].getPublicKeyOID()) && !this.chain[i].containsDomainParameter()) {
//		print("Looking for DPs down the chain");
		for (cl--; (cl >= 0) && !this.chain[cl].containsDomainParameter(); cl--) {}
		if (cl < 0) {
			return null;
		}
//		print("Found domain parameter in " + this.chain[cl]);
		var dp = this.chain[cl].getPublicKey();
		return this.chain[i].getPublicKey(dp);
	} else {
//		print(this.chain[i]);
		return this.chain[i].getPublicKey();
	}
}



/**
 * Return certificate for chr
 *
 * @param {PublicKeyReference} chr the certificate holder
 * @type CVC
 * @return the certificate or null
 */
TrustAnchor.prototype.getCertificateFor = function(chr) {
	var cl = this.chain.length;
	if (this.chain[cl - 1].getCHR().toString() == chr) {
		return this.chain[cl - 1];
	}
	if (cl > 1) {
		if (this.chain[cl - 2].getCHR().toString() == chr) {
			return this.chain[cl - 2];
		}
	}
	return null;
}



/**
 * Update EF.CVCA with list of valid trust anchors
 *
 * @param {Object} dataProvider object implementing getDate(), setDate() and updateEFCVCA()
 */
TrustAnchor.prototype.updateEFCVCA = function(dataProvider) {
	var cl = this.chain.length - 1;
	var bb = new ByteBuffer();
	bb.append((new ASN1(0x42, this.chain[cl].getCHR().getBytes())).getBytes());
	if (cl > 0) {
		bb.append((new ASN1(0x42, this.chain[cl - 1].getCHR().getBytes())).getBytes());
	}
	bb.append(0);
	dataProvider.updateEFCVCA(bb.toByteString());
}



/**
 * Check certificate
 *
 * <p>This method updates the current date for certificates issued by domestic DVCAs.</p>
 * @param {CVC} issuer the issuing certificate
 * @param {CVC} subject the subjects certificate
 * @param {Object} dataProvider object implementing getDate(), setDate() and updateEFCVCA()
 */
TrustAnchor.prototype.checkCertificate = function(issuer, subject, dataProvider) {
	var chatissuer = issuer.getCHAT();
	var chatsubject = subject.getCHAT();
	
	var rolesubject = chatsubject.get(0).value;
	if (!chatissuer.get(0).value.equals(rolesubject)) {
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

	var date = dataProvider.getDate().valueOf();
	if (typesubject != 0xC0) {			// CVCA certificates do not expire
		if (subject.getCXD().valueOf() < date) {
			throw new GPError("TrustAnchor", GPError.INVALID_DATA, APDU.SW_INVDATA, "Certificate is expired");
		}
	} else {
		print("Add to chain: " + subject);
		this.chain.push(subject);							// Add new CVCA link to the chain
		if (rolesubject.equals(TrustAnchor.idIS)) {
			this.updateEFCVCA(dataProvider);					// Update /DF.ePass/EF.CVCA
		}
	}

	if ((rightsissuer.byteAt(0) & 0xC0) != 0x40) {			// Trust all except foreign DVCAs
		if (subject.getCED().valueOf() > date) {
			dataProvider.setDate(subject.getCED());
		}
	}
}



/**
 * Validate certificate issued by CVCA
 *
 * @param {Crypto} crypto the crypto object to use for verification
 * @param {CVC} cert the certificate to validate
 * @param {Object} dataProvider object implementing getDate(), setDate() and updateEFCVCA()
 */
TrustAnchor.prototype.validateCertificateIssuedByCVCA = function(crypto, cert, dataProvider) {
	cc = this.getCertificateFor(cert.getCAR());
	puk = this.getPublicKeyFor(cert.getCAR());
	if (!puk || !cert.verifyWith(crypto, puk, cc.getPublicKeyOID())) {
		throw new GPError("TrustAnchor", GPError.INVALID_DATA, APDU.SW_INVDATA, "Could not verify certificate signature");
	}
	this.checkCertificate(cc, cert, dataProvider);
}



/**
 * Validate certificate issued by CVCA
 *
 * @param {Crypto} crypto the crypto object to use for verification
 * @param {CVC} cert the certificate to validate
 * @param {CVC} dvca the issuing certificate
 * @param {Object} dataProvider object implementing getDate(), setDate() and updateEFCVCA()
 */
TrustAnchor.prototype.validateCertificateIssuedByDVCA = function(crypto, cert, dvca, dataProvider) {
	var dp = this.getPublicKeyFor(dvca.getCAR());
//	print(dp);
	if (!dp || !cert.verifyWith(crypto, dvca.getPublicKey(dp), dvca.getPublicKeyOID())) {
		throw new GPError("TrustAnchor", GPError.INVALID_DATA, APDU.SW_INVDATA, "Could not verify certificate signature");
	}
	this.checkCertificate(dvca, cert, dataProvider);
}
