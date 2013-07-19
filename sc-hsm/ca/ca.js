/**
 *  ---------
 * |.##> <##.|  SmartCard-HSM Support Scripts
 * |#       #|  
 * |#       #|  Copyright (c) 2011-2012 CardContact Software & System Consulting
 * |'##> <##'|  Andreas Schwier, 32429 Minden, Germany (www.cardcontact.de)
 *  --------- 
 *
 * Consult your license package for usage terms and conditions.
 *
 * @fileoverview A simple X.509 CA setup
 */
 
if (typeof(__ScriptingServer) == "undefined") {
	load("tools/pkcs8.js");
	load("tools/pkixcommon.js");
	load("tools/x509certificategenerator.js");
	load("tools/crlgenerator.js");
}



/**
 * Create a signer using a X.509 certificate
 *
 * @class Class implementing a signer having a X.509 certificate
 * @constructor
 * @param {Crypto} crypto the crypto provider
 */
function X509Signer(crypto) {
	this.crypto = crypto;
}



/**
 * Set the signer key object
 *
 * @param {Key} signerKey the signer key
 */
X509Signer.prototype.setSignerKey = function(signerKey) {
	this.signerKey = signerKey;
}



/**
 * Set the signer certificates
 *
 * @param{X509} signerCert the signer's certificate
 */
X509Signer.prototype.setSignerCertificate = function(signerCert) {
	this.signerCert = signerCert;
	this.signerSubject = new ASN1(signerCert.getNative().getSubjectX500Principal().getEncoded());
}



/**
 * Return the signer's certificate
 *
 * @type X509
 * @return the signer's certificate
 */
X509Signer.prototype.getSignerCertificate = function() {
	return this.signerCert;
}



/**
 * Create a certification authority that issues X.509 certificates and CRLs
 *
 * @class Class implementing a certification authority issuing X.509 certificates and CRLs
 * @constructor
 * @param {Crypto} crypto the crypto provider
 */
function X509CA(crypto) {
	X509Signer.call(this, crypto);
	this.crldp = [];
}

X509CA.prototype = new X509Signer();
X509CA.constructor = X509CA;



/**
 * Add a CRL distribution point to issued certificates
 *
 * @param {String} crldp the URL of the distribution point
 */
X509CA.prototype.addCRLDistributionPoint = function(crldp) {
	this.crldp.push(crldp);
}



/**
 * Create a new randomly generated certificate serial number
 *
 * @private
 * @type ByteString
 * @return a 8 byte bytestring that resembles an unsigned integer
 */
X509CA.prototype.newSerialNumber = function() {
	var crypto = new Crypto();
	var serial = crypto.generateRandom(8);

	// Strip first bit to make integer unsigned
	if (serial.byteAt(0) > 0x7F) {
		serial = ByteString.valueOf(serial.byteAt(0) & 0x7F).concat(serial.bytes(1));
	}
	return serial;
}



/**
 * Issuer a certificate
 *
 * @param {Key} publicKey the public key
 * @param {Object[]} subject an array of RDN objects in the form [ { C:"DE" }, { O:"CardContact" }, { OU:"CardContact Demo CA 1" }, { CN:"TLS client" } ]. 
 *			See pkixcommon.js for details
 * @param {String} profile an extension profile name for which a addExtFor<profile> method is defined. Predefined profiles are TLSServer, TLSClient and EmailAndTLSClient.
 * @param {Object} extvalues JSON object containing extension values
 * @type X509
 * @return the new X.509 certificate
 */
X509CA.prototype.issueCertificate = function(publicKey, subject, profile, extvalues) {

	var x = new X509CertificateGenerator(this.crypto);

	x.encodeECDomainParameter = false;
	x.reset();
	x.setSerialNumber(this.newSerialNumber());
	x.setSignatureAlgorithm(Crypto.RSA_SHA256);
	x.setIssuer(this.signerSubject);
	var ced = new Date();
	var cxd = PKIXCommon.addDays(ced, 1095); // 3 years
	x.setNotBefore(ced);
	x.setNotAfter(cxd);
	x.setSubject(subject);
	x.setPublicKey(publicKey);
	x.addSubjectKeyIdentifierExtension();
	x.addAuthorityKeyIdentifierExtension(this.signerCert.getPublicKey());
	x.addBasicConstraintsExtension(false);

	if (this.crldp.length > 0) {
		x.addCRLDistributionPointURL(this.crldp);
	}

	if (typeof(this["addExtFor" + profile]) == "function") {
		this["addExtFor" + profile](x, extvalues);
	}	
		
	return x.generateX509Certificate(this.signerKey);
}



/**
 * Extension handler method for TLS server certificates
 *
 * @private
 */
X509CA.prototype.addExtForTLSServer = function(certgen, extvalues) {
	
	certgen.addKeyUsageExtension( X509CertificateGenerator.keyAgreement |
								  X509CertificateGenerator.keyEncipherment);

	certgen.addExtendedKeyUsages(["id-csn-369791-tls-server", "id-kp-serverAuth"]);
	
	var ext = new ASN1("subjectAltName", ASN1.SEQUENCE,
						new ASN1("dNSName", 0x82, new ByteString(extvalues["dNSName"], ASCII))
					);
	certgen.addExtension("id-ce-subjectAltName", false, ext.getBytes());
}



/**
 * Extension handler method for TLS client certificates
 *
 * @private
 */
X509CA.prototype.addExtForTLSClient = function(certgen, extvalues) {
	certgen.addKeyUsageExtension( X509CertificateGenerator.digitalSignature);

	// certgen.addExtendedKeyUsages(["id-csn-369791-tls-client", "id-kp-clientAuth"]);
	certgen.addExtendedKeyUsages(["id-kp-clientAuth"]);
}



/**
 * Extension handler method for certificates suitable for TLS client authentication and e-Mail signature and encryption
 *
 * @private
 */
X509CA.prototype.addExtForEmailAndTLSClient = function(certgen, extvalues) {

	certgen.addKeyUsageExtension( X509CertificateGenerator.digitalSignature | X509CertificateGenerator.keyEncipherment);

//	print(extvalues.email);
	var ext = new ASN1("subjectAltName", ASN1.SEQUENCE,
						new ASN1("rfc822Name", 0x81, new ByteString(extvalues["email"], ASCII))
					);
	certgen.addExtension("id-ce-subjectAltName", false, ext.getBytes());

	certgen.addExtendedKeyUsages(["id-kp-clientAuth", "id-kp-emailProtection"]);
}



/**
 * Issue a CRL
 *
 * @type ByteString
 * @return the encoded CRL
 */
X509CA.prototype.issueCRL = function() {
	var x = new CRLGenerator(this.crypto);

	x.reset();
	x.setSignatureAlgorithm(Crypto.RSA_SHA256);
	x.setIssuer(this.signerSubject);
	var now = new Date();
	x.setThisUpdate(now);
	x.setNextUpdate(PKIXCommon.addDays(now, 10));

	var crl = x.generateCRL(this.signerKey);
	print("CRL:");
	print(crl);
	return crl.getBytes();
}



X509CA.dir = GPSystem.mapFilename("", GPSystem.CWD);



/**
 * Setup the CA instance
 */
X509CA.setup = function() {
	var crypto = new Crypto();
	
	var pubKey = new Key();
	pubKey.setSize(2048);
	pubKey.setType(Key.PUBLIC);

	var priKey = new Key();
	priKey.setType(Key.PRIVATE);

	crypto.generateKeyPair(Crypto.RSA, pubKey, priKey);
	
	var x = new X509CertificateGenerator(crypto);

	x.reset();
	x.setSerialNumber((new ByteString("02", HEX)).concat(crypto.generateRandom(7)));
	x.setSignatureAlgorithm(Crypto.RSA_SHA256);
	var subject = [ { C:"DE" }, { O:"CardContact" }, { CN:"CardContact Demo CA 1" } ];
	x.setIssuer(subject);
	var ced = new Date();
	var cxd = PKIXCommon.addDays(ced, 3650); // 10 years
	x.setNotBefore(ced);
	x.setNotAfter(cxd);
	x.setSubject(subject);
	x.setPublicKey(pubKey);
	x.addSubjectKeyIdentifierExtension();
	x.addAuthorityKeyIdentifierExtension(pubKey);
	x.addKeyUsageExtension(	PKIXCommon.keyCertSign |
							PKIXCommon.cRLSign );
	x.addBasicConstraintsExtension(true, 1);

	var cert = x.generateX509Certificate(priKey);
	print(cert);
	
	var ks = new KeyStore("SUN", "JKS");

	priKey.setID("DEMOCA");
	ks.setKey(priKey, "openscdp", [cert]);
	
	ks.store(X509CA.dir + "/DEMO-CA.jks", "openscdp");
}



/**
 * Test the CA setup
 */
X509CA.test = function() {
	var crypto = new Crypto();
	var ca = new X509CA(crypto);

	var ks = new KeyStore("SUN", "JKS", X509CA.dir + "/DEMO-CA.jks", "openscdp");
	var key = new Key();
	key.setID("DEMOCA");

	ks.getKey(key, "openscdp");
	ca.setSignerKey(key);

	var cert = ks.getCertificate("DEMOCA");
	ca.setSignerCertificate(cert);
	
	
	var subject = [ { C:"DE" }, { O:"CardContact" }, { OU:"CardContact Demo CA 1" }, { CN:"TLS server" } ];
	
	var pubKey = new Key();
	pubKey.setSize(2048);
	pubKey.setType(Key.PUBLIC);

	var priKey = new Key();
	priKey.setType(Key.PRIVATE);

	crypto.generateKeyPair(Crypto.RSA, pubKey, priKey);

	var extvalues = { dNSName: "www.openehic.org" };
	var cert = ca.issueCertificate(pubKey, subject, "TLSServer", extvalues);
	print(cert);
	
	var ks = new KeyStore("SUN", "JKS");

	priKey.setID("tlsserver");
	ks.setKey(priKey, "openscdp", [cert]);
	
	ks.store(X509CA.dir + "/www.openehic.org.jks", "openscdp");
	
	var p8Key = PKCS8.encodeKeyUsingPKCS8Format(priKey, pubKey);
	PKIXCommon.writeFileToDisk(X509CA.dir + "/www.openehic.org.pkcs8", p8Key);
	PKIXCommon.writeFileToDisk(X509CA.dir + "/www.openehic.org.cer", cert.getBytes());
	

	var subject = [ { C:"DE" }, { O:"CardContact" }, { OU:"CardContact Demo CA 1" }, { CN:"TLS client" } ];
	
	var pubKey = new Key();
	pubKey.setSize(2048);
	pubKey.setType(Key.PUBLIC);

	var priKey = new Key();
	priKey.setType(Key.PRIVATE);

	crypto.generateKeyPair(Crypto.RSA, pubKey, priKey);

	var cert = ca.issueCertificate(pubKey, subject, "TLSClient", null);
	print(cert);
	
	var ks = new KeyStore("SUN", "JKS");

	priKey.setID("tlsclient");
	ks.setKey(priKey, "openscdp", [cert]);
	
	ks.store(X509CA.dir + "/tlsclient.jks", "openscdp");
	
	var crl = ca.issueCRL();
	PKIXCommon.writeFileToDisk(X509CA.dir + "/democa.crl", crl);
}
