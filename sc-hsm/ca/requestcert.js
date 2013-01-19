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
 * @fileoverview Obtain a certificate from an online ca service
 */

load("../lib/smartcardhsm.js");
load("../lib/hsmkeystore.js");
 
// var url = "http://localhost:8080/se/caws";
var url = "http://devnet.cardcontact.de/se/caws";

var userPIN = new ByteString("648219", ASCII);
var initializationCode = new ByteString("57621880", ASCII);



/**
 * Creates a web service connector to access an online CA
 *
 * @class Class implementing a CA web service connector
 * @constructor
 * @param {String} url the web service endpoint
 */
function CAConnection(url) {
	this.url = url;
	this.soapcon = new SOAPConnection();
	this.verbose = true;
	this.lastReturnCode = null;
}



/**
 * Get the last return code
 *
 * @returns the last return code received or null if none defined
 * @type String
 */
CAConnection.prototype.getLastReturnCode = function() {
	return this.lastReturnCode;
}



/**
 * Gets the last request
 *
 * @returns the last request
 * @type XML
 */
CAConnection.prototype.getLastRequest = function() {
	return this.request;
}



/**
 * Gets the last response
 *
 * @returns the last response
 * @type XML
 */
CAConnection.prototype.getLastResponse = function() {
	return this.response;
}



/**
 * Close the connector and release allocated resources
 */
CAConnection.prototype.close = function() {
	this.soapcon.close();
}



/**
 * Request a certificate from the CA using a web service
 *
 * @param {ByteString} certreq the certificate request
 * @param {String} messageID the messageID for asynchronous requests (optional)
 * @param {String} responseURL the URL to which the asynchronous response is send (optional)
 * @returns the new certificates
 * @type ByteString[]
 */
CAConnection.prototype.requestCertificate = function(certreq, devicecert, commonName, eMailAddress, activationCode) {

	this.lastReturnCode = null;

	var soapConnection = new SOAPConnection();

	var ns = new Namespace("http://www.openscdp.org/CAService");

	var request =
		<ns:RequestCertificate xmlns:ns={ns}>
			<CertificateSigningRequest>{certreq.toString(BASE64)}</CertificateSigningRequest>
			<DeviceCertificate>{devicecert.toString(BASE64)}</DeviceCertificate>
			<CommonName>{commonName}</CommonName>
			<eMailAddress>{eMailAddress}</eMailAddress>
		</ns:RequestCertificate>

	if (activationCode) {
		request.eMailAddress += <ActivationCode>{activationCode}</ActivationCode>;
	}

	if (this.verbose) {
		GPSystem.trace(request.toXMLString());
	}

	this.request = request;

	try	{
		var response = this.soapcon.call(this.url, request);
		if (this.verbose) {
			GPSystem.trace(response.toXMLString());
		}
	}
	catch(e) {
		GPSystem.trace("SOAP call to " + this.url + " failed : " + e);
		throw new GPError("CAConnection", GPError.DEVICE_ERROR, 0, "RequestCertificate failed with : " + e);
	}
	
	this.response = response;

	var certlist = [];

	this.lastReturnCode = response.ReturnCode.toString();
	
	if (this.lastReturnCode != "ok") {
		return null;
	}
	
	GPSystem.trace("Received certificates:");
	for each (var c in response.Certificates.Certificate) {
		var cert = new ByteString(c, BASE64);
		certlist.push(cert);
		GPSystem.trace(cert);
	}

	return certlist;
}



 
// Use default crypto provider
var crypto = new Crypto();

// Create card access object
var card = new Card(_scsh3.reader);

card.reset(Card.RESET_COLD);

// Create SmartCard-HSM card service
var sc = new SmartCardHSM(card);

// Check if device is yet un-initialized
if (sc.queryUserPINStatus() == 0x6984) {
	var page = "<html><p><b>Warning:</b></p><br/>" + 
			   "<p>This is a new device that has never been initialized before.</p><br/>" + 
			   "<p>If you choose to continue, then the device initialization code will be set to " + initializationCode.toString(HEX) + "</p><br/>" + 
			   "<p>Please be advised, that this code can not be changed once set. The same code must be used in subsequent re-initialization of the device.</p><br/>" + 
			   "<p>Press OK to continue or Cancel to abort.</p>" + 
			   "</html>";
	var userAction = Dialog.prompt(page);
	assert(userAction != null);

	var userPIN = Dialog.prompt("Please select user PIN for SmartCard-HSM", "648219");
	assert(userPIN != null);

	sc.initDevice(new ByteString("0001", HEX), userPIN, initializationCode, 3);
} else {
	var userPIN = Dialog.prompt("Please enter user PIN for SmartCard-HSM", "648219");
	assert(userPIN != null);

	// Verify user PIN
	sc.verifyUserPIN(new ByteString(userPIN, ASCII));
}

var url = Dialog.prompt("Please enter URL of Online CA", url);
assert(url != null);

var label = url.match(/\w+:\/\/([\w.]+)/)[1];
print("Using label \"" + label + "\" for key");

var commonName = "Joe Doe";
var commonName = Dialog.prompt("Please enter name or pseudonym for entry into the common name field of the certificate", commonName);
assert(commonName != null);

var eMailAddress = " joe.doe@openscdp.org";

do	{
	var eMailAddress = Dialog.prompt("Please enter a valid e-mail address for entry into the subjectAlternativeName field of the certificate", eMailAddress);
	assert(eMailAddress != null);
} while (eMailAddress.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+/)[0] != eMailAddress);

if (eMailAddress.length > 0) {
	print("The CA will send an activation code to " + eMailAddress);
}

var hsmks = new HSMKeyStore(sc);

sc.enumerateKeys();
var key = sc.getKey(label);

if (key) {
	assert(Dialog.prompt("A key with the label " + label + " already exists. Press OK to delete the key"));
	hsmks.deleteKey(label);
}

print("Generating a 2048 bit RSA key pair can take up to 60 seconds. Please wait...");
var req = hsmks.generateRSAKeyPair(label, 2048);

var devAutCert = sc.readBinary(SmartCardHSM.C_DevAut);

var activationCode;

do	{
	var cacon = new CAConnection(url);
	var certs = cacon.requestCertificate(req.getBytes(), devAutCert, commonName, eMailAddress, activationCode);
	cacon.close();

	if (certs == null) {
		var rc = cacon.getLastReturnCode();
		if (rc == "activation_code_wrong") {
			assert(Dialog.prompt("Wrong activation code - Press OK to retry"));
		}
		if ((rc == "activation_code_required") || (rc == "activation_code_wrong")) {
			activationCode = Dialog.prompt("Please check your e-mail and enter activation code", "");
			assert(activationCode != null);
		} else {
			print("Online CA returned " + cacon.getLastReturnCode());
			break;
		}
	} else {
		var cert = new X509(certs[0]);
		print(cert);
		print("Received certificate from CA, now storing it on the device...");
		hsmks.storeEndEntityCertificate(label, cert);
	}
} while (!certs);
