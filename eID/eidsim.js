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
 * @fileoverview A simple eID card simulation
 */

load("../cardsim/filesystem.js");
load("../cardsim/authenticationobject.js");
load("../cardsim/signaturekey.js");

load("eidcommandinterpreter.js");
load("../cardsim/securechannel.js");

load("../icao/pace.js");
load("../icao/chipauthentication.js");


var paceInfo = new PACEInfo();
paceInfo.protocol = new ByteString("id-PACE-ECDH-GM-AES-CBC-CMAC-128", OID);
paceInfo.version = 2;

var paceDomainParameterInfo = new PACEDomainParameterInfo();
paceDomainParameterInfo.protocol = new ByteString("id-PACE-ECDH-GM", OID);

var chipAuthenticationInfo = new ChipAuthenticationInfo();
chipAuthenticationInfo.protocol = new ByteString("id-CA-ECDH-AES-CBC-CMAC-128", OID);
chipAuthenticationInfo.version = 2;

var chipAuthenticationDomainParameterInfo = new PACEDomainParameterInfo();
chipAuthenticationDomainParameterInfo.protocol = new ByteString("id-CA-ECDH", OID);

var groupCAPrk = new Key("kp_prk_GroupCAKey.xml");
var groupCAPuk = new Key("kp_puk_GroupCAKey.xml");

var chipAuthenticationPublicKeyInfo = new ChipAuthenticationPublicKeyInfo();
chipAuthenticationPublicKeyInfo.protocol = new ByteString("id-PK-ECDH", OID);
chipAuthenticationPublicKeyInfo.algorithm = new ByteString("standardizedDomainParameter", OID);
chipAuthenticationPublicKeyInfo.standardizedDomainParameter = 0x0D;
chipAuthenticationPublicKeyInfo.publicKey = groupCAPuk;


var cardAccess = new ASN1(ASN1.SET,
							paceInfo.toTLV(),
							paceDomainParameterInfo.toTLV(),
							chipAuthenticationInfo.toTLV(),
							chipAuthenticationDomainParameterInfo.toTLV()
						);

var cardSecurity = new ASN1(ASN1.SET,
							paceInfo.toTLV(),
							paceDomainParameterInfo.toTLV(),
							chipAuthenticationInfo.toTLV(),
							chipAuthenticationDomainParameterInfo.toTLV(),
							chipAuthenticationPublicKeyInfo.toTLV()
						);

var dskey = new Key("kp_prk_DocSigner.xml");
var dscert = new X509("C_DocSigner.cer");

var gen = new CMSGenerator(CMSGenerator.TYPE_SIGNED_DATA);
gen.setDataContent(cardSecurity.getBytes());
gen.addSigner(dskey, dscert, new ByteString("id-sha256", OID), true);
var signedCardSecurity = gen.generate(new ByteString("id-SecurityObject", OID));

//print(new ASN1(signedCardSecurity));




/**
 * Create a card simulation object
 *
 * @class Class implementing a simple ISO 7816-4 card simulation
 * @constructor
 */
function eIDSimulation() {
	this.createFileSystem();
	this.initialize();
}



/**
 * Initialize card runtime
 */
eIDSimulation.prototype.createFileSystem = function() {
	this.mf = new DF(FCP.newDF("3F00", null),
						new TransparentEF(FCP.newTransparentEF("011C", 0x1C, 100), cardAccess.getBytes()),
						new TransparentEF(FCP.newTransparentEF("011D", 0x1D, 100), signedCardSecurity)
					);

	this.mf.addMeta("groupChipAuthenticationPrivateKey", groupCAPrk);
	this.mf.addMeta("groupChipAuthenticationPublicKey", groupCAPuk);
	this.mf.addMeta("groupChipAuthenticationInfo", chipAuthenticationInfo);
	this.mf.addMeta("paceInfo", paceInfo);

	var pacemrz = new AuthenticationObject("PACE_MRZ", AuthenticationObject.TYPE_PACE, 1, 
									new ByteString("BC5CED1FC3775214F8AD22EA86C37E86FD27F717", HEX));
	pacemrz.initialretrycounter = 0;
	this.mf.addObject(pacemrz);

	var pacecan = new AuthenticationObject("PACE_CAN", AuthenticationObject.TYPE_PACE, 2, 
									new ByteString("488444", ASCII));
	pacecan.initialretrycounter = 0;
	pacecan.allowResetRetryCounter = true;
	pacecan.allowResetValue = true;
	this.mf.addObject(pacecan);

	var pacepin = new AuthenticationObject("PACE_PIN", AuthenticationObject.TYPE_PACE, 3, 
									new ByteString("55555", ASCII));
	pacepin.isTransport = true;
	pacepin.allowActivate = true;
	pacepin.allowDeactivate = true;
	pacepin.allowResetRetryCounter = true;
	pacepin.allowResetValue = true;
	pacepin.unsuspendAuthenticationObject = pacecan;
	pacepin.unblockAuthenticationObject = pacepuk;
	this.mf.addObject(pacepin);

	var pacepuk = new AuthenticationObject("PACE_PUK", AuthenticationObject.TYPE_PACE, 4, 
									new ByteString("87654321", ASCII));
	pacecan.initialretrycounter = 0;
	this.mf.addObject(pacepuk);

	var dFeID = 		new DF(FCP.newDF("DF02", new ByteString("E80704007F00070302", HEX)),
							new TransparentEF(FCP.newTransparentEF("0101", 1, 100), 		// EF.DG1
								(new ASN1(0x61, new ASN1(ASN1.PrintableString, new ByteString("TP", ASCII)))).getBytes())
						);

	var dFeSign =		new DF(FCP.newDF("DF03", new ByteString("A000000167455349474E", HEX)),
							new TransparentEF(FCP.newTransparentEF("C000", 1, 2048)), 		// EF.C.ZDA.QES
							new TransparentEF(FCP.newTransparentEF("C001", 2, 2048)) 		// EF.C.ICC.QES
						);

	var signpin = new AuthenticationObject("PIN.QES", AuthenticationObject.TYPE_PIN, 1);
	signpin.isTerminated = true;
	signpin.allowTerminate = true;
	signpin.allowResetRetryCounter = true;
	signpin.allowResetValue = true;
	signpin.allowChangeReferenceData = true;
	signpin.unblockAuthenticationObject = pacepuk;
	dFeSign.addObject(signpin);

	var signaturekey = new SignatureKey("PrK.QES", 4);
	dFeSign.addObject(signaturekey);

	this.mf.add(dFeID);
	this.mf.add(dFeSign);

	print(this.mf.dump(""));
}


/**
 * Initialize card runtime
 */
eIDSimulation.prototype.initialize = function() {
	this.fileSelector = new FileSelector(this.mf);
	this.commandInterpreter = new eIDCommandInterpreter(this.fileSelector);
}



/**
 * Process an inbound APDU
 *
 * @param {ByteString} capdu the command APDU
 * @type ByteString
 * @return the response APDU
 */ 
eIDSimulation.prototype.processAPDU = function(capdu) {
	print("Command APDU : " + capdu);

	var apdu;
	
	try	{
		apdu = new APDU(capdu);
	}
	catch(e) {
		GPSystem.trace(e);
		var sw = APDU.SW_GENERALERROR;
		if (e instanceof GPError) {
			sw = e.reason;
		}
		var bb = new ByteBuffer();
		bb.append(sw >> 8);
		bb.append(sw & 0xFF);
		return bb.toByteString();
	}

	this.commandInterpreter.processAPDU(apdu);
	
	var rapdu = apdu.getResponseAPDU();
	print("Response APDU: " + rapdu);
	return rapdu;
}



/**
 * Respond to reset request
 *
 * @param {Number} type reset type (One of Card.RESET_COLD or Card.RESET.WARM)
 * @type ByteString
 * @return answer to reset
 */
eIDSimulation.prototype.reset = function(type) {
	print("Reset type: " + type);

	this.initialize();

	var atr = new ByteString("3B600000", HEX);
	return atr;
}



/**
 * Create new simulation and register with existing or newly created adapter singleton.
 *
 */
eIDSimulation.newInstance = function() {
	var sim = new eIDSimulation();

	if (typeof(CARDSIM) == "undefined") {
		var adapter = new CardSimulationAdapter("JCOPSimulation", "8050");
		adapter.setSimulationObject(sim);
		adapter.start();
		CARDSIM = adapter;
		print("Simulation running...");
	} else {
		CARDSIM.setSimulationObject(sim);
		print("Simulation replaced...");
	}
}



eIDSimulation.newInstance();
