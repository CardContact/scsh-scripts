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
 * @fileoverview An eID card simulation
 */

load("tools/file.js");

load("../cardsim/filesystem.js");
load("../cardsim/authenticationobject.js");
load("../cardsim/trustanchor.js");
load("../cardsim/signaturekey.js");

load("eidcommandinterpreter.js");
load("eidaccesscontroller.js");
load("../cardsim/securechannel.js");

load("../icao/cvc.js");
load("../icao/pace.js");
load("../icao/chipauthentication.js");
load("../icao/restrictedidentification.js");



var paceInfo = new PACEInfo();
paceInfo.protocol = new ByteString("id-PACE-ECDH-GM-AES-CBC-CMAC-128", OID);
paceInfo.version = 2;
paceInfo.parameterId = 13;

var chipAuthenticationInfo = new ChipAuthenticationInfo();
chipAuthenticationInfo.protocol = new ByteString("id-CA-ECDH-AES-CBC-CMAC-128", OID);
chipAuthenticationInfo.version = 2;
chipAuthenticationInfo.keyId = 16;

var privChipAuthenticationInfo = new ChipAuthenticationInfo();
privChipAuthenticationInfo.protocol = new ByteString("id-CA-ECDH-AES-CBC-CMAC-128", OID);
privChipAuthenticationInfo.version = 2;
privChipAuthenticationInfo.keyId = 17;

var chipAuthenticationInfoDG14 = new ChipAuthenticationInfo();
chipAuthenticationInfoDG14.protocol = new ByteString("id-CA-ECDH-3DES-CBC-CBC", OID);
chipAuthenticationInfoDG14.version = 1;

var chipAuthenticationDomainParameterInfo = new ChipAuthenticationDomainParameterInfo();
chipAuthenticationDomainParameterInfo.protocol = new ByteString("id-CA-ECDH", OID);
chipAuthenticationDomainParameterInfo.standardizedDomainParameter = 13;
chipAuthenticationDomainParameterInfo.keyId = 16;

var privChipAuthenticationDomainParameterInfo = new ChipAuthenticationDomainParameterInfo();
privChipAuthenticationDomainParameterInfo.protocol = new ByteString("id-CA-ECDH", OID);
privChipAuthenticationDomainParameterInfo.standardizedDomainParameter = 13;
privChipAuthenticationDomainParameterInfo.keyId = 17;

var groupCAPrk = new Key("kp_prk_GroupCAKey.xml");
var groupCAPuk = new Key("kp_puk_GroupCAKey.xml");

var chipAuthenticationPublicKeyInfo = new ChipAuthenticationPublicKeyInfo();
chipAuthenticationPublicKeyInfo.protocol = new ByteString("id-PK-ECDH", OID);
chipAuthenticationPublicKeyInfo.algorithm = new ByteString("standardizedDomainParameter", OID);
chipAuthenticationPublicKeyInfo.standardizedDomainParameter = 13;
chipAuthenticationPublicKeyInfo.publicKey = groupCAPuk;
chipAuthenticationPublicKeyInfo.keyId = 16;

var chipAuthenticationPublicKeyInfoDG14 = new ChipAuthenticationPublicKeyInfo();
chipAuthenticationPublicKeyInfoDG14.protocol = new ByteString("id-PK-ECDH", OID);
chipAuthenticationPublicKeyInfoDG14.algorithm = new ByteString("id-ecPublicKey", OID);
chipAuthenticationPublicKeyInfoDG14.publicKey = groupCAPuk;

var chipCAPrk = new Key("kp_prk_UniqueCAKey.xml");
var chipCAPuk = new Key("kp_puk_UniqueCAKey.xml");

var privChipAuthenticationPublicKeyInfo = new ChipAuthenticationPublicKeyInfo();
privChipAuthenticationPublicKeyInfo.protocol = new ByteString("id-PK-ECDH", OID);
privChipAuthenticationPublicKeyInfo.algorithm = new ByteString("standardizedDomainParameter", OID);
privChipAuthenticationPublicKeyInfo.standardizedDomainParameter = 13;
privChipAuthenticationPublicKeyInfo.publicKey = chipCAPuk;
privChipAuthenticationPublicKeyInfo.keyId = 17;

var terminalAuthenticationInfo = new ASN1("terminalAuthenticationInfo", ASN1.SEQUENCE,
										new ASN1("protocol", ASN1.OBJECT_IDENTIFIER, new ByteString("id-TA", OID)),
										new ASN1("version", ASN1.INTEGER, ByteString.valueOf(2))
									);

var terminalAuthenticationInfoDG14 = new ASN1("terminalAuthenticationInfo", ASN1.SEQUENCE,
										new ASN1("protocol", ASN1.OBJECT_IDENTIFIER, new ByteString("id-TA", OID)),
										new ASN1("version", ASN1.INTEGER, ByteString.valueOf(1))
									);

var restrictedIdentificationDomainParameterInfo = new RestrictedIdentificationDomainParameterInfo();
restrictedIdentificationDomainParameterInfo.protocol = new ByteString("id-RI-ECDH", OID);
restrictedIdentificationDomainParameterInfo.standardizedDomainParameter = 13;

var rIKeys = [];

var restrictedIdentificationRecovation = new RestrictedIdentificationInfo();
restrictedIdentificationRecovation.protocol = new ByteString("id-RI-ECDH-SHA-256", OID);
restrictedIdentificationRecovation.version = 1;
restrictedIdentificationRecovation.keyId = 0x8;
restrictedIdentificationRecovation.authorizedOnly = false;

var riKey = new Key("kp_prk_RevocationKey.xml");
rIKeys[restrictedIdentificationRecovation.keyId] = {
	prk: riKey,
	authorizedOnly: false
};


var restrictedIdentificationSector = new RestrictedIdentificationInfo();
restrictedIdentificationSector.protocol = new ByteString("id-RI-ECDH-SHA-256", OID);
restrictedIdentificationSector.version = 1;
restrictedIdentificationSector.keyId = 0x9;
restrictedIdentificationSector.authorizedOnly = true;

var riKey = new Key("kp_prk_IDKey.xml");
rIKeys[restrictedIdentificationSector.keyId] = {
	prk: riKey,
	authorizedOnly: true
};

var ciInfo = 	new ASN1(ASN1.SEQUENCE,
					new ASN1(ASN1.OBJECT_IDENTIFIER, new ByteString("id-CI", OID)),
					new ASN1(ASN1.IA5String, new ByteString("http://www.openscdp.org/eID/eID.xml", ASCII))
				);


var cardAccess = new ASN1(ASN1.SET,
							terminalAuthenticationInfo,
							chipAuthenticationInfo.toTLV(),
							paceInfo.toTLV(),
							chipAuthenticationDomainParameterInfo.toTLV(),
							ciInfo,
							new ASN1(ASN1.SEQUENCE,
								new ASN1(ASN1.OBJECT_IDENTIFIER, new ByteString("id-PT", OID)),
								new ASN1(ASN1.SET,
									privChipAuthenticationInfo.toTLV(),
									privChipAuthenticationDomainParameterInfo.toTLV()
								)
							)
						);
print("CardAccess:");
print(cardAccess);

var cardSecurity = new ASN1(ASN1.SET,
							terminalAuthenticationInfo,
							chipAuthenticationInfo.toTLV(),
							paceInfo.toTLV(),
							restrictedIdentificationRecovation.toTLV(),
							restrictedIdentificationSector.toTLV(),
							restrictedIdentificationDomainParameterInfo.toTLV(),
							chipAuthenticationDomainParameterInfo.toTLV(),
							ciInfo,
							chipAuthenticationPublicKeyInfo.toTLV()
						);
print("CardSecurity:");
print(cardSecurity);

var chipSecurity = new ASN1(ASN1.SET,
							terminalAuthenticationInfo,
							privChipAuthenticationInfo.toTLV(),
							paceInfo.toTLV(),
							restrictedIdentificationRecovation.toTLV(),
							restrictedIdentificationSector.toTLV(),
							restrictedIdentificationDomainParameterInfo.toTLV(),
							privChipAuthenticationDomainParameterInfo.toTLV(),
							ciInfo,
							privChipAuthenticationPublicKeyInfo.toTLV()
						);
print("ChipSecurity:");
print(chipSecurity);

var dg14 = new ASN1(0x64,
					new ASN1(ASN1.SET,
							terminalAuthenticationInfoDG14,
							chipAuthenticationInfoDG14.toTLV(),
							chipAuthenticationPublicKeyInfoDG14.toTLV()
						)
				);


var dskey = new Key("kp_prk_DocSigner.xml");
var dscert = new X509("C_DocSigner.cer");

var gen = new CMSGenerator(CMSGenerator.TYPE_SIGNED_DATA);
gen.setDataContent(cardSecurity.getBytes());
gen.addSigner(dskey, dscert, new ByteString("id-sha256", OID), true);
var signedCardSecurity = gen.generate(new ByteString("id-SecurityObject", OID));
//print(new ASN1(signedCardSecurity));

var gen = new CMSGenerator(CMSGenerator.TYPE_SIGNED_DATA);
gen.setDataContent(chipSecurity.getBytes());
gen.addSigner(dskey, dscert, new ByteString("id-sha256", OID), true);
var signedChipSecurity = gen.generate(new ByteString("id-SecurityObject", OID));
//print(new ASN1(signedChipSecurity));


// Load root certificates
var f = new File(GPSystem.mapFilename("cvc/UTISCVCA/UTISCVCA00001.selfsigned.cvcert", GPSystem.CWD));
var c = new CVC(f.readAllAsBinary());
print(c);
var currentDate = c.getCED();
var cvcis = new TrustAnchor(c);

var f = new File(GPSystem.mapFilename("cvc/UTATCVCA/UTATCVCA00001.selfsigned.cvcert", GPSystem.CWD));
var c = new CVC(f.readAllAsBinary());
print(c);
var cvcat = new TrustAnchor(c);

var f = new File(GPSystem.mapFilename("cvc/UTSTCVCA/UTSTCVCA00001.selfsigned.cvcert", GPSystem.CWD));
var c = new CVC(f.readAllAsBinary());
print(c);
var cvcst = new TrustAnchor(c);





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
						new TransparentEF(FCP.newTransparentEF("011D", 0x1D, 100), signedCardSecurity),
						new TransparentEF(FCP.newTransparentEF("011B", 0x1B, 100), signedChipSecurity)
					);

	this.mf.addMeta("accessController", new MFAccessController());
	this.mf.addMeta("groupChipAuthenticationPrivateKey", groupCAPrk);
	this.mf.addMeta("groupChipAuthenticationPublicKey", groupCAPuk);
	this.mf.addMeta("groupChipAuthenticationInfo", chipAuthenticationInfo);
	this.mf.addMeta("uniqueChipAuthenticationPrivateKey", chipCAPrk);
	this.mf.addMeta("uniqueChipAuthenticationPublicKey", chipCAPuk);
	this.mf.addMeta("uniqueChipAuthenticationInfo", privChipAuthenticationInfo);

	this.mf.addMeta("paceInfo", paceInfo);
	this.mf.addMeta("idPICC", new ByteString("YV30003670", ASCII));
	this.mf.addObject(cvcis);
	this.mf.addObject(cvcat);
	this.mf.addObject(cvcst);
	this.mf.addMeta("currentDate", { currentDate: currentDate} );

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
	pacepin.minLength = 6;
	pacepin.unsuspendAuthenticationObject = pacecan;
	this.mf.addObject(pacepin);

	var pacepuk = new AuthenticationObject("PACE_PUK", AuthenticationObject.TYPE_PACE, 4, 
									new ByteString("87654321", ASCII));
	pacecan.initialretrycounter = 0;
	this.mf.addObject(pacepuk);

	pacepin.unblockAuthenticationObject = pacepuk;

	var efCVCA = new TransparentEF(FCP.newTransparentEF("011C", 0x1C, 100),		// EF.CVCA
								(new ASN1(0x42, new ByteString("UTISCVCA00001", ASCII))).getBytes().concat(new ByteString("00", HEX)));

	this.mf.addMeta("efCVCA", efCVCA);

	var dFePass = 		new DF(FCP.newDF(null, new ByteString("A0000002471001", HEX)),
							new TransparentEF(FCP.newTransparentEF("011E", 0x1E, 100),		// EF.COM
								new ByteString("60175f0104303130375f36063034303030305c056175676b6c", HEX)),
							new TransparentEF(FCP.newTransparentEF("011D", 0x1D, 100),		// EF.SOD
								new ByteString("60175f0104303130375f36063034303030305c056175676b6c", HEX)),
							new TransparentEF(FCP.newTransparentEF("0101", 0x01, 100),		// EF.DG1
								new ByteString("60175f0104303130375f36063034303030305c056175676b6c", HEX)),
							new TransparentEF(FCP.newTransparentEF("0102", 0x02, 100),		// EF.DG2
								new ByteString("60175f0104303130375f36063034303030305c056175676b6c", HEX)),
							new TransparentEF(FCP.newTransparentEF("0103", 0x03, 100),		// EF.DG3
								new ByteString("60175f0104303130375f36063034303030305c056175676b6c", HEX)),
							new TransparentEF(FCP.newTransparentEF("0104", 0x04, 100),		// EF.DG4
								new ByteString("60175f0104303130375f36063034303030305c056175676b6c", HEX)),
							new TransparentEF(FCP.newTransparentEF("010E", 0x0E, 100),		// EF.DG14
								dg14.getBytes()),
							efCVCA
						);

	dFePass.addMeta("accessController", new ePassAccessController());
	
	var k_enc_bac = new Key();
	k_enc_bac.setComponent(Key.DES, new ByteString("46D05FA43C0D9ABB95F02C7EFFE22755", HEX));
	dFePass.addMeta("KENC", k_enc_bac);

	var k_mac_bac = new Key();
	k_mac_bac.setComponent(Key.DES, new ByteString("F0B777EDB5CAF9B6E849842C77607098", HEX));
	dFePass.addMeta("KMAC", k_mac_bac);

	dFePass.addMeta("chipAuthenticationPrivateKey", groupCAPrk);
	dFePass.addMeta("chipAuthenticationPublicKey", groupCAPuk);
	dFePass.addMeta("chipAuthenticationInfo", chipAuthenticationInfoDG14);


	var dFeID = 		new DF(FCP.newDF(null, new ByteString("E80704007F00070302", HEX)),
							new TransparentEF(FCP.newTransparentEF("0101", 0x01, 100), 		// EF.DG1
								new ByteString("6100", HEX)),
							new TransparentEF(FCP.newTransparentEF("0102", 0x02, 100), 		// EF.DG2
								new ByteString("6200", HEX)),
							new TransparentEF(FCP.newTransparentEF("0103", 0x03, 100), 		// EF.DG3
								new ByteString("6300", HEX)),
							new TransparentEF(FCP.newTransparentEF("0104", 0x04, 100), 		// EF.DG4
								new ByteString("6400", HEX)),
							new TransparentEF(FCP.newTransparentEF("0105", 0x05, 100), 		// EF.DG5
								new ByteString("6500", HEX)),
							new TransparentEF(FCP.newTransparentEF("0106", 0x06, 100), 		// EF.DG6
								new ByteString("6600", HEX)),
							new TransparentEF(FCP.newTransparentEF("0107", 0x07, 100), 		// EF.DG7
								new ByteString("6700", HEX)),
							new TransparentEF(FCP.newTransparentEF("0108", 0x08, 100), 		// EF.DG8
								new ByteString("6800", HEX)),
							new TransparentEF(FCP.newTransparentEF("0109", 0x09, 100), 		// EF.DG9
								new ByteString("6900", HEX)),
							new TransparentEF(FCP.newTransparentEF("010A", 0x0A, 100), 		// EF.DG10
								new ByteString("6A00", HEX)),
							new TransparentEF(FCP.newTransparentEF("010B", 0x0B, 100), 		// EF.DG11
								new ByteString("6B00", HEX)),
							new TransparentEF(FCP.newTransparentEF("010C", 0x0C, 100), 		// EF.DG12
								new ByteString("6C00", HEX)),
							new TransparentEF(FCP.newTransparentEF("010D", 0x0D, 100), 		// EF.DG13
								new ByteString("6D00", HEX)),
							new TransparentEF(FCP.newTransparentEF("010E", 0x0E, 100), 		// EF.DG14
								new ByteString("6E00", HEX)),
							new TransparentEF(FCP.newTransparentEF("010F", 0x0F, 100), 		// EF.DG15
								new ByteString("6F00", HEX)),
							new TransparentEF(FCP.newTransparentEF("0110", 0x10, 100), 		// EF.DG16
								new ByteString("7000", HEX)),
							new TransparentEF(FCP.newTransparentEF("0111", 0x11, 200), 		// EF.DG17
								new ByteString("7100", HEX)),
							new TransparentEF(FCP.newTransparentEF("0112", 0x12, 100), 		// EF.DG18
								new ByteString("7200", HEX)),
							new TransparentEF(FCP.newTransparentEF("0113", 0x13, 100), 		// EF.DG19
								new ByteString("7300", HEX)),
							new TransparentEF(FCP.newTransparentEF("0114", 0x14, 100), 		// EF.DG20
								new ByteString("7400", HEX)),
							new TransparentEF(FCP.newTransparentEF("0115", 0x15, 100), 		// EF.DG21
								new ByteString("7500", HEX))
						);

	dFeID.addMeta("accessController", new eIDAccessController());
	dFeID.addMeta("DateOfExpiry", "20121231");
	dFeID.addMeta("DateOfBirth", "19661109");
	dFeID.addMeta("CommunityID", "1234");
	dFeID.addMeta("RIKeys", rIKeys);


	var dFeSign =		new DF(FCP.newDF(null, new ByteString("A000000167455349474E", HEX)),
							new TransparentEF(FCP.newTransparentEF("C000", 1, 2048)), 		// EF.C.ZDA.QES
							new TransparentEF(FCP.newTransparentEF("C001", 2, 2048)) 		// EF.C.ICC.QES
						);

	dFeSign.addMeta("accessController", new eSignAccessController());

	var signpin = new AuthenticationObject("PIN.QES", AuthenticationObject.TYPE_PIN, 1);
	signpin.isTerminated = true;
	signpin.allowTerminate = true;
	signpin.allowResetRetryCounter = true;
	signpin.allowResetValue = true;
	signpin.allowChangeReferenceData = true;
	signpin.unblockAuthenticationObject = pacepuk;
	dFeSign.addObject(signpin);

	var signaturekey = new SignatureKey("PrK.QES", 1);
	signaturekey.useAuthenticationObject = signpin;
	signpin.associatedKey = signaturekey;
	dFeSign.addObject(signaturekey);

	this.mf.add(dFePass);
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
