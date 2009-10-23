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
 */
 
load("tools/eccutils.js");
// load("eac20sim.js");

load("cvcertstore.js");



function EAC20(crypto, card) {
	this.crypto = crypto;
	this.card = card;
	this.sm = null;
	
	// ToDo: Read from EF_CardInfo
	this.oidPACE = PACE.id_PACE_ECDH_GM_AES_CBC_CMAC_128;
	this.oidTerminalAuthentication = EAC20.id_TA_ECDSA_SHA_256;

	var dp = new Key();
	dp.setComponent(Key.ECC_CURVE_OID, ECCUtils.brainpoolP256r1);
	this.domainParameterPACE = dp;
	this.domainParameterCA = dp;
}



EAC20.prototype.doPACE = function(id, pwd, chat) {

	// ToDo: Read from EF_CardInfo
	
	var pace = new PACE(this.oidPACE, this.domainParameterPACE);
	pace.setPassword(pwd);

	// Manage SE
	var crt = new ByteBuffer();
	crt.append((new ASN1(0x80, new ByteString(PACE.id_PACE_ECDH_GM_AES_CBC_CMAC_128, OID))).getBytes());
	crt.append(new ByteString("8301", HEX));
	crt.append(id);
	crt.append(chat.getBytes());

	card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO, 0x00, 0x22, 0xC1, 0xA4, crt.toByteString(), [0x9000, 0x63C2, 0x63C1, 0x63C0, 0x6283 ]);


	// General Authenticate
	var dado = new ASN1(0x7C);

	dadobin = card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO|Card.RENC, 0x10, 0x86, 0x00, 0x00, dado.getBytes(), 0, [0x9000]);

	var dado = new ASN1(dadobin);
	assert(dado.tag == 0x7C);
	assert(dado.elements == 1);
	var encryptedNonceDO = dado.get(0);
	assert(encryptedNonceDO.tag == 0x80);
	var encryptedNonce = encryptedNonceDO.value;

	GPSystem.trace("Encrypted nonce: " + encryptedNonce);

	pace.decryptNonce(encryptedNonce);

	var mappingData = pace.getMappingData();

	var dado = new ASN1(0x7C, new ASN1(0x81, mappingData));

	dadobin = card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO|Card.RENC, 0x10, 0x86, 0x00, 0x00, dado.getBytes(), 0, [0x9000]);

	var dado = new ASN1(dadobin);
	assert(dado.tag == 0x7C);
	assert(dado.elements == 1);
	var mappingDataDO = dado.get(0);
	assert(mappingDataDO.tag == 0x82);

	pace.performMapping(mappingDataDO.value);

	var ephemeralPublicKeyIfd = pace.getEphemeralPublicKey();

	var dado = new ASN1(0x7C, new ASN1(0x83, ephemeralPublicKeyIfd));

	dadobin = card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO|Card.RENC, 0x10, 0x86, 0x00, 0x00, dado.getBytes(), 0, [0x9000]);

	var dado = new ASN1(dadobin);
	assert(dado.tag == 0x7C);
	assert(dado.elements == 1);
	var ephemeralPublicKeyICC = dado.get(0);
	assert(ephemeralPublicKeyICC.tag == 0x84);

	this.idPicc = ephemeralPublicKeyICC.value.bytes(1, (ephemeralPublicKeyICC.value.length - 1) >> 1);
	GPSystem.trace("ID_PICC : " + this.idPicc);
	
	pace.performKeyAgreement(ephemeralPublicKeyICC.value);


	var authToken = pace.calculateAuthenticationToken();

	var dado = new ASN1(0x7C, new ASN1(0x85, authToken));

	dadobin = card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO|Card.RENC, 0x00, 0x86, 0x00, 0x00, dado.getBytes(), 0, [0x9000, 0x63C2, 0x63C1, 0x63C0, 0x6283 ]);

	var dado = new ASN1(dadobin);
	GPSystem.trace(dado);
	assert(dado.tag == 0x7C);
	assert(dado.elements >= 1);
	assert(dado.elements <= 3);
	var authTokenDO = dado.get(0);
	assert(authTokenDO.tag == 0x86);

	if (dado.elements > 1) {
		var cardo = dado.get(1);
		assert(cardo.tag == 0x87);
		this.lastCAR = new PublicKeyReference(cardo.value);
	}
	
	if (dado.elements > 2) {
		var cardo = dado.get(2);
		assert(cardo.tag == 0x88);
		this.previousCAR = new PublicKeyReference(cardo.value);
	}

	var sm = null;
	
	if (pace.verifyAuthenticationToken(authTokenDO.value)) {
		GPSystem.trace("Authentication token valid");

		sm = new IsoSecureChannel(crypto, IsoSecureChannel.SSC_SYNC_ENC_POLICY);
		sm.setEncKey(pace.kenc);
		sm.setMacKey(pace.kmac);
		sm.setMACSendSequenceCounter(new ByteString("00000000000000000000000000000000", HEX));
		
	}

	this.sm = sm;
	return sm;
}



EAC20.prototype.getTrustAnchorCAR = function(previous) {
	if (previous) {
		return this.previousCAR;
	} else {
		return this.lastCAR;
	}
}



EAC20.prototype.verifyCertificateChain = function(cvcchain) {
	for (var i = cvcchain.length - 1; i >= 0; i--) {
		var cvc = cvcchain[i];
		
		var car = cvc.getCAR().getBytes();
		
		var pukrefdo = new ASN1(0x83, car);
		var pukref = pukrefdo.getBytes();
		
		this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO, 0x00, 0x22, 0x81, 0xB6, pukref, [0x9000]);
		
		// Extract value of 7F21
		var tl = new TLVList(cvc.getBytes(), TLV.EMV);
		var t = tl.index(0);
		var v = t.getValue();
		
		this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO, 0x00, 0x2A, 0x00, 0xBE, v, [0x9000]);
	}
	
	this.terminalCHR = cvc.getCHR();
}



EAC20.prototype.generateEphemeralCAKeyPair = function() {
	this.prkCA = new Key(this.domainParameterCA);
	this.prkCA.setType(Key.PRIVATE);
	
	this.pukCA = new Key(this.domainParameterCA);
	this.pukCA.setType(Key.PUBLIC);
	
	this.crypto.generateKeyPair(Crypto.EC, this.pukCA, this.prkCA);
	
	return (this.pukCA.getComponent(Key.ECC_QX));
}



EAC20.prototype.performTerminalAuthentication = function(termkey, auxdata) {

	var idIFD = this.generateEphemeralCAKeyPair();

	var bb = new ByteBuffer();
	bb.append(new ASN1(0x80, new ByteString(this.oidTerminalAuthentication, OID)).getBytes());
	bb.append(new ASN1(0x83, this.terminalCHR.getBytes()).getBytes());
//	bb.append(auxdata);
	bb.append(new ASN1(0x91, idIFD).getBytes());
	
	var msedata = bb.toByteString();
	print(msedata);
	this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO, 0x00, 0x22, 0x81, 0xA4, msedata, [0x9000]);
	
	var challenge = this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO|Card.RENC, 0x00, 0x84, 0x00, 0x00, 8, [0x9000]);
	
	var bb = new ByteBuffer();
	bb.append(this.idPicc);
	bb.append(challenge);
	bb.append(idIFD);
	
	var signatureInput = bb.toByteString();
	print("Signature Input:");
	print(signatureInput);
	var signature = this.crypto.sign(termkey, Crypto.ECDSA_SHA256, signatureInput);
	print("Signature (Encoded):");
	print(signature);

	signature = ECCUtils.unwrapSignature(signature);
	print("Signature (Encoded):");
	print(signature);

	this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO, 0x00, 0x82, 0x00, 0x00, signature, [0x9000]);
	
}



EAC20.ID_MRZ = 1;
EAC20.ID_CAN = 2;
EAC20.ID_PIN = 3;
EAC20.ID_PUK = 4;

EAC20.bsi_de = "0.4.0.127.0.7";
EAC20.id_TA = EAC20.bsi_de + ".2.2.2";
EAC20.id_TA_RSA = EAC20.id_TA + ".1";

EAC20.id_TA_ECDSA = EAC20.id_TA + ".2";
EAC20.id_TA_ECDSA_SHA_1 = EAC20.id_TA_ECDSA + ".1";
EAC20.id_TA_ECDSA_SHA_224 = EAC20.id_TA_ECDSA + ".2";
EAC20.id_TA_ECDSA_SHA_256 = EAC20.id_TA_ECDSA + ".3";



var crypto = new Crypto();

var certstorepath = GPSystem.mapFilename("cvc", GPSystem.CWD);

var certstore = new CVCertificateStore(certstorepath);


// var card = new EAC20Sim();
var card = new Card(_scsh3.reader);

card.reset(Card.RESET_COLD);

var mf = new CardFile(card, ":3F00");

var chat = new ASN1(0x7F4C, 
						new ASN1(ASN1.OBJECT_IDENTIFIER, new ByteString(PACE.id_IS, OID)),
						new ASN1(0x53, new ByteString("23", HEX))
					);

var eac = new EAC20(crypto, card);

var pwd = new ByteString("000001", ASCII);
var sm = eac.doPACE(EAC20.ID_CAN, pwd, chat);

card.setCredential(sm);

var car = eac.getTrustAnchorCAR(false);

var cvcchain = certstore.getCertificateChainFor(car);

eac.verifyCertificateChain(cvcchain);

// Get key for terminal certificate
var termkey = certstore.getTerminalKeyFor(car);

var ad = new ASN1(0x67);

eac.performTerminalAuthentication(termkey, ad.getBytes());



/*
// card.setCredential(sm);
mf.setCredential(CardFile.ALL, Card.ALL, sm);

var ef = new CardFile(mf, ":011C");
ef.readBinary();

mf.sendSecMsgApdu(Card.CPRO|Card.RPRO|Card.RENC, 0x00, 0xB0, 0, 0, 65536);

*/