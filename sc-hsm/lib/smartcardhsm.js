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
 * @fileoverview SmartCard-HSM Card Service
 */

if (typeof(__ScriptingServer) == "undefined") {
	load("../../icao/cvc.js");
	load("../../icao/chipauthentication.js");
}


/**
 * Create a SmartCard-HSM access object
 * @class Class implementing support for SmartCard-HSM access
 * @constructor
 * @param {Card} card the card object
 */
function SmartCardHSM(card) {
	this.card = card;
	this.maxAPDU = 1000;			// Cyberjack supports 1014 byte APDUs
//	this.maxAPDU = 255;				// Enable for MicroSD card or set in calling application

	// Check if SmartCard-HSM is already selected
	this.card.sendSecMsgApdu(Card.ALL, 0x00, 0x20, 0x00, 0x81);
	if ((this.card.SW == 0x6E00) || ((this.card.SW == 0x6900))) {
		this.logout();		// Select application
	}

	this.namemap = [];
	this.idmap = [];
}


SmartCardHSM.C_DevAut = new ByteString("2F02", HEX);
SmartCardHSM.PrK_DevAut = 0;
SmartCardHSM.PIN_User = 0x81;

SmartCardHSM.PRKDPREFIX = 0xC4;
SmartCardHSM.KEYMETAPREFIX = 0xCB;
SmartCardHSM.KEYPREFIX = 0xCC;
SmartCardHSM.CONFIDENTIALDATAPREFIX = 0xCD;
SmartCardHSM.EECERTIFICATEPREFIX = 0xCE;
SmartCardHSM.CACERTIFICATEPREFIX = 0xCA;

SmartCardHSM.rootCerts = {
	DESRCACC100001: new CVC(new ByteString("7F218201B47F4E82016C5F290100420E44455352434143433130303030317F4982011D060A04007F000702020202038120A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E537782207D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9832026DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B68441048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F0469978520A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A78641046D025A8026CDBA245F10DF1B72E9880FFF746DAB40A43A3D5C6BEBF27707C30F6DEA72430EE3287B0665C1EAA6EAA4FA26C46303001983F82BD1AA31E03DA0628701015F200E44455352434143433130303030317F4C10060B2B0601040181C31F0301015301C05F25060102010100095F24060302010100085F37409DBB382B1711D2BAACB0C623D40C6267D0B52BA455C01F56333DC9554810B9B2878DAF9EC3ADA19C7B065D780D6C9C3C2ECEDFD78DEB18AF40778ADF89E861CA", HEX)),
	UTSRCACC100001: new CVC(new ByteString("7F218201B47F4E82016C5F290100420E55545352434143433130303030317F4982011D060A04007F000702020202038120A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E537782207D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9832026DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B68441048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F0469978520A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7864104A041FEB2FD116B2AD19CA6B7EACD71C9892F941BB88D67DCEEC92501F070011957E22122BA6C2CF5FF02936F482E35A6129CCBBA8E9383836D3106879C408EF08701015F200E55545352434143433130303030317F4C10060B2B0601040181C31F0301015301C05F25060102010100095F24060302010100085F3740914DD0FA00615C44048D1467435400423A4AD1BD37FD98D6DE84FD8037489582325C72956D4FDFABC6EDBA48184A754F37F1BE5142DD1C27D66569308CE19AAF", HEX))
}

SmartCardHSM.devAutPuk = new Key();
SmartCardHSM.devAutPuk.setType(Key.PUBLIC);
SmartCardHSM.devAutPuk.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP256r1", OID));
SmartCardHSM.devAutPuk.setComponent(Key.ECC_QX, new ByteString("4C01EA36C5065FF47E8F0676A77CDCED6C8F745E6784F7807F5520124F81ED05", HEX));
SmartCardHSM.devAutPuk.setComponent(Key.ECC_QY, new ByteString("4112DCE471CA003442830A10C75B31F9BFADD60628F47131628C7254AD8B956A", HEX));



/**
 * Validate device certificate chain
 *
 * @param {Crypto} crypto the crypto provider to use
 * @param {ByteString} devAutCert the device certificate chain read from EF.C_DevAut
 * @type Key
 * @return the device authentication public key
 */
SmartCardHSM.validateCertificateChain = function(crypto, devAutCert) {
	// Device device certificate
	var cvc = new CVC(devAutCert);
	print("Device Certificate    : " + cvc);

	if (cvc.getCAR().toString() == "DECA00001") {		// CA used for development version up to 0.17
		if (!cvc.verifyWith(crypto, SmartCardHSM.devAutPuk)) {
			print("Device certificate verification failed for CAR=DECA00001");
			return null;
		}
		var path = "/" + cvc.getCAR().getHolder() + "/" + cvc.getCHR().getHolder();
		return { devicecert: cvc, publicKey:cvc.getPublicKey(), path:path };
	}

	// Decode device issuer certificate
	var dica = new CVC(devAutCert.bytes(cvc.getASN1().size));
	print("Device Issuer CA      : " + dica);

	// Determine root certificate
	var srca = SmartCardHSM.rootCerts[dica.getCAR()];
	print("SmartCard-HSM Root CA : " + srca);

	// Validate chain
	var srcapuk = srca.getPublicKey();
	var oid = srca.getPublicKeyOID();
	if (!dica.verifyWith(crypto, srcapuk, oid)) {
		print("DICA certificate not verified");
		return null;
	}

	var dicapuk = dica.getPublicKey(srcapuk);
	if (!cvc.verifyWith(crypto, dicapuk, oid)) {
		print("Device certificate verification failed");
		return null;
	}

	var path = "/" + srca.getCHR().getHolder() + "/" + dica.getCHR().getHolder() + "/" + cvc.getCHR().getHolder();
	return { srca: srca, dica: dica, devicecert: cvc, publicKey:cvc.getPublicKey(srcapuk), path:path };
}



/**
 * Validate device certificate chain
 *
 * @param {Crypto} crypto the crypto provider to use
 * @type Key
 * @return the device authentication public key
 */
SmartCardHSM.prototype.validateCertificateChain = function(crypto) {
	// Read concatenation of both certificates
	var devAutCert = this.readBinary(SmartCardHSM.C_DevAut);
	var chain = SmartCardHSM.validateCertificateChain(crypto, devAutCert);
	if (chain == null) {
		return null;
	}
	return chain.publicKey;
}



/**
 * Open a secure channel using device authentication
 *
 * @param {Crypto} crypto the crypto provider to use
 * @param {Key} devAuthPK the device authentication public key
 * @type ISOSecureChannel
 * @return the initialized secure channel
 */
SmartCardHSM.prototype.openSecureChannel = function(crypto, devAuthPK) {

	var protocol = new ByteString("id-CA-ECDH-3DES-CBC-CBC", OID);
	var ca = new ChipAuthentication(crypto, protocol, devAuthPK);	// For domain parameter
	ca.noPadding = true;
	ca.generateEphemeralCAKeyPair();

	// Perform chip authentication

	var bb = new ByteBuffer();
	bb.append(new ASN1(0x80, protocol).getBytes());

	this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO, 0x00, 0x22, 0x41, 0xA4, bb.toByteString(), [0x9000]);

	var ephemeralPublicKeyIfd = ca.getEphemeralPublicKey();

	var dado = new ASN1(0x7C, new ASN1(0x80, ephemeralPublicKeyIfd));

	var dadobin = this.card.sendSecMsgApdu(Card.CPRO|Card.CENC|Card.RPRO|Card.RENC, 0x00, 0x86, 0x00, 0x00, dado.getBytes(), 0, [0x9000]);

//	print(dadobin);

	var dado = new ASN1(dadobin);
	assert(dado.tag == 0x7C);
	assert(dado.elements == 2);
	var nonceDO = dado.get(0);
	assert(nonceDO.tag == 0x81);
	var nonce = nonceDO.value;

	var authTokenDO = dado.get(1);
	assert(authTokenDO.tag == 0x82);
	var authToken = authTokenDO.value;

	var enc = new ByteString("04", HEX);
	enc = enc.concat(devAuthPK.getComponent(Key.ECC_QX));
	enc = enc.concat(devAuthPK.getComponent(Key.ECC_QY));

	GPSystem.trace("Encoded CA public key: " + enc);
	ca.performKeyAgreement(enc, nonce);
	var result = ca.verifyAuthenticationToken(authToken);

	if (!result) {
		GPSystem.trace("Authentication token invalid");
		throw new Error("Authentication token invalid");
	}
	GPSystem.trace("Authentication token valid");
	var sm = new IsoSecureChannel(crypto);
	sm.setEncKey(ca.kenc);
	sm.setMacKey(ca.kmac);
	sm.setMACSendSequenceCounter(new ByteString("0000000000000000", HEX));

	this.card.setCredential(sm);
	return sm;
}



/**
 * Update transparent EF referenced by file identifier
 *
 * @param {ByteString} fid the two byte file identifier
 * @param {Number} offset the offset into the EF
 * @param {ByteString} data the data to write
 */
SmartCardHSM.prototype.updateBinary = function(fid, offset, data) {

	var bytesLeft = data.length;
	var offset = 0;

	while (bytesLeft > 0) {
		// 15 bytes are required for CLA IN P1 P2 Lc(3) T54(4) and T53(4)
		var toSend = bytesLeft >= this.maxAPDU - 15 ? this.maxAPDU -15 : bytesLeft;

		var t54 = new ASN1(0x54, ByteString.valueOf(offset, 2));
		var t53 = new ASN1(0x53, data.bytes(offset, toSend));

		var cdata = t54.getBytes().concat(t53.getBytes());
		this.card.sendSecMsgApdu(Card.ALL, 0x00, 0xD7, fid.byteAt(0), fid.byteAt(1), cdata, [0x9000]);

		bytesLeft -= toSend;
		offset += toSend;
	}
}



/**
 * Read transparent EF referenced by file identifier
 *
 * @param {ByteString} fid the two byte file identifier
 * @param {Number} offset the offset into the EF (optional)
 * @param {Number} length the number of byte to read (optional)
 * @type ByteString
 * @return the data read from the EF
 */
SmartCardHSM.prototype.readBinary = function(fid, offset, length) {
	if (typeof(offset) == "undefined") {
		offset = 0;
	}

	var rsp = new ByteBuffer();
	do	{
		var t54 = new ASN1(0x54, ByteString.valueOf(offset, 2));

		if (length) {					// Is a length defined ?
			var le = length > this.maxAPDU - 2 ? this.maxAPDU - 2: length;			// Truncate if larger than maximum APDU size ?
		} else {
			var le = this.maxAPDU < 256 ? 0 : 65536;						// Get all with Le=0 in either short or extended APDU mode
		}

		var data = this.card.sendSecMsgApdu(Card.ALL, 0x00, 0xB1, fid.byteAt(0), fid.byteAt(1), t54.getBytes(), le, [0x9000, 0x6282]);

		rsp.append(data);
		offset += data.length;

		if (le == 65536) {				// Only a single command required when send as extended length APDU
			break;
		}
		if (length) {					// Length was defined, see if we already got everything
			length -= data.length;
			if (length <= 0) {
				break;
			}
		}
	} while ((this.card.SW == 0x9000) && (data.length > 0));

	return rsp.toByteString();
}



/**
 * Delete file system object (EF or key)
 *
 * @param {ByteString} fid the two byte file object identifier
 */
SmartCardHSM.prototype.deleteFile = function(fid) {
	return this.card.sendSecMsgApdu(Card.ALL, 0x00, 0xE4, 0x02, 0x00, fid, [0x9000]);
}



/**
 * Strips leading zeros of a ByteString
 *
 * @param {ByteString} value the ByteString value
 * @return the stripped ByteString object, may be an empty ByteString
 * @type ByteString
 */
SmartCardHSM.stripLeadingZeros = function(value) {
	var i = 0;
	for (; (i < value.length) && (value.byteAt(i) == 0); i++);

	return value.right(value.length - i);
}



/**
 * Build input for Generate Asymmetric Key Pair command for generating an ECC key pair
 *
 * @param {PublicKeyReference} innerCAR the CA the request shall be directed to
 * @param {ByteString} algo the public key algorithm
 * @param {PublicKeyReference} chr the certificate holder reference associated with this key
 * @param {Key} dp the domain parameter for the key
 * @param {PublicKeyReference} outerCAR the certificate holder reference of the public key for verifying the outer signature
 * @param {Key} privateKey optional parameter to supply a private key value for import. This only works with the development version
 *              of the SmartCard-HSM.
 * @type ByteString
 * @return the encoded C-Data for GENERATE ASYMMETRIC KEY PAIR
 */
SmartCardHSM.buildGAKPwithECC = function(innerCAR, algo, chr, dp, outerCAR, priKey) {

	// Encode G
	var bb = new ByteBuffer();
	// uncompressed encoding
	bb.append(new ByteString("04", HEX));
	bb.append(dp.getComponent(Key.ECC_GX));
	bb.append(dp.getComponent(Key.ECC_GY));
	var G = bb.toByteString();

	var t = new ASN1(0x30,
				new ASN1("CPI", 0x5F29, new ByteString("00", HEX)),
				new ASN1("CAR", 0x42, innerCAR.getBytes()),
				new ASN1("Public Key", 0x7F49,
					new ASN1("Object Identifier", 0x06, algo),
					new ASN1("Prime Modulus", 0x81, dp.getComponent(Key.ECC_P)),
					new ASN1("First coefficient a", 0x82, dp.getComponent(Key.ECC_A)),
					new ASN1("Second coefficient b", 0x83, dp.getComponent(Key.ECC_B)),
					new ASN1("Base Point G", 0x84, G),
					new ASN1("Order of the base point", 0x85, dp.getComponent(Key.ECC_N)),
					new ASN1("Cofactor f", 0x87, SmartCardHSM.stripLeadingZeros(dp.getComponent(Key.ECC_H)))
				),
				new ASN1("CHR", 0x5F20, chr.getBytes())
			);

	if (typeof(outerCAR) != "undefined") {
		t.add(new ASN1("OuterCAR", 0x45, outerCAR.getBytes()));
	}

	if (priKey != undefined) {
		var d = new ASN1("Private Key", 0x8A, priKey.getComponent(Key.ECC_D));
		t.get(2).add(d);
//		print(t);
	}
	return t.value;
}



/**
 * Build input for Generate Asymmetric Key Pair command for generating a RSA key pair
 *
 * @param {PublicKeyReference} innerCAR the CA the request shall be directed to
 * @param {ByteString} algo the public key algorithm
 * @param {PublicKeyReference} chr the certificate holder reference associated with this key
 * @param {Number} keysize the module size in bits (1024, 1536 or 2048)
 * @param {PublicKeyReference} outerCAR the certificate holder reference of the public key for verifying the outer signature
 * @type ByteString
 * @return the encoded C-Data for GENERATE ASYMMETRIC KEY PAIR
 */
SmartCardHSM.buildGAKPwithRSA = function(innerCAR, algo, chr, keysize, outerCAR) {

	var t = new ASN1(0x30,
				new ASN1("CPI", 0x5F29, new ByteString("00", HEX)),
				new ASN1("CAR", 0x42, innerCAR.getBytes()),
				new ASN1("Public Key", 0x7F49,
					new ASN1("Object Identifier", 0x06, algo),
					new ASN1("Public Key Exponent", 0x82, ByteString.valueOf(65537)),
					new ASN1("Key Size", 0x02, ByteString.valueOf(keysize))
				),
				new ASN1("CHR", 0x5F20, chr.getBytes())
			);

	if (typeof(outerCAR) != "undefined") {
		t.add(new ASN1("OuterCAR", 0x45, outerCAR.getBytes()));
	}
	return t.value;
}



/**
 * Create a PKCS#15 PrivateECCKey description
 *
 * @param {Number} keyid the key identifier
 * @param {String} label the key label
 * @type ASN1
 * @return the PrivateECCKey description
 */
SmartCardHSM.buildPrkDforECC = function(keyid, label, keysize) {
	var prkd = 	new ASN1(0xA0,
					new ASN1(ASN1.SEQUENCE,
						new ASN1(ASN1.UTF8String, new ByteString(label, UTF8))
//						new ASN1(ASN1.BIT_STRING, new ByteString("0780", HEX)),
//						new ASN1(ASN1.OCTET_STRING, new ByteString("01", HEX))
					),
					new ASN1(ASN1.SEQUENCE,
						new ASN1(ASN1.OCTET_STRING, ByteString.valueOf(keyid)),
						new ASN1(ASN1.BIT_STRING, new ByteString("072080", HEX))
					),
					new ASN1(0xA1,
						new ASN1(ASN1.SEQUENCE,
							new ASN1(ASN1.SEQUENCE,
								new ASN1(ASN1.OCTET_STRING, new ByteString("", HEX))
							)
						)
					)
				);

	if (keysize != undefined) {
		assert(keysize > 0);
		var tlvint = ByteString.valueOf(keysize);
		if (tlvint.byteAt(0) >= 0x80) {
			tlvint = (new ByteString("00", HEX)).concat(tlvint);
		}
		prkd.get(2).get(0).add(new ASN1(ASN1.INTEGER, tlvint));
	}

//	print(prkd);
	return prkd;
}



/**
 * Create a PKCS#15 PrivateRSAKey description
 *
 * @param {Number} keyid the key identifier
 * @param {String} label the key label
 * @param {Number} modulussize
 * @type ASN1
 * @return the PrivateECCKey description
 */
SmartCardHSM.buildPrkDforRSA = function(keyid, label, modulussize) {
	var prkd = 	new ASN1(0x30,
					new ASN1(ASN1.SEQUENCE,
						new ASN1(ASN1.UTF8String, new ByteString(label, UTF8))
//						new ASN1(ASN1.BIT_STRING, new ByteString("0780", HEX)),
//						new ASN1(ASN1.OCTET_STRING, new ByteString("01", HEX))
					),
					new ASN1(ASN1.SEQUENCE,
						new ASN1(ASN1.OCTET_STRING, ByteString.valueOf(keyid)),
						new ASN1(ASN1.BIT_STRING, new ByteString("0274", HEX))
					),
					new ASN1(0xA1,
						new ASN1(ASN1.SEQUENCE,
							new ASN1(ASN1.SEQUENCE,
								new ASN1(ASN1.OCTET_STRING, new ByteString("", HEX))
							),
							new ASN1(ASN1.INTEGER, ByteString.valueOf(modulussize))
						)
					)
				);
//	print(prkd);
	return prkd;
}



/**
 * Dump C-Data of Generate Asymmetric Key Pair command
 *
 * @param {ByteString} keydata the content of C-Data
 */
SmartCardHSM.dumpKeyData = function(keydata) {
	print(keydata);
	var a = new ASN1(0x30, keydata);
	var a = new ASN1(a.getBytes());
	for (var i = 0; i < a.elements; i++) {
		print(a.get(i));
	}
}



/**
 * Generate an asymmetric key pair
 *
 * @param {Number} newkid key identifier for new key
 * @param {Number} signkid key identifier for signing the new public key
 * @param {ByteString} keydata the key data template
 * @type ByteString
 * @return the certificate signing request containing the new public key
 */
SmartCardHSM.prototype.generateAsymmetricKeyPair = function(newkid, signkid, keydata) {

	if (this.maxAPDU > 255) { // Use extended length
		var rsp = this.card.sendSecMsgApdu(Card.ALL, 0x00, 0x46, newkid, signkid, keydata, 65536, [0x9000]);
	} else {
		this.card.sendSecMsgApdu(Card.ALL, 0x00, 0x46, newkid, signkid, keydata, [0x9000]);
		var rsp = this.readBinary(ByteString.valueOf(0xCE00 + newkid), 0);
	}

	return rsp;
}



SmartCardHSM.prototype.isInitialized = function() {
	var sw = this.queryUserPINStatus();
	if (sw == 0x6984) {		// V1.2: Not initialized / V2.0: Transport PIN
		var sw = this.queryInitializationCodeStatus();
		if (sw == 0x6A88) {
			return false;
		}
	} else {
		if (sw == 0x6A88) {	// V2.0: Not initialized
			return false;
		}
	}
	return true;
}



/**
 * Initialize device and clear all keys and files
 *
 * @param {ByteString} options two byte option mask
 * @param {ByteString} initialPIN initial user PIN value
 * @param {ByteString} initializationCode secret code for device initialization (set during first use)
 * @param {Number} retryCounterInitial retry counter for user PIN
 * @param {Number} keyshares number of device key encryption key shares (optional)
 */
SmartCardHSM.prototype.initDevice = function(options, initialPIN, initializationCode, retryCounterInitial, keyshares) {
	var s = new ASN1(0x30,
				new ASN1(0x80, options),
				new ASN1(0x81, initialPIN),
				new ASN1(0x82, initializationCode),
				new ASN1(0x91, ByteString.valueOf(retryCounterInitial))
				);

	if (typeof(keyshares) != "undefined") {
		s.add(new ASN1(0x92, ByteString.valueOf(keyshares)));
	}
	this.card.sendSecMsgApdu(Card.ALL, 0x80, 0x50, 0x00, 0x00, s.value, [0x9000]);
}



/**
 * Import DKEK share or query status
 *
 * @param {ByteString} keyshare 32 byte key share
 * @type Object
 * @return object with properties sw{Number}, shares{Number}, outstanding{Number} and kcv{ByteString}
 */
SmartCardHSM.prototype.importKeyShare = function(keyshare) {
	if (typeof(keyshare) != "undefined") {
		var status = this.card.sendSecMsgApdu(Card.ALL, 0x80, 0x52, 0x00, 0x00, keyshare, 0);
	} else {
		var status = this.card.sendSecMsgApdu(Card.ALL, 0x80, 0x52, 0x00, 0x00, 0);
	}
	if (status.length == 0) {
		return { sw: this.card.SW };
	}
	return { sw: this.card.SW, shares: status.byteAt(0), outstanding: status.byteAt(1), kcv: status.bytes(2) };
}



/**
 * Wrap key under DKEK
 *
 * @param {Number} id key id
 * @type ByteString
 * @return key blob with encrypted key value
 */
SmartCardHSM.prototype.wrapKey = function(id) {
	var keyblob = this.card.sendSecMsgApdu(Card.ALL, 0x80, 0x72, id, 0x92, 65536, [0x9000]);
	return keyblob;
}



/**
 * Unwrap key with DKEK
 *
 * @param {Number} id key id
 * @param {ByteString} keyblob the wrapped key
 */
SmartCardHSM.prototype.unwrapKey = function(id, keyblob) {
	this.card.sendSecMsgApdu(Card.ALL, 0x80, 0x74, id, 0x93, keyblob, [0x9000]);
}



/**
 * Verify User PIN
 *
 * @param {ByteString} userPIN user PIN value
 * @return the status word SW1/SW2 returned by the device
 */
SmartCardHSM.prototype.verifyUserPIN = function(userPIN) {
	this.card.sendSecMsgApdu(Card.ALL, 0x00, 0x20, 0x00, 0x81, userPIN);
	return this.card.SW;
}



/**
 * Logout
 *
 */
SmartCardHSM.prototype.logout = function() {
	this.card.sendApdu(0x00, 0xA4, 0x04, 0x04, new ByteString("E82B0601040181C31F0201", HEX), [0x9000]);
}



/**
 * Change User PIN
 *
 * @param {ByteString} currentPIN current user PIN value
 * @param {ByteString} newPIN new user PIN value
 */
SmartCardHSM.prototype.changeUserPIN = function(currentPIN, newPIN) {
	this.card.sendSecMsgApdu(Card.ALL, 0x00, 0x24, 0x00, 0x81, currentPIN.concat(newPIN), [0x9000]);
}



/**
 * Request PIN Status Information
 *
 * @type Number
 * @return the status word SW1/SW2 returned by the device
 */
SmartCardHSM.prototype.queryUserPINStatus = function() {
	this.card.sendSecMsgApdu(Card.ALL, 0x00, 0x20, 0x00, 0x81, 0);
	return this.card.SW;
}



/**
 * Request Initialization Code Status
 *
 * @type Number
 * @return the status word SW1/SW2 returned by the device
 */
SmartCardHSM.prototype.queryInitializationCodeStatus = function() {
	this.card.sendSecMsgApdu(Card.ALL, 0x00, 0x20, 0x00, 0x88, 0);
	return this.card.SW;
}



/**
 * Enumerate Objects
 *
 * @return the enumeration
 */
SmartCardHSM.prototype.enumerateObjects = function() {
	var rsp = this.card.sendSecMsgApdu(Card.ALL, 0x80, 0x58, 0x00, 0x00, 65536, [0x9000]);
	return rsp;
}



/**
 * Generate random data
 *
 * @param {Number} length number of bytes
 * @return the random bytes
 */
SmartCardHSM.prototype.generateRandom = function(length) {
	var rsp = this.card.sendSecMsgApdu(Card.ALL, 0x00, 0x84, 0x00, 0x00, length, [0x9000]);
	return rsp;
}



/**
 * Sign data using referenced key
 *
 * @param {Number} keyid the key identifier for signing
 * @param {algo} algo the algorithm identifier
 * @param {ByteString} data the data to be signed
 * @return the signature value
 */
SmartCardHSM.prototype.sign = function(keyid, algo, data) {
	var rsp = this.card.sendSecMsgApdu(Card.ALL, 0x80, 0x68, keyid, algo, data, 0x00, [0x9000]);
	return rsp;
}



/**
 * Decipher cryptogram or agree shared secret using Diffie-Hellman
 *
 * @param {Number} keyid the key identifier
 * @param {Number} algo the algorithm identifier
 * @param {ByteString} data the the cryptogram or concatenation of x || y of ECC public key
 * @return the plain output
 */
SmartCardHSM.prototype.decipher = function(keyid, algo, data) {
	var rsp = this.card.sendSecMsgApdu(Card.ALL, 0x80, 0x62, keyid, algo, data, 0x00, [0x9000]);
	return rsp;
}



/**
 * Enumerate key objects in the SmartCard-HSM and build the map of keys
 *
 * @type String[]
 * @return the list of key labels
 */
SmartCardHSM.prototype.enumerateKeys = function() {
	this.namemap = [];
	this.idmap = [];

	var fobs = this.enumerateObjects();

	// Process keys
	for (var i = 0; i < fobs.length; i += 2) {
		if (fobs.byteAt(i) == SmartCardHSM.KEYPREFIX) {
			var kid = fobs.byteAt(i + 1);
			if (kid > 0) {
//				print("Found key: " + kid);
				this.idmap[kid] = new SmartCardHSMKey(this, kid);
			}
		}
	}

	var keylist = [];
	// Process PKCS#15 private key descriptions
	for (var i = 0; i < fobs.length; i += 2) {
		if (fobs.byteAt(i) == SmartCardHSM.PRKDPREFIX) {
			var kid = fobs.byteAt(i + 1);
			var descbin = this.readBinary(fobs.bytes(i, 2));
			var desc = new ASN1(descbin);
			var key = this.idmap[kid];
			if (key) {
				key.setDescription(desc);
				var label = key.getLabel();
//				print(key.getId() + " - " + label);
				keylist.push(label);
				this.namemap[label] = key;
			}
		}
	}

	return keylist;
}



/**
 * Determine an unused key identifier
 *
 * @type Number
 * @return a free key identifier or -1 if all key identifier in use
 */
SmartCardHSM.prototype.determineFreeKeyId = function() {
	for (var i = 1; i < 256; i++) {
		if (this.idmap[i] == undefined) {
			return i;
		}
	}
	return -1;
}



/**
 * Add a new key to the map of keys
 *
 * @param {HSMKey} key the HSM key
 */
SmartCardHSM.prototype.addKeyToMap = function(key) {
	var label = key.getLabel();
	var id = key.getId();
	this.namemap[label] = key;
	this.idmap[id] = key;
}



/**
 * Get a key reference object
 *
 * @param {String} path the relative path of the PKI element (e.g. "/UTCVCA1/UTDVCA1/UTTERM")
 * @returns the key or null if not found
 * @type Key
 */
SmartCardHSM.prototype.getKey = function(label) {
	var key = this.namemap[label];
	if (key == undefined) {
		return null;
	}
	return key;
}



/**
 * Get crypto object
 *
 * @type HSMCrypto
 * @return the HSMCrypto object
 */
SmartCardHSM.prototype.getCrypto = function() {
	if (this.crypto == undefined) {
		this.crypto = new SmartCardHSMCrypto(new Crypto());
	}
	return this.crypto;
}



/**
 * Create crypto object implementing access to the SmartCard-HSM
 *
 * @class Wrapper to provide Crypto interface to SmartCard-HSM
 * @constructor
 * @param {Crypto} crypto the backend crypto provider
 */
function SmartCardHSMCrypto(crypto) {
	this.crypto = crypto;
}



/**
 * Sign a message using the defined mechanism and key
 *
 * @param {HSMKey} key the private key
 * @param {Number} mech the mechanism (e.g. Crypto.ECDSA)
 * @param {ByteString} message the message to be signed
 * @type ByteString
 * @return the signature
 */
SmartCardHSMCrypto.prototype.sign = function(key, mech, message) {
	if (key instanceof SmartCardHSMKey) {
		return key.sign(mech, message);
	} else {
		return this.crypto.sign(key, mech, message);
	}
}



/**
 * Verify a message using the defined mechanism and key
 *
 * @param {Key} key the public key
 * @param {Number} mech the mechanism (e.g. Crypto.ECDSA)
 * @param {ByteString} message the message to be signed
 * @param {ByteString} signature the signature to verify
 * @type Boolean
 * @return true if signature is valid
 */
SmartCardHSMCrypto.prototype.verify = function(key, mech, message, signature) {
	return this.crypto.verify(key, mech, message, signature);
}



/**
 * Create a key access object
 *
 * @class Class implementing key access
 * @param {SmartCardHSM} sc the card access object
 * @param {Number} id the key identifier
 */
function SmartCardHSMKey(sc, id) {
	this.sc = sc;
	this.id = id;
}



/**
 * Set the PKCS#15 private key description
 *
 * @param {ASN1} desc the description
 */
SmartCardHSMKey.prototype.setDescription = function(desc) {
	this.desc = desc;
}



/**
 * Return the key identifier
 *
 * @type Number
 * @return the key identifier
 */
SmartCardHSMKey.prototype.getId = function() {
	return this.id;
}



/**
 * Return the key label as encoded in the PKCS#15 structure
 *
 * @type String
 * @return the key label
 */
SmartCardHSMKey.prototype.getLabel = function() {
	if (this.desc == undefined) {
		return undefined;
	}
	return this.desc.get(0).get(0).value.toString(UTF8);
}



/**
 * Return the key size in bits
 *
 * @type Number
 * @return the key size in bits
 */
SmartCardHSMKey.prototype.getSize = function() {
	if (this.desc == undefined) {
		return undefined;
	}
//	print(this.desc);
	if (this.desc.get(2).elements > 1) {	// Fix a bug from early versions
		return this.desc.get(2).get(1).value.toUnsigned();
	} else {
		return this.desc.get(2).get(0).get(1).value.toUnsigned();
	}
}



/**
 * Sign data using a key in the SmartCard-HSM
 *
 * @param {ByteString} data to be signed
 * @param {Number} mech the signing mechanism
 * @type ByteString
 * @return the signature
 */
SmartCardHSMKey.prototype.sign = function(mech, data) {
	if (mech) {
		switch(mech) {
		case Crypto.RSA:
			algo = 0x20;
			break;
		case Crypto.RSA_SHA1:
			algo = 0x31;
			break;
		case Crypto.RSA_SHA256:
			algo = 0x33;
			break;
		case Crypto.RSA_PSS_SHA1:
			algo = 0x41;
			break;
		case Crypto.RSA_PSS_SHA256:
			algo = 0x43;
			break;
		case Crypto.ECDSA:
			algo = 0x70;
			break;
		case Crypto.ECDSA_SHA1:
			algo = 0x71;
			break;
		case Crypto.ECDSA_SHA224:
			algo = 0x72;
			break;
		case Crypto.ECDSA_SHA256:
			algo = 0x73;
			break;
		default:
			throw new GPError("SmartCardHSMKey", GPError.INVALID_DATA, mech, "Unsupported crypto mechanism");
		}
	}

	return this.sc.sign(this.id, algo, data);
}



/**
 * Return human readable string
 */
SmartCardHSMKey.prototype.toString = function() {
	return "SmartCardHSMKey(id=" + this.id + ")";
}



SmartCardHSM.test = function() {
	var crypto = new Crypto();
	var card = new Card(_scsh3.reader);
	var sc = new SmartCardHSM(card);

	var pubKey = sc.validateCertificateChain(crypto);
	sc.openSecureChannel(crypto, pubKey);

	sc.verifyUserPIN(new ByteString("648219", ASCII));
	var list = sc.enumerateKeys();
	print("Keys on device: " + list);

	var crypto = sc.getCrypto();
	var message = new ByteString("Hello World", ASCII);
	var key = sc.getKey(list[0]);
	var signature = crypto.sign(key, Crypto.ECDSA, message);
	print("Signature: " + signature);
}
