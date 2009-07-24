/**
 *
 */


load("eac20sim.js");

var bsi_de = "0.4.0.127.0.7";
var id_PACE = bsi_de + ".2.2.4";
var id_PACE_ECDH_GM = id_PACE + ".2";
var id_PACE_ECDH_GM_AES_CBC_CMAC_128 = id_PACE_ECDH_GM + ".2";




var card = new EAC20Sim();

var dp = new Key();
dp.setComponent(Key.ECC_CURVE_OID, new ByteString("1.3.36.3.3.2.8.1.1.7", OID));

var pace = new PACE(PACE.id_PACE_ECDH_GM_AES_CBC_CMAC_128, dp);
pace.setPassword(new ByteString("123456", ASCII));

card.reset(Card.RESET_COLD);


// Manage SE
var crt = new ByteBuffer();
crt.append((new ASN1(0x80, new ByteString(id_PACE_ECDH_GM_AES_CBC_CMAC_128, OID))).getBytes());
crt.append(new ByteString("830103", HEX));

card.sendApdu(0x00, 0x22, 0xC1, 0xA4, crt.toByteString());
assert(card.SW == 0x9000);


// General Authenticate
var dado = new ASN1(0x7C);

dadobin = card.sendApdu(0x00, 0x86, 0x00, 0x00, dado.getBytes(), 0);
assert(card.SW == 0x9000);

var dado = new ASN1(dadobin);
assert(dado.tag == 0x7C);
assert(dado.elements == 1);
var encryptedNonceDO = dado.get(0);
assert(encryptedNonceDO.tag == 0x80);
var encryptedNonce = encryptedNonceDO.value;

print("Encrypted nonce: " + encryptedNonce);

pace.decryptNonce(encryptedNonce);

var mappingData = pace.getMappingData();

var dado = new ASN1(0x7C, new ASN1(0x81, mappingData));

dadobin = card.sendApdu(0x00, 0x86, 0x00, 0x00, dado.getBytes(), 0);

var dado = new ASN1(dadobin);
assert(dado.tag == 0x7C);
assert(dado.elements == 1);
var mappingDataDO = dado.get(0);
assert(mappingDataDO.tag == 0x82);

pace.performMapping(mappingDataDO.value);

var ephemeralPublicKeyIfd = pace.getEphemeralPublicKey();

var dado = new ASN1(0x7C, new ASN1(0x83, ephemeralPublicKeyIfd));

dadobin = card.sendApdu(0x00, 0x86, 0x00, 0x00, dado.getBytes(), 0);

var dado = new ASN1(dadobin);
assert(dado.tag == 0x7C);
assert(dado.elements == 1);
var ephemeralPublicKeyICC = dado.get(0);
assert(ephemeralPublicKeyICC.tag == 0x84);

pace.performKeyAgreement(ephemeralPublicKeyICC.value);


var authToken = pace.calculateAuthenticationToken();

var dado = new ASN1(0x7C, new ASN1(0x85, authToken));

dadobin = card.sendApdu(0x00, 0x86, 0x00, 0x00, dado.getBytes(), 0);

var dado = new ASN1(dadobin);
print(dado);
assert(dado.tag == 0x7C);
assert(dado.elements == 1);
var authTokenDO = dado.get(0);
assert(authTokenDO.tag == 0x86);

if (pace.verifyAuthenticationToken(authTokenDO.value)) {
	print("Authentication token valid");
}

print(card);
print(pace);
