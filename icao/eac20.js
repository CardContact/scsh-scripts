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
load("eac20sim.js");




var card = new EAC20Sim();
// var card = new Card(_scsh3.reader);

var dp = new Key();
dp.setComponent(Key.ECC_CURVE_OID, ECCUtils.brainpoolP256r1);

var pace = new PACE(PACE.id_PACE_ECDH_GM_AES_CBC_CMAC_128, dp);
pace.setPassword(new ByteString("000001", ASCII));

card.reset(Card.RESET_COLD);


// Manage SE
var crt = new ByteBuffer();
crt.append((new ASN1(0x80, new ByteString(PACE.id_PACE_ECDH_GM_AES_CBC_CMAC_128, OID))).getBytes());
crt.append(new ByteString("830102", HEX));

card.sendApdu(0x00, 0x22, 0xC1, 0xA4, crt.toByteString());
assert(card.SW == 0x9000);


// General Authenticate
var dado = new ASN1(0x7C);

dadobin = card.sendApdu(0x10, 0x86, 0x00, 0x00, dado.getBytes(), 0);
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

dadobin = card.sendApdu(0x10, 0x86, 0x00, 0x00, dado.getBytes(), 0);

var dado = new ASN1(dadobin);
assert(dado.tag == 0x7C);
assert(dado.elements == 1);
var mappingDataDO = dado.get(0);
assert(mappingDataDO.tag == 0x82);

pace.performMapping(mappingDataDO.value);

var ephemeralPublicKeyIfd = pace.getEphemeralPublicKey();

var dado = new ASN1(0x7C, new ASN1(0x83, ephemeralPublicKeyIfd));

dadobin = card.sendApdu(0x10, 0x86, 0x00, 0x00, dado.getBytes(), 0);

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
