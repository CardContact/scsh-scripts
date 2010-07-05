/*
var card = new Card(_scsh3.reader);
card.reset(Card.RESET_COLD);


var aid = new ByteString("A0000000031010", HEX); // VISA
var rec = new ByteString("2", HEX);
var sfi = new ByteString("2", HEX);

var fcp = card.sendApdu(0x00, 0xA4, 0x04, 0x00, aid, 0x00, [0x9000]);
print("FCP returned in SELECT: ", new ASN1(fcp));

var tlv = card.sendApdu(0x00, 0xB2, rec, (sfi << 3) | 4, 0x00);


*/

/*
// Make RSA private key from modulus and private exponent

var rsaprkey = new Key();
rsaprkey.setType(Key.PRIVATE);

rsaprkey.setComponent(Key.MODULUS, new ByteString("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", HEX));
rsaprkey.setComponent(Key.EXPONENT, new ByteString("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", HEX));

// Make RSA public key from modulus and public exponent

var rsapukey = new Key();
rsapukey.setType(Key.PUBLIC);
rsapukey.setComponent(Key.MODULUS, new ByteString("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", HEX));
rsapukey.setComponent(Key.EXPONENT, new ByteString("11", HEX));

var inp = new ByteString("Message", ASCII);
//var inp = new ByteString("26000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", HEX);
//assert(inp.length == 64);

var cipher = crypto.encrypt(rsaprkey, Crypto.RSA_OAEP, inp);

print("cipher");
print(cipher);

var plain = crypto.decrypt(rsapukey, Crypto.RSA_OAEP, cipher);

print("plain");
print(plain);
assert(plain.equals(inp));

*/
var crypto = new Crypto();

var rsapukey = new Key();
rsapukey.setType(Key.PUBLIC);
rsapukey.setComponent(Key.MODULUS, new ByteString("C696034213D7D8546984579D1D0F0EA519CFF8DEFFC429354CF3A871A6F7183F1228DA5C7470C055387100CB935A712C4E2864DF5D64BA93FE7E63E71F25B1E5F5298575EBE1C63AA617706917911DC2A75AC28B251C7EF40F2365912490B939BCA2124A30A28F54402C34AECA331AB67E1E79B285DD5771B5D9FF79EA630B75", HEX));
rsapukey.setComponent(Key.EXPONENT, new ByteString("03", HEX));

print("modulus");
print(rsapukey.getComponent(Key.MODULUS));
var cipher = new ByteString("A713A718B698C06B7EB6E9131C641D80672046647AD3ECCDB8D1C88766AB04377634B9F819F4F0D24672C8BD5DB64749292C2585E71EA0F17B0DECF88D2A66D7A0146F8B0BFFCDAF9A7B64D29F7A7B00C57F35ADCC126EB31B866FCA900C2061C774F2FF417D224B4F568B58399379F7760BFA13FCBD59F11E46DBE3225DBB1E", HEX);
print("cipher:");
print(cipher);

var plain = crypto.decrypt(rsapukey, Crypto.RSA, cipher);

print("plain:");
print(plain);





