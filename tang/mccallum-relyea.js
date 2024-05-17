/*
 * McCallum-Relyea Exchange
 *
 * Developed by RedHat and is used by the tang [1] and clevis utilities for binding data to network presence.
 *
 * [1] https://github.com/latchset/tang
 * [2] https://crypto.stackexchange.com/questions/98602/security-of-mccallum-relyea-exchange
 */


requires("3.18.10"); // Needs EC_MULTIPLY_SUB


var crypto = new Crypto();

var dp = new Key();
dp.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP256r1", OID));


// Server - Generate Server Keypair

var S = new Key(dp);
S.setType(Key.PUBLIC);

var s = new Key(dp);
s.setType(Key.PRIVATE);

crypto.generateKeyPair(Crypto.EC, S, s);


// Client - Generate Client Keypair

var C = new Key(dp);
C.setType(Key.PUBLIC);

var c = new Key(dp);
c.setType(Key.PRIVATE);

crypto.generateKeyPair(Crypto.EC, C, c);


// ECDH - Generate Client Secret

var pk = S.getComponent(Key.ECC_QX).concat(S.getComponent(Key.ECC_QY));
var K = crypto.decrypt(c, Crypto.ECDHP, pk);
print(K);


// Client - Generate Export Key to request secret

var E = new Key(dp);
E.setType(Key.PUBLIC);

var e = new Key(dp);
e.setType(Key.PRIVATE);

crypto.generateKeyPair(Crypto.EC, E, e);

// Client calculate X := C + E

var X = new Key(E);

crypto.deriveKey(C, Crypto.EC_MULTIPLY_ADD, null, X);


// Server - ECDH

var pk = X.getComponent(Key.ECC_QX).concat(X.getComponent(Key.ECC_QY));
var secret = crypto.decrypt(s, Crypto.ECDHP, pk);


var Y = new Key(dp);
Y.setType(Key.PUBLIC);
Y.setComponent(Key.ECC_QX, secret.left(secret.length >> 1));
Y.setComponent(Key.ECC_QY, secret.right(secret.length >> 1));


// Client - ECDH

var pk = S.getComponent(Key.ECC_QX).concat(S.getComponent(Key.ECC_QY));
var secret = crypto.decrypt(e, Crypto.ECDHP, pk);

var Z = new Key(dp);
Z.setType(Key.PUBLIC);
Z.setComponent(Key.ECC_QX, secret.left(secret.length >> 1));
Z.setComponent(Key.ECC_QY, secret.right(secret.length >> 1));

// Y - Z

crypto.deriveKey(Y, Crypto.EC_MULTIPLY_SUB, null, Z);

// Should match K
print(Z.getComponent(Key.ECC_QX).concat(Z.getComponent(Key.ECC_QY)));
