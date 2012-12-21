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
 * @fileoverview Test document revocation crypto
 */

var crypto = new Crypto();

// Revocation key at CVCA
// Generated at setup
var prkRev = new Key("kp_prk_RevocationKey.xml");

// Revocation key of document
// Generated per document and send to CVCA
var pukId = new Key("kp_puk_IDKey.xml");


// Revocation ID calculated from pukRevId = 04 || prkRev * pukId
// Calculated when document is revoked. Id is send to DV
var inp = pukId.getComponent(Key.ECC_QX).concat(pukId.getComponent(Key.ECC_QY));
var pukRevId = ByteString.valueOf(0x04).concat(crypto.decrypt(prkRev, Crypto.ECDHP, inp));
print("Revocation ID                   : " + pukRevId);


// Transformation at DV for each sector with Hash(X-coordinate(prkSector * pukRevId));
var prkSector = new Key("kp_prk_SectorKey.xml");
var secrevid1 = crypto.digest(Crypto.SHA_256, crypto.decrypt(prkSector, Crypto.ECDH, pukRevId.bytes(1)));
print("Sector Revocation ID at DV      : " + secrevid1);


// Calculation of the sector revocation id in the document
var prkId = new Key("kp_prk_IDKey.xml");
var pukSector = new Key("kp_puk_SectorKey.xml");
var inp = pukSector.getComponent(Key.ECC_QX).concat(pukSector.getComponent(Key.ECC_QY));
var secrevid2 = crypto.digest(Crypto.SHA_256, crypto.decrypt(prkId, Crypto.ECDH, inp));
print("Sector Revocation ID at document: " + secrevid2);

