/*
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|
 * |#       #|  Copyright (c) 1999-2011 CardContact Software & System Consulting
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
 *  Load APDU test applet into JCOP/JTOP card
 */

// Crypto object
var crypto = new Crypto();

// Create application factory that holds all application profiles
var af = new ApplicationFactory(crypto);

af.addApplicationProfile("gp/ap_jcop_cardmanager.xml");
af.addKeyProfile("gp/kp_jcop_default_s-enc.xml");
af.addKeyProfile("gp/kp_jcop_default_s-mac.xml");
af.addKeyProfile("gp/kp_jcop_default_dek.xml");

// Card object
var card = new Card(_scsh3.reader);

//Reset the card
card.reset(Card.RESET_COLD);

var sdAid = new ByteString("A000000151000000", HEX);
var uniqueId = new ByteString("2B0601040181C31F10050201", HEX);

var sd = this.af.getApplicationInstance(new Object(), sdAid, card, uniqueId);

print("Authenticate...");
print(sd.select());
sd.run("AUTHENTICATE");

var loadFileAid = new ByteString("E82B0601040181C31F020201", HEX);
var moduleAid = new ByteString("E82B0601040181C31F0202", HEX);
var applAid = new ByteString("E82B0601040181C31F0202", HEX);

print("Delete old applet instance...");
sd.deleteAID(applAid, [0x9000, 0x6A88, 0x6A80] );

print("Delete old load file...");
sd.deleteAID(loadFileAid, [0x9000, 0x6A88, 0x6A80] );

print("InstallForLoad...");
sd.installForLoad(loadFileAid, sdAid, null, null, null);

print("Loading applet...");
sd.loadByName("apdutest/apdutest.cap");

print("Instantiating applet...");

var applPrivileges = new ByteString("00", HEX);
var installParam = new ByteString("C900", HEX);

sd.installForInstallAndSelectable(loadFileAid, moduleAid, applAid, applPrivileges, installParam, null);
