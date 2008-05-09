/*
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2006 CardContact Software & System Consulting
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
 *  Load Musclecard Applet into Cyberflex 64K card
 */

load("const.js");
load("gp/tools.js");


var sdAid = new ByteString("A000000003000000", HEX);

// Generate default keys
var masterSENC = new Key("gp/kp_jcop_default_s-enc.xml");
var masterSMAC = new Key("gp/kp_jcop_default_s-mac.xml");


// Card object
var card = new Card(_scsh3.reader);

// Crypto object
var crypto = new Crypto();


// Define a security domain (profiles does not matter so far)
var sd = new GPSecurityDomain("profiles/ap_sample.xml");
sd.aid = sdAid;
sd.card = card;

//Reset the card 
card.reset(Card.RESET_COLD);


print("Selecting card manager application...");

print(sd.select());

GPAuthenticate(card, crypto, masterSENC, masterSMAC);

print("Delete old applet instance...");
sd.deleteAID(applAid, [0x9000, 0x6A88, 0x6A80] );

print("Delete old load file...");
sd.deleteAID(loadFileAid, [0x9000, 0x6A88, 0x6A80] );

print("InstallForLoad...");

// EF 04		- System parameter
//    C6 02 40 00  	- Code Size (16K)
//
var loadParameter = new ByteString("EF04C6024000", HEX);
sd.installForLoad(loadFileAid, sdAid, null, loadParameter, null);

print("Loading applet...");
sd.loadByName("musclecard/CardEdgeCF.cap");

print("Instantiating applet...");

var applPrivileges = new ByteString("00", HEX);

//
// C9 01 00		- Application specific install parameter
// EF 04		- System parameter
//    C8 02 2E E0	- Instance size
var installParam = new ByteString("C90100EF04C8022EE0", HEX);

sd.installForInstallAndSelectable(loadFileAid, moduleAid, applAid, applPrivileges, installParam, null);
