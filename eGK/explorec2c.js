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
 *  eGK explorer with card to card authentication
 */

requires("3.6.525");

var reader_hic = "";
var reader_hpc = "";

// Uncomment the following, if you have two PC/SC reader rather than a terminal
// with multiple slots. Fill in the card reader names as they are shown in the
// Options/Reader Configuration dialog

// reader_hic = "ORGA CardMouse USB 0";
// reader_hpc = "SCM Microsystems Inc. SCR33x USB Smart Card Reader 0";

print("eGK Explorer with Card-To-Card Authentication.");
print("==============================================");

if (!_scsh3.reader) {
	if (!reader_hic || !reader_hpc) {
		print("This script will only work, if you configured a card reader with dual-slots");
		print("from the Options/Reader Configuration menu or set the variables reader_hic");
		print("and reader_hpc in this script");
		throw new GPError("explorec2c.js", 0, 0, "Reader not configured");
	}
	slot_hic = reader_hic;
	slot_hpc = reader_hpc;
} else {
	if (reader_hic || reader_hpc) {
		slot_hic = reader_hic;
		slot_hpc = reader_hpc;
	} else {
		slot_hic = _scsh3.reader + "#1";
		slot_hpc = _scsh3.reader + "#2";
	}
}

print("Make sure you have a HIC in " + slot_hic);
print("               and a HPC in " + slot_hpc);

// Load CardOutlineFactory to display card tree
load("tools/CardOutlineFactory.js");

// Load special classes to display XML encoded fields
load("tools.js");

// Load Card2CardAuthentication() function
load("c2caut.js");


// Create crypto object
var crypto = new Crypto();

// Create application factory that holds all application profiles
var af = new ApplicationFactory(crypto);

// Add ec-card application profiles
af.addApplicationProfile("ap_mf.xml");
af.addApplicationProfile("ap_hca.xml");
af.addApplicationProfile("ap_esign.xml");
af.addApplicationProfile("ap_ciaesign.xml");
af.addApplicationProfile("ap_qes.xml");
        

// Create card outline factory
var of = new eGKCardOutlineFactory();

// Create list of AIDs, just in case the EF.DIR is empty
// This is just temporary to make sure the explorer works
// even for card with a defect in EF.DIR

var aidlist = new Array();

/* Enable, if EF.DIR is invalid
aidlist.push(new ByteString("D27600000102", HEX));
aidlist.push(new ByteString("A000000167455349474E", HEX));
aidlist.push(new ByteString("E828BD080FA000000167455349474E", HEX));
aidlist.push(new ByteString("D27600006601", HEX));
*/

var card_HIC = new Card(slot_hic, "cp_egk.xml"); 	// Reader with eGK in slot#1
var card_HPC = new Card(slot_hpc); 			// Reader with HPC in slot#2

card_HPC.reset(Card.RESET_COLD);

// Select application on HPC
var mf_hpc = new CardFile(card_HPC, ":3F00");

print("Please enter PIN for HPC");
// Verify PIN for HPC
ok = mf_hpc.performCHV(true, 1);

if (!ok) {
	print("PIN Verification failed");
	exit;
}


// Activate explorer
try     {
	var egk = new OutlineCard(of, card_HIC, af, aidlist);
	egk.view.setContextMenu(["Verify PIN.CH", "Verify PIN.home"]);
	egk.actionListener = OutlineCardActionListener;
	
	var rootPuk = [ new Key("kp_cvc_root_test.xml"),
				    new Key("kp_cvc_root_testlabor.xml")];
	
	Card2CardAuthentication(card_HIC, card_HPC, rootPuk);

	print("");
	print("Right click on the eGK node to select PIN verification");
	print("before you select any DF or EF.");

	egk.view.show();
}

catch(e) {
	print("Problem accessing the card : " + e);
}
