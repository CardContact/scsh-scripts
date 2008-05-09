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
 *  PKCS15 explorer
 */


load("tools/CardOutlineFactory2.0.js");

// Create crypto object
var crypto = new Crypto();

// Create application factory that holds all application profiles
var af = new ApplicationFactory(crypto);

// Add ec-card application profiles
af.addApplicationProfile("ap_mf.xml");
af.addApplicationProfile("ap_pkcs15.xml");
        
// Create card object
var card = new Card(_scsh3.reader, "cp_pkcs15.xml");

// Create card outline factory
var of = new CardOutlineFactory();

// Create list of AIDs, just in case the EF.DIR is empty
// This is just temporary to make sure the explorer works
// even for card with a defect in EF.DIR

var aidlist = new Array();

// and go...
// try     {
        var c = new OutlineCard(of, card, af, aidlist);
        c.view.show();
// }

// catch(e) {
//        print("Problem accessing the card: " + e);
//}
