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
 *  GeldKarte Explorer
 */

load("tools/CardOutlineFactory.js");

// Create crypto object
var crypto = new Crypto();

// Create application factory that holds all application profiles
var af = new ApplicationFactory(crypto);

// Add ec-card application profiles
af.addApplicationProfile("ap_mf.xml");
af.addApplicationProfile("ap_geldkarte.xml");
	
// Create ec-card card object
var card = new Card(_scsh3.reader, "cp_eccard.xml");

// Create card outline factory
var of = new CardOutlineFactory();

// and go...
try     {
        var eccard = new OutlineCard(of, card, af);
        eccard.view.show();
}

catch(e) {
        print("No card in reader or problem with reset: " + e);
}

