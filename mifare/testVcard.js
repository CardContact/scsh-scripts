/**
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
 * @fileoverview Example NDEF messages with a vCard
 */


load("ndef.js");
load("vcard.js");
load("loader.js");

var v = new Vcard();

v.setFormattedName("Max Mustermann");
v.setOrganization("CardContact");
v.addTelephone(null, "1234");
v.addEmail("CardContact@CardContact.de");
v.setUrl("www.cardcontact.de");

var enc = v.getEncoded();

var n = Ndef.newMessage("text/x-vCard", enc);

enc = n.getEncoded();

var loader = new Loader();
loader.initialize();
loader.load(enc);

