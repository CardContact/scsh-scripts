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
 *  Script to read German KVK card
 */

//
// For this script to work correctly, you need a card reader that supports
// interindustry commands for synchronous cards. CT-API reader usually have this
// support.
//
 
var card = new Card(_scsh3.reader);

var mf = new CardFile(card, ":3F00");

var data = mf.readBinary();

print("Content of card:");
print(data);

var appl = new CardFile(card, "#D27600000101");

var data = appl.readBinary();

print("Content of application KVK:");
print(data);

print("...in ASN.1 encoding:");
print(new ASN1(data));

