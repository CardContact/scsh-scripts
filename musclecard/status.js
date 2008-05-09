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
 *  Display the status of the MuscleCard Applet
 */

load("tools.js");

var reset = true;
var resp;

// If we still have a valid card handle, then we use GetStatus directly
if (typeof(card) != "undefined") {
	try	{
		// Try MSCGetStatus
		resp = card.sendApdu(0xB0, 0x3C, 0x00, 0x00, 0x05);
		reset = false;
	}
	catch(e) {
		// The card handle is no longer valid, e.g. the card
		// has been removed or replaced
	}
}

if (reset) {
	var card = new Card(_scsh3.reader);
	card.reset(Card.RESET_COLD);
	
	// Select Applet
	card.sendApdu(0x00, 0xA4, 0x04, 0x00, mcaid, [0x9000]);
	resp = card.sendApdu(0xB0, 0x3C, 0x00, 0x00, 0x05);
}


if (card.SW == 0x9C05) {
        print("Applet not initialized");
} else {
	if (card.SW1 == 0x61) {
		var rem = card.sendApdu(0x00, 0xC0, 0x00, 0x00, card.SW1);
		resp = resp.concat(rem);
	}

	printStatus(resp);

	// MSCListPINs	
	resp = card.sendApdu(0xB0, 0x48, 0x00, 0x00, 0x02, [0x9000]);
	var v = resp.toUnsigned();
	print("List PINs: " + accessMaskToString(v, "none", "all", ",") + " (" + v.toString(16) + ")");

	print("-- List Objects ------------------------------------------------");
	// MSCListObjects	

	resp = card.sendApdu(0xB0, 0x58, 0x00, 0x00, 0x0E);
	
	while(resp.length > 0) {
//		print(resp);

		print("  Object Id     : " + resp.bytes(0, 4));
		var objid = resp.bytes(0, 4).toUnsigned();
		var size = resp.bytes(4, 4).toUnsigned();
		print("  Size          : " + size);
		var v = resp.bytes(8, 2).toUnsigned();
		print("  Read Access   : " + accessConditionToString(v) + " (" + v.toString(16) + ")");
		var v = resp.bytes(10, 2).toUnsigned();
		print("  Write Access  : " + accessConditionToString(v) + " (" + v.toString(16) + ")");
		var v = resp.bytes(12, 2).toUnsigned();
		print("  Delete Access : " + accessConditionToString(v) + " (" + v.toString(16) + ")");

		try	{
			var content = readObject(card, objid, 0, size);
			print(content);
		}
		catch(e) {
			if (e instanceof GPError) {
				print("Error reading object - SW1/SW2 = " + e.reason.toString(16));
			} else {
				print("Exception reading object: " + e);
			}
		}
		
		resp = card.sendApdu(0xB0, 0x58, 0x01, 0x00, 0x0E);
	}

	print("-- List Keys ---------------------------------------------------");

	// MSCListKeys
	resp = card.sendApdu(0xB0, 0x3A, 0x00, 0x00, 0x0B);
	
	while(resp.length > 0) {
//		print(resp);
		print("  Key Number    : " + resp.byteAt(0));
		var v = resp.byteAt(1)
		print("  Key Type      : " + mckeytypes[v] + " (" + v + ")");
		print("  Key Partner   : " + resp.byteAt(2));
		print("  Key Size      : " + resp.bytes(3, 2).toUnsigned());
		var v = resp.bytes(5, 2).toUnsigned();
		print("  Read Access   : " + accessConditionToString(v) + " (" + v.toString(16) + ")");
		var v = resp.bytes(7, 2).toUnsigned();
		print("  Write Access  : " + accessConditionToString(v) + " (" + v.toString(16) + ")");
		var v = resp.bytes(9, 2).toUnsigned();
		print("  Use Access    : " + accessConditionToString(v) + " (" + v.toString(16) + ")");
		
		resp = card.sendApdu(0xB0, 0x3A, 0x01, 0x00, 0x0B);
	}
}