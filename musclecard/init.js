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
 *  MuscleCard Initialization
 *
 *  After loading the applet into a JavaCard, the data structure needs to be
 *  initialized. This is done through an undocumented setup APDU.
 *
 *  The contents of the APDU has been reverse engineered from the applet's code
 */


load("tools.js");

var card = new Card(_scsh3.reader);
card.reset(Card.RESET_COLD);

// Select Applet
card.sendApdu(0x00, 0xA4, 0x04, 0x00, mcaid, [0x9000]);

// Try MSCGetStatus
resp = card.sendApdu(0xB0, 0x3C, 0x00, 0x00, 0x05);

if (card.SW == 0x9C05) {
        print("Applet not initialized");
        
        // Initialize applet
        
        var initstr = new ByteBuffer();
        
        var defaultPwd = new ByteString("Muscle00", ASCII);
        var PIN0 = new ByteString("12345678", ASCII);
        var UPIN0 = new ByteString("12345678", ASCII);
        var PIN1 = new ByteString("12345678", ASCII);
        var UPIN1 = new ByteString("12345678", ASCII);

	// The applet verifies the default PIN0 value,...
        initstr.append(defaultPwd.length);
        initstr.append(defaultPwd);

	// ...then sets PIN 0,...
        initstr.append(0x10);   // PIN0 Tries
        initstr.append(0x10);   // UPIN0 Tries
        initstr.append(PIN0.length);
        initstr.append(PIN0);
        initstr.append(UPIN0.length);
        initstr.append(UPIN0);

	// ...PIN1,...        
        initstr.append(0x10);   // PIN1 Tries
        initstr.append(0x10);   // UPIN1 Tries
        initstr.append(PIN1.length);
        initstr.append(PIN1);
        initstr.append(UPIN1.length);
        initstr.append(UPIN1);

	// ... <unused>, ...
        initstr.append(new ByteString("0000", HEX));
        
        // ... memory size for keys and objects and ...
        initstr.append(new ByteString("1000", HEX));    // Memory Size

	// ... access control settings for creating objects, keys and PINs
        initstr.append(new ByteString("000000", HEX));  // ACL for Object, Key and PIN
        
        print(initstr);
        
        card.sendApdu(0xB0, 0x2A, 0x00, 0x00, initstr.toByteString());
        print(card.SW.toString(HEX));
        
        // Try MSCGetStatus
        resp = card.sendApdu(0xB0, 0x3C, 0x00, 0x00, 0x05);
} else {
	print("MuscleCard Applet already initialized");
}

if (card.SW1 == 0x61) {
	var rem = card.sendApdu(0x00, 0xC0, 0x00, 0x00, card.SW1);
	resp = resp.concat(rem);
}

printStatus(resp);
