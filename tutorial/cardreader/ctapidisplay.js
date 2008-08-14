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
 */

//
// Example how to use Java classes from within scripts
// Display a text on a CT-API compliant card terminal with a display
//

// 1. Get CardTerminalRegistry from OpenCard Framework

var ctr = Packages.opencard.core.terminal.CardTerminalRegistry.getRegistry();

// 2. Get CardTerminal instance for a given name

if (_scsh3.reader) {
	var ct = ctr.cardTerminalForName(_scsh3.reader);
} else {
	// Use default if no reader is configured
	var ct = ctr.cardTerminalForName("MCT");
}

// 3. Prepare message to display (TLV object with tag '50')

var text = "Hello World";
var displayObject = new ASN1(0x50, new ByteString(text, ASCII));

// 4. Create display APDU (see MKT specification, part 4, chapter 6.2.3
// CLA = 20, INS = 17, P1 = 40 (Display), P2 = 00

var apdu = new ByteBuffer("20174000", HEX);
apdu.append(displayObject.size);
apdu.append(displayObject.getBytes());

// 5. Send to card reader

var response = ct.sendTerminalCommand(apdu.toByteString());

print(response);
