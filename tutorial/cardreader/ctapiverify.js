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
// Perform verification with PIN input on the card reader
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

// 3. Create command to perform
//      Control Byte | Offset | APDU

var ctp = new ByteString("4206002000010824FFFFFFFFFFFFFF", HEX);
//or: var ctp = new ByteString("420600200001", HEX);
var ctpdo = new ASN1(0x52, ctp);

// 4. Prepare message to display (TLV object with tag '50')

var text = "Please enter PIN";
var displayObject = new ASN1(0x50, new ByteString(text, ASCII));

// 5. Create display APDU (see MKT specification, part 4, chapter 6.2.3
// CLA = 20, INS = 18, P1 = 01 (Slot#1), P2 = 00 (PIN-PAD)

var capdu = new ByteBuffer("20180100", HEX);
capdu.append(ctpdo.size + displayObject.size);
capdu.append(ctpdo.getBytes());
capdu.append(displayObject.getBytes());

// 5. Send to card reader

print(capdu.toByteString());
var response = ct.sendTerminalCommand(capdu.toByteString());

print(response);
