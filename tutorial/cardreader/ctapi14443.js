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
// Use 14443 low level commands with CT-API card reader
//

// 1. Get CardTerminalRegistry from OpenCard Framework

var ctr = Packages.opencard.core.terminal.CardTerminalRegistry.getRegistry();

// 2. Get CardTerminal instance for a given name

if (_scsh3.reader) {
	var ct = ctr.cardTerminalForName(_scsh3.reader);
}

// 3. Turn of antenna power
var cmd = new ByteString("poff", ASCII);

var apdu = new ByteBuffer("8070", HEX);
apdu.append(cmd.length);
apdu.append(0x00);
apdu.append(cmd.length);
apdu.append(cmd);

var response = ct.sendTerminalCommand(apdu.toByteString());
print(response);


// 4. Select type A
var cmd = new ByteString("oa", ASCII);

var apdu = new ByteBuffer("8070", HEX);
apdu.append(cmd.length);
apdu.append(0x00);
apdu.append(cmd.length);
apdu.append(cmd);

var response = ct.sendTerminalCommand(apdu.toByteString());
print(response);


// 5. Send REQA
var cmd = new ByteString("26", HEX);

var apdu = new ByteBuffer("8074E300", HEX);
apdu.append(cmd.length);
apdu.append(cmd);

var response = ct.sendTerminalCommand(apdu.toByteString());
print(response);



// 6. Send 1st SELECT
var cmd = new ByteString("9320", HEX);

var apdu = new ByteBuffer("80740300", HEX);
apdu.append(cmd.length);
apdu.append(cmd);

var response = ct.sendTerminalCommand(apdu.toByteString());
print(response);

var uid = response.bytes(0, response.length - 2);
print("UID=" + uid.toString(HEX));


// 7. Send 2nd SELECT
var cmd = new ByteString("9370", HEX);

var apdu = new ByteBuffer("80740F00", HEX);
apdu.append(cmd.length + uid.length);
apdu.append(cmd);
apdu.append(uid);

var response = ct.sendTerminalCommand(apdu.toByteString());
print(response);


// 8. Send RATS
var cmd = new ByteString("E080", HEX);

var apdu = new ByteBuffer("80740F00", HEX);
apdu.append(cmd.length);
apdu.append(cmd);

var response = ct.sendTerminalCommand(apdu.toByteString());
print(response);

