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

// Read serial number from Identiv R-series reader

var card = new Card(_scsh3.reader);

// READER_GET_INFO_EXTENDED command
var cmd = new ByteString("1E", HEX);

if (java.lang.System.getProperty("os.name").indexOf("Linux") >= 0) {
	// Escape command is 1 on Linux and IOCTL code is 0x42000000 + command
	var ioctl = ByteString.valueOf(0x42000000 + 1, 4);
} else {
	// Escape command is 3500 on Windows and IOCTL code is 0x31000000 + (command << 2)
	var ioctl = ByteString.valueOf(0x310000 + (3500 << 2), 4);
}

var rsp = card.nativeCardTerminal.sendTerminalCommand(ioctl.concat(cmd));

print(rsp);

var ofs = 9;
var snlen = rsp.byteAt(ofs++) >> 1;
var bb = new ByteBuffer();
for (var i = 0; i < snlen; i++) {
	bb.append(rsp.byteAt(ofs));
	ofs += 2;
}

print(bb.toString(ASCII));
