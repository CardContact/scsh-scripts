/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2009 CardContact Software & System Consulting
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
 * @fileoverview EMV Data Model
 */

 

/**
 * Create an EMV data model
 * @class Class implementing an EMV data model
 * @constructor
 */ 
function EMVDataModel() {

}



/**
 * Return the application file locator
 */
EMVDataModel.prototype.getApplicationFileLocator = function() {
	return new ByteString("08010100 10010101 18010200 20010200", HEX);
}



/**
 * Return the application interchange profile
 */
EMVDataModel.prototype.getApplicationInterchangeProfile = function() {
	return new ByteString("1980", HEX);
}



/**
 * Return the list of EFs and their records
 */
EMVDataModel.prototype.getFiles = function() {
	return [
		{ sfi: 1, records: [
			new ByteString("70 81 8D 9F 6C 02 00 01 9F 62 06 00 00 00 00 01 C0 9F 63 06 00 00 00 07 80 00 56 4C 42 35 32 33 34 30 30 30 30 35 30 33 34 31 31 34 35 5E 20 2F 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 5E 31 36 30 32 32 30 32 34 39 39 32 30 30 33 39 38 39 31 34 39 38 31 30 30 30 37 34 31 39 36 36 9F 64 01 02 9F 65 02 00 E0 9F 66 02 00 1E 9F 6B 13 52 34 00 00 50 34 11 45 D1 60 22 02 14 98 10 00 04 00 0F 9F 67 01 02", HEX)
			]
		},
		{ sfi: 2, records: [
			new ByteString("70 81 A3 57 13 52 34 00 00 50 34 11 45 D1 60 22 01 14 98 19 09 04 00 0F 5A 08 52 34 00 00 50 34 11 45 5F 24 03 16 02 28 5F 30 02 02 02 9F 44 01 02 5F 28 02 02 80 5F 34 01 04 8C 21 9F 02 06 9F 03 06 9F 1A 02 95 05 5F 2A 02 9A 03 9C 01 9F 37 04 9F 35 01 9F 45 02 9F 4C 08 9F 34 03 8D 0C 91 0A 8A 02 95 05 9F 37 04 9F 4C 08 8E 0E 00 00 00 00 00 00 00 00 5E 03 42 03 1F 03 9F 07 02 FF 00 9F 08 02 00 02 9F 0D 05 B4 50 04 00 00 9F 0E 05 00 00 88 00 00 9F 0F 05 B4 70 04 98 00 9F 42 02 09 78 9F 4A 01 82", HEX)
			]
		},
		{ sfi: 3, records: [
			new ByteString("70 81 C0 8F 01 04 9F 32 01 03 92 24 94 EE D1 88 44 B8 C9 0A 55 5C AE 8B 39 16 86 C1 2A 30 ED 71 C2 81 D3 FA 90 EE B0 5E AF 29 8A E2 C9 D1 40 0F 90 81 90 27 18 3B 7E 0B 7D E4 47 D9 C5 2B 5A D9 58 CF 41 60 FD C0 A7 0D 84 C8 8A C9 B0 1B B4 B7 58 61 D8 36 B1 8D 15 4E 28 89 EF 50 CC A8 3E 76 43 B5 27 91 FF 1C C6 1B 1F 0A D6 16 1A F9 E6 8E 14 36 F5 73 07 EC 07 DB B3 04 B6 F1 78 C1 AF 68 3E 3D B7 17 41 32 19 69 95 DB F6 72 1B 13 89 2A CF 46 8A 14 06 60 8E 95 FD 97 7A 3F 34 3D 18 B6 1F 5D 77 E4 E7 9F A0 ED 5A 4B 5D 4B 57 C4 1A 29 E7 B7 FD 1E 9F 42 36 B0 BE ED FF 58 32 C3 6C E0 CF 14 AA", HEX),
			new ByteString("70 81 A3 9F 6E 0D 02 80 F0 01 22 09 92 00 39 89 74 19 66 93 81 90 06 8C 34 A1 42 BF A9 2B 88 FC 5D 86 AB 32 9C A8 19 DA E2 DF 38 85 F6 E1 4C 1B 8C CD 16 9F 58 F0 14 B9 3F 92 50 69 0C AC 6D 20 1F 9D 42 F3 00 B9 14 9C E4 C1 D1 6F FF 3B FB F5 F5 10 DC 6F A1 4F 9B F7 A3 8F BB 82 7F B5 18 FB 2C 00 6A 85 29 8B 84 1F 77 0F 3F 93 B8 33 9F 9F 83 63 6A 0C 49 88 4D 22 56 8F 32 70 E5 E0 7B F3 7F 77 58 5C C4 D4 B0 88 4C B0 24 3A 8C 3B 25 E8 85 AF EF 2E C3 2E CD 41 C7 44 DF AA 19 C7 30 2F 6F E0 4F 87 7F E5", HEX)
			]
		},
		{ sfi: 4, records: [
			new ByteString("70 27 9F 47 01 03 9F 48 1A F2 17 AC 6F 17 6D FD 58 00 92 6C 10 A9 85 DD BF 7B 1C FF D8 27 D7 C4 82 14 13 9F 49 03 9F 37 04", HEX),
			new ByteString("70 81 94 9F 46 81 90 83 88 29 E4 97 9D 3A B9 7D 69 48 14 CE D3 C7 DC B3 51 83 08 D5 EA 4F 72 A7 CF 48 29 EF 14 94 FD 4D A6 40 31 3E D6 75 93 8A 40 E2 94 17 53 32 AD 6C 18 FA 04 A9 65 DC 36 FF 7E 7C 6E 26 68 F0 E0 D3 72 0F 19 EA 80 11 34 DF 7B 7F 32 98 BE DF 9C 54 5A 9D F8 E5 AB E9 71 2D F6 1E 52 90 28 18 64 5A C3 F8 37 AA CB 3B E7 C6 DD 45 FF F5 92 71 E8 66 B5 BB 27 32 01 0A 8D 90 D1 83 97 AB BF FC E3 A6 5D DD 83 07 FC 23 09 26 53 A7 7D 5B 28 64 12", HEX)
			]
		}
	];
}

