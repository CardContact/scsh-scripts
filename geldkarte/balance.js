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
 *  Read balance from German Geldkarte
 */


try	{
	var card = new Card(_scsh3.reader);

	var record;
	
	try	{
		var mf = new CardFile(card, ":3F00");
		var df_boerse = new CardFile(card, "#D27600002545500200");
		var ef_betrag = new CardFile(df_boerse, ":0104");

		record = ef_betrag.readRecord(1);
	}
	catch(e) {
		print("Trying old GeldKarte version");
		card.sendApdu(0x00, 0xA4, 0x04, 0x0C, new ByteString("D27600002545500100", HEX), [0x9000]);
		record = card.sendApdu(0x00, 0xB2, 0x01, 0xC4, 0x09, [0x9000]);
	}
	
	// Convert ByteString to String and read BCD coded value
	var balance = record.bytes(0, 3).toString(HEX).valueOf();
	print("Current balance : " + (balance / 100).toFixed(2) + " EUR");
	
}

catch(e) {
	print("Exception reading from GeldKarte: " + e);
}



