/*
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2013 CardContact Software & System Consulting
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
 *  Dump content of German contactless girogo card
 */


function getIssuer(id) {
	
	switch(id) {
		case 0x21:
			return "Öffentlich rechtliche und private Banken";
			break;
		case 0x22:
			return "Privat- und Geschäftsbanken";
			break;
		case 0x25:
			return "Sparkassen";
			break;
		case 0x29:
			return "Genossenschaftsbanken";
			break;
		default:
			return "unknown";
	}
}


function getConversionFactor(factor) {

	switch (factor) {    
		case 1:
			return 0.01;
		case 2:
			return 0.1;		
		case 4:
			return 1.0;
		case 8:
			return 10.0;
		case 16:
			return 100.0;
		case 32:
			return 1000.0;
	}
}


try	{
	var card = new Card(_scsh3.reader);

	var record;
	
	var mf = new CardFile(card, ":3F00");
	var df_boerse = new CardFile(card, "#D27600002545500200");
	
	var ef_karte = new CardFile(df_boerse, ":17");
	record = ef_karte.readRecord(1);

	print("Kartennummer: " + record.bytes(4, 5).toString(HEX));
	print("Herausgeber: " + getIssuer(record.byteAt(1)));
	print("Gültig seit: " + record.byteAt(14).toString(HEX) + "." + record.byteAt(13).toString(HEX) + "." + record.byteAt(12).toString(HEX));
	print("Gültig bis: " + record.byteAt(11).toString(HEX) + "/" + "20" + record.byteAt(10).toString(HEX));
	var currency = record.bytes(17, 3).toString(ASCII);
	print("Währung: " + currency);
	var conversionFactor = getConversionFactor(record.byteAt(20));
	
	var ef_betrag = new CardFile(df_boerse, ":18");
	record = ef_betrag.readRecord(1);
	var balance = record.bytes(0, 3).toString(HEX).valueOf();
	print("Aktuelles Guthaben: " + balance * conversionFactor + " " + currency);
	
	var ef_llog = new CardFile(df_boerse, ":1C");
	var recordNo = 1;
	record = ef_llog.readRecord(recordNo);
	
	print("Ladevorgänge: ");
	var counter = record.byteAt(2); // Number of load transactions
	
	while (counter-- >= 1) {
		print("(" + counter + ")");
		var date = record.bytes(24, 6);
		print(ByteString.valueOf(date.byteAt(3)).toString(HEX) + "." + ByteString.valueOf(date.byteAt(2)).toString(HEX) + "." + ByteString.valueOf(date.byteAt(0)).toString(HEX) + ByteString.valueOf(date.byteAt(1)).toString(HEX) + ", " + ByteString.valueOf(date.byteAt(4)).toString(HEX) + ":" + ByteString.valueOf(date.byteAt(5)).toString(HEX) + " Uhr");
		var amount = record.bytes(4, 3).toString(HEX).valueOf();
		var amountNew = record.bytes(7, 3).toString(HEX).valueOf();
		print("Betrag: " + amount * conversionFactor + " " + currency);
		print("Guthaben Neu: " + amountNew * conversionFactor + " " + currency);
		record = ef_llog.readRecord(++recordNo);
	}
	
	var ef_blog = new CardFile(df_boerse, ":1D");
	record = ef_blog.readRecord(1);
}

catch(e) {
	print("Exception reading from card: " + e);
}
