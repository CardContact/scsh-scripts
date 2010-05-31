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
 * @fileoverview Class supporting EMV cards
 */


/**
 * EMV class constructor
 */
function EMV(card, crypto) {
	this.card = card;
	this.crypto = crypto;
	
	this.cardDE = new Array();
	this.terminalDE = new Array();
	
//	this.terminalDE[] = crypto.generateRandom(4);
}



/**
 * Send SELECT APDU
 */
EMV.prototype.select = function(dfname, first) {
	var fci = this.card.sendApdu(0x00, 0xA4, 0x04, (first ? 0x00 : 0x02), dfname, 0x00);
	return(fci);
}



/**
 * Send READ RECORD APDU
 *
 * Return empty ByteString if no data was read
 */
EMV.prototype.readRecord = function(sfi, recno) {
	var data = this.card.sendApdu(0x00, 0xB2, recno, (sfi << 3) | 0x04, 0);
	if (this.card.SW1 == 0x6C) {
		var data = this.card.sendApdu(0x00, 0xB2, recno, (sfi << 3) | 0x04, this.card.SW2);
	}
	
	return(data);
}



/**
 * Send GET PROCESSING OPTION APDU
 *
 * 
 */
EMV.prototype.getProcessingOptions = function(pdol) {
	var pdol = new ByteString("8300", HEX);
	var data = this.card.sendApdu(0x80, 0xA8, 0x00, 0x00, pdol, 0);
	
	return(data);
}



/**
 * Select and read Payment System Environment on either
 * contact or contactless card
 */
EMV.prototype.selectPSE = function(contactless) {
	this.PSE = null;

	var dfname = (contactless ? EMV.prototype.PSE2 : EMV.prototype.PSE1);
	var fci = this.select(dfname, true);
	print(fci);
	if (fci.length == 0) {
		GPSystem.trace("No " + dfname.toString(ASCII) + " found");
		return;
	}
	
	// Decode FCI Template
	var tl = new TLVList(fci, TLV.EMV);
	var t = tl.index(0);
	assert(t.getTag() == EMV.prototype.FCI);
	var tl = new TLVList(t.getValue(), TLV.EMV);
	assert(tl.length >= 2);
	
	// Decode DF Name
	t = tl.index(0);
	assert(t.getTag() == EMV.prototype.DFNAME);
	
	// Decode FCI Proprietary Template
	t = tl.index(1);
	assert(t.getTag() == EMV.prototype.FCI_ISSUER);
	
	var tl = new TLVList(t.getValue(), TLV.EMV);
	
	// Decode SFI of the Directory Elementary File
	t = tl.index(0);
	assert(t.getTag() == EMV.prototype.SFI);
	var sfi = t.getValue();
	assert(sfi.length == 1);
	sfi = sfi.byteAt(0);

	this.PSE = new Array();
	
	// Read all records from Directory Elementary File
	var recno = 1;
	do	{
		var data = this.readRecord(sfi, recno++);
		if (data.length > 0) {
			var tl = new TLVList(data, TLV.EMV);
			assert(tl.length == 1);
			var t = tl.index(0);
			assert(t.getTag() == EMV.prototype.TEMPLATE);
			var tl = new TLVList(t.getValue(), TLV.EMV);
			assert(tl.length >= 1);
			for (var i = 0; i < tl.length; i++) {
				var t = tl.index(i);
				assert(t.getTag() == 0x61);
				this.PSE.push(new TLVList(t.getValue(), TLV.EMV));
			}
		}
	} while (data.length > 0);
}



/**
 * Return array of PSE entries or null if none defined
 */
EMV.prototype.getPSE = function() {
	return this.PSE;
}



/**
 * Return AID of application with highest priority or null if no PSE defined
 */
EMV.prototype.getAID = function() {

	var prio = 0xFFFF;
	var aid = null;
	var pse = e.getPSE();
	if (pse == null) {
		return null;
	}
	// Iterate through PSE entries
	for (var i = 0; i < pse.length; i++) {
		var t = pse[i].find(EMV.prototype.AID);
		assert(t != null);
		var entryAid = t.getValue();
		print(entryAid);

		var t = pse[i].find(EMV.prototype.LABEL);
		assert(t != null);
		print(t.getValue().toString(ASCII));

		var entryPrio = 0xFFFE;
		var t = pse[i].find(EMV.prototype.PRIORITY);
		if (t != null) {
			entryPrio = t.getValue().toUnsigned();
			entryPrio &= 0x0F;
		}
		if (entryPrio < prio) {
			prio = entryPrio;
			aid = entryAid;
		}
	}
	return aid;
}



/**
 * Select application and return FCI
 */
EMV.prototype.selectADF = function(aid) {
	var fci = this.select(aid, true);
	print(fci);
	
}



/**
 * Try a list of predefined AID in order to select an application
 */
EMV.prototype.tryAID = function() {
	for (var i = 0; i < EMV.prototype.AIDLIST.length; i++) {
		var le = EMV.prototype.AIDLIST[i];
		var aid = new ByteString(le.aid, HEX);
		var fci = this.select(aid, true);
		
		if (fci.length > 0) {
			return;
		}
	}
}



EMV.prototype.addCardDEFromList = function(tlvlist) {
	for (var i = 0; i < tlvlist.length; i++) {
		var t = tlvlist.index(i);
		print(t.getTag().toString(16) + " - " + t.getValue());
		this.cardDE[t.getTag()] = t.getValue();
	}
}



EMV.prototype.initApplProc = function() {
	var data = this.getProcessingOptions(null);
	print(data);
	var tl = new TLVList(data, TLV.EMV);
	assert(tl.length == 1);
	var t = tl.index(0);
	if (t.getTag() == EMV.prototype.RMTF1) {	// Format 1
		this.cardDE[EMV.prototype.AIP] = t.getValue().left(2);
		this.cardDE[EMV.prototype.AFL] = t.getValue().bytes(2);
	} else {
		assert(t.getTag() == EMV.prototype.RMTF2);
		tl = new TLVList(t.getValue(), TLV.EMV);
		assert(tl.length >= 2);
		this.addCardDEFromList(tl);
	}
}



/**
 * Read application data as indicated in the Application File Locator
 * Collect input to data authentication
 *
 */
EMV.prototype.readApplData = function() {
	// Application File Locator must exist
	assert(typeof(this.cardDE[EMV.prototype.AFL]) != "undefined");
	var afl = this.cardDE[EMV.prototype.AFL];
	
	// Must be a multiple of 4
	assert((afl.length & 0x03) == 0);

	// Collect input to data authentication	
	var da = new ByteBuffer();
	
	while(afl.length > 0) {
		var sfi = afl.byteAt(0) >> 3;	// Short file identifier
		var srec = afl.byteAt(1);	// Start record
		var erec = afl.byteAt(2);	// End record
		var dar = afl.byteAt(3);	// Number of records included in data authentication
		
		for (; srec <= erec; srec++) {
			// Read all indicated records
			var data = this.readRecord(sfi, srec);
			print(data);
			
			// Decode template
			var tl = new TLVList(data, TLV.EMV);
			assert(tl.length == 1);
			var t = tl.index(0);
			assert(t.getTag() == EMV.prototype.TEMPLATE);

			// Add data authentication input			
			if (dar > 0) {
				if (sfi <= 10) {	// Only value
					da.append(t.getValue());
				} else {		// Full template
					da.append(data);
				}
				dar--;
			}

			// Add card based data elements	to internal list
			var tl = new TLVList(t.getValue(), TLV.EMV);
			this.addCardDEFromList(tl);
		}

		// Continue with next entry in AFL
		afl = afl.bytes(4);
	}
	this.daInput = da.toByteString();
	print(this.daInput);
}



EMV.prototype.processDOL = function(dol) {
	
}



// Constants

EMV.prototype.PSE1 = new ByteString("1PAY.SYS.DDF01", ASCII);
EMV.prototype.PSE2 = new ByteString("2PAY.SYS.DDF01", ASCII);

EMV.prototype.AID = 0x4F;
EMV.prototype.LABEL = 0x50;
EMV.prototype.FCI = 0x6F;
EMV.prototype.TEMPLATE = 0x70;
EMV.prototype.RMTF2 = 0x77;
EMV.prototype.RMTF1 = 0x80;
EMV.prototype.AIP = 0x82;
EMV.prototype.DFNAME = 0x84;
EMV.prototype.PRIORITY = 0x87;
EMV.prototype.SFI = 0x88;
EMV.prototype.CDOL1 = 0x8C;
EMV.prototype.CDOL2 = 0x8D;
EMV.prototype.CAPKI = 0x8F;
EMV.prototype.AFL = 0x94;
EMV.prototype.FCI_ISSUER = 0xA5;
EMV.prototype.UN = 0x9F36;
EMV.prototype.SDATL = 0x9F4A;

EMV.prototype.AIDLIST = new Array();
EMV.prototype.AIDLIST[0] = { aid : "A00000002501", partial : true, name : "AMEX" };
EMV.prototype.AIDLIST[1] = { aid : "A0000000031010", partial : false, name : "VISA" };
EMV.prototype.AIDLIST[2] = { aid : "A0000000041010", partial : false, name : "MC" };

EMV.prototype.TAGLIST = new Array();
EMV.prototype.TAGLIST[EMV.prototype.UN] = { name : "Unpredictable Number" };
EMV.prototype.TAGLIST[EMV.prototype.CAPKI] = { name : "Certification Authority Public Key Index" };
EMV.prototype.TAGLIST[EMV.prototype.SDATL] = { name : "Static Data Authentication Tag List" };
EMV.prototype.TAGLIST[EMV.prototype.CDOL1] = { name : "Card Risk Management Data Object List 1" };
EMV.prototype.TAGLIST[EMV.prototype.CDOL2] = { name : "Card Risk Management Data Object List 2" };


// Example code
var card = new Card(_scsh3.reader);
card.reset(Card.RESET_COLD);

var crypto = new Crypto();

var e = new EMV(card, crypto);

e.selectPSE(false);

var aid = e.getAID();

if (aid != null) {
	e.selectADF(aid);
} else {
	e.tryAID();
}

e.initApplProc();
e.readApplData();

card.close();
