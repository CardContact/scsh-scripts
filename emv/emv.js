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
 * @class This class implements functions for tansaction process 
 * @constructor
 * @param {card} the card object 
 * @param {crypto} crypto
 */
function EMV(card, crypto) {
	this.card = card;
	this.crypto = crypto;
	
	this.cardDE = new Array();
	this.terminalDE = new Array();
	
	this.terminalDE[EMV.UN] = crypto.generateRandom(4);
}


/**
 * Return cardDE
 *
 * @return the cardDE array 
 * @type Array
 */
EMV.prototype.getCardDataElements = function() {
	return this.cardDE;
}



/**
 * Send SELECT APDU
 *
 * @param {dfname} dfname the PSE AID
 * @param {first} first the selection options
 * @return the FCI
 * @type ByteString
 */
EMV.prototype.select = function(dfname, first) {
	var fci = this.card.sendApdu(0x00, 0xA4, 0x04, (first ? 0x00 : 0x02), dfname, 0x00);
	return(fci);
}



/**
 * Send READ RECORD APDU
 *
 * @param {sfi} the SFI
 * @param {recno} the record number
 * @return the corresponding record or empty ByteString if no data was read
 * @type ByteString
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
 * @param{pdol} the Processing Data Object List
 * @return the Application Interchange Profile and the Application File Locator
 * @type ByteString
 */
EMV.prototype.getProcessingOptions = function(pdol) {
	if (pdol == null) {
		//var pdol = new ByteString("8300", HEX);						// OTHER
		//var pdol = new ByteString("830B0000000000000000000000", HEX);	// VISA
		//var pdol = new ByteString("830B2028C00276160200000000", HEX);	// VISA mit generate ac support
		var pdol = new ByteString("830B2028C00276150200000000", HEX);
	
	}
	var data = this.card.sendApdu(0x80, 0xA8, 0x00, 0x00, pdol, 0);
	
	return(data);
}



/**
 * <p>Select and read Payment System Environment on either
 * contact or contactless card</p>
 *
 * @param{contactless} the PSE AID
 */
EMV.prototype.selectPSE = function(contactless) {
	this.PSE = null;

	var dfname = (contactless ? EMV.PSE2 : EMV.PSE1);
	var fci = this.select(dfname, true);
	print(fci);
	if (fci.length == 0) {
		GPSystem.trace("No " + dfname.toString(ASCII) + " found");
		return;
	}
	
	// Decode FCI Template
	var tl = new TLVList(fci, TLV.EMV);
	var t = tl.index(0);
	assert(t.getTag() == EMV.FCI);
	var tl = new TLVList(t.getValue(), TLV.EMV);
	assert(tl.length >= 2);
	
	// Decode DF Name
	t = tl.index(0);
	assert(t.getTag() == EMV.DFNAME);
	
	// Decode FCI Proprietary Template
	t = tl.index(1);
	assert(t.getTag() == EMV.FCI_ISSUER);
	
	var tl = new TLVList(t.getValue(), TLV.EMV);
	
	// Decode SFI of the Directory Elementary File
	t = tl.index(0);
	assert(t.getTag() == EMV.SFI);
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
			assert(t.getTag() == EMV.TEMPLATE);
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
 * @return array of PSE entries or null if none defined
 * @type Array
 */
EMV.prototype.getPSE = function() {
	return this.PSE;
}



/**
 * @return AID of application with highest priority or null if no PSE defined
 * @type ByteString
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
		var t = pse[i].find(EMV.AID);
		assert(t != null);
		var entryAid = t.getValue();
		print(entryAid);

		var t = pse[i].find(EMV.LABEL);
		assert(t != null);
		print(t.getValue().toString(ASCII));

		var entryPrio = 0xFFFE;
		var t = pse[i].find(EMV.PRIORITY);
		if (t != null) {
			entryPrio = t.getValue().toUnsigned();
			entryPrio &= 0x0F;
		}
		if (entryPrio < prio) {
			prio = entryPrio;
			aid = entryAid;
		}
	}
	this.cardDE[EMV.AID] = aid;
	return aid;
}



/**
 * Select application and return FCI
 */
EMV.prototype.selectADF = function(aid) {
	var fci = this.select(aid, true);
	print(fci);
	// FCI dekodieren
	// DE aus FCI in this.cardDE aufnehmen
	this.cardDE[EMV.AID] = aid;
}



/**
 * Try a list of predefined AID in order to select an application
 */
EMV.prototype.tryAID = function() {
	for (var i = 0; i < EMV.AIDLIST.length; i++) {
		var le = EMV.AIDLIST[i];
		var aid = new ByteString(le.aid, HEX);
		var fci = this.select(aid, true);
		
		if (fci.length > 0) {
			this.cardDE[EMV.AID] = aid;
			print("FCI returned in SELECT: ", new ASN1(fci));
			return;
		}
	}
}


/**
 * Add elements from ByteString into the cardDE array
 */
EMV.prototype.addCardDEFromList = function(tlvlist) {
	for (var i = 0; i < tlvlist.length; i++) {
		var t = tlvlist.index(i);
		print(t.getTag().toString(16) + " - " + t.getValue());
		this.cardDE[t.getTag()] = t.getValue();
	}
}

/**
 * Inform the ICC that a new transaction is beginning
 * Store AIP and AFL into the cardDE array
 */
EMV.prototype.initApplProc = function() {
	// Create PDOL
	var data = this.getProcessingOptions(null);
	print(data);
	var tl = new TLVList(data, TLV.EMV);
	assert(tl.length == 1);
	var t = tl.index(0);
	if (t.getTag() == EMV.RMTF1) {	// Format 1
		this.cardDE[EMV.AIP] = t.getValue().left(2);
		this.cardDE[EMV.AFL] = t.getValue().bytes(2);
	} else {
		assert(t.getTag() == EMV.RMTF2);
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
	assert(typeof(this.cardDE[EMV.AFL]) != "undefined");
	var afl = this.cardDE[EMV.AFL];
	
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
			assert(t.getTag() == EMV.TEMPLATE);

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

/**
 * @return the Data Authentication Input
 */
EMV.prototype.getDAInput = function() {
	return this.daInput;
}


EMV.prototype.processDOL = function(dol) {
	
}


/**
 * Send GENERATE APPLICATION CRYPTOGRAM APDU
 */
EMV.prototype.generateAC = function() {
/*
p1
0x00 = AAC = reject transaction
0x40 = TC = proceed offline
0x80 = ARQC = go online
*/

var p1 = 0x40;

var authorisedAmount = new ByteString("000000000001", HEX);
var secondaryAmount = new ByteString("000000000000", HEX);
var tvr = new ByteString("0000000000", HEX);
var transCurrencyCode = new ByteString("0978", HEX);
var transDate = new ByteString("090730", HEX);
var transType = new ByteString("21", HEX);
var unpredictableNumber = crypto.generateRandom(4);
var iccDynamicNumber = card.sendApdu(0x00, 0x84, 0x00, 0x00, 0x00);
var DataAuthCode = this.cardDE[0x9F45];

var Data = authorisedAmount.concat(secondaryAmount).concat(tvr).concat(transCurrencyCode).concat(transDate).concat(transType).concat(unpredictableNumber).concat(iccDynamicNumber).concat(DataAuthCode); 

var generateAC = card.sendApdu(0x80, 0xAE, p1, 0x00, Data, 0x00);
}

// Constants

EMV.PSE1 = new ByteString("1PAY.SYS.DDF01", ASCII);
EMV.PSE2 = new ByteString("2PAY.SYS.DDF01", ASCII);

EMV.AID = 0x4F;
EMV.LABEL = 0x50;
EMV.FCI = 0x6F;
EMV.TEMPLATE = 0x70;
EMV.RMTF2 = 0x77;
EMV.RMTF1 = 0x80;
EMV.AIP = 0x82;
EMV.DFNAME = 0x84;
EMV.PRIORITY = 0x87;
EMV.SFI = 0x88;
EMV.CDOL1 = 0x8C;
EMV.CDOL2 = 0x8D;
EMV.CAPKI = 0x8F;
EMV.AFL = 0x94;
EMV.FCI_ISSUER = 0xA5;
EMV.UN = 0x9F37;
EMV.SDATL = 0x9F4A;

EMV.AIDLIST = new Array();
EMV.AIDLIST[0] = { aid : "A00000002501", partial : true, name : "AMEX" };
EMV.AIDLIST[1] = { aid : "A0000000031010", partial : false, name : "VISA" };
EMV.AIDLIST[2] = { aid : "A0000000041010", partial : false, name : "MC" };

EMV.TAGLIST = new Array();
EMV.TAGLIST[EMV.UN] = { name : "Unpredictable Number" };
EMV.TAGLIST[EMV.CAPKI] = { name : "Certification Authority Public Key Index" };
EMV.TAGLIST[EMV.SDATL] = { name : "Static Data Authentication Tag List" };
EMV.TAGLIST[EMV.CDOL1] = { name : "Card Risk Management Data Object List 1" };
EMV.TAGLIST[EMV.CDOL2] = { name : "Card Risk Management Data Object List 2" };

//EMV.pdol = 0x9F38179F1A0200009F33030000009F3501009F40050000000000;



/*
EMV.terminalDE[0x9F1A] = "9F1A020000";
this.terminalDE[0x9F33] = "9F3303000000";
this.terminalDE[0x9F35] = "9F350100";
this.terminalDE[0x9F40] = "9F40050000000000";

this.terminalDE[0x9F1A] = new ByteString("9F1A020000", HEX);
this.terminalDE[0x9F33] = new ByteString("9F3303000000", HEX);
this.terminalDE[0x9F35] = new ByteString("9F350100", HEX);
this.terminalDE[0x9F40] = new ByteString("9F40050000000000", HEX);
*/