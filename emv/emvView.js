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
 * @fileoverview The class EMVView displays data stored on emv cards.
 */

/**
 * EMVView class constructor
 *
 * @class This class implements a viewer for data stored on emv cards
 * @constructor
 * @requires EMV
 * @param {object} emv an instance of the EMV class
 */
function EMVView(emv) {
	this.emv = emv;
}

/**
 * Display the data elements into a human readable form
 */
EMVView.prototype.displayDataElements = function(){
	print("<----------------------------Display Data Elements-----------------------------");
	print();
	var cardDE = this.emv.getCardDataElements();
	
	print("cardDE.length=" + cardDE.length);
	for (var i = 0; i < cardDE.length; i++) {
		if(cardDE[i] != undefined){
			var tag = i; 
			var value= cardDE[i];
			this.decodeDataElement(tag, value);
		}
	}
	print("------------------------------------------------------------------------------>\n");
}

/**
 * Decodes a template containing TLV data object into a human readable form
 *
 * @param {Number}  tag containing the tag name of TLV data objects
 * @param {ASN1} value the template containing TLV data objects
 */
EMVView.prototype.decodeDataElement = function(tag, value) {
	switch (tag) {
		case 0x57:
			var str = value.toString(HEX);
			if (str.charAt(str.length-1) == 'F') {
				str = str.substr(0, str.length-1);
			}
			
			var separatorOfs = str.indexOf("D");
			var pan = str.substr(0, separatorOfs);
			var exDate = str.substr(separatorOfs+1, 4);
			var serCode = str.substr(separatorOfs+5, 3);
			var disData = str.substr(separatorOfs+8);
			
			print("Track 2 Equivalent Data (Magnetic Strip): ");
			print("  Primary Account Number: " + pan);
			print("  Expiration Date (YYMM): " + exDate);
			print("  Service Code: " + serCode);
			print("  Discretionary Data: " + disData);
			print("\n");
			break;
		case 0x82:
			print("Application Interchange Profile: " + value.toString(HEX))
			this.decodeAIP(value);
			print();
		case 0x8C:
			print("Card Risk Management Data Object List 1 (CDOL1): " + value.toString(HEX));
			this.decodeDataObjectList(value);
			print();
			break;
		case 0x8D: 
			print("Card Risk Management Data Object List 2 (CDOL2): " + value.toString(HEX));
			this.decodeDataObjectList(value);
			print();
			break;
		case 0x8E: 
			print("Cardholder Verification Method (CVM) List: " + value.toString(HEX));
			this.decodeCVM(value);
			print();
			break;
		case 0x94:
			print("Application File Locator: " + value.toString(HEX));
			this.decodeAFL(value);
			print();
			break;
		case 0x5F20:
			print("Cardholder Name : " + value.toString(ASCII));
			break;
		case 0x5F2D:
			print("Language Preference : " + value.toString(ASCII));
			break;
		case 0x5F30: 
			var string2 = value.toString(HEX);
			print("Service Code: " + string2.substr(1));
			print();
			break;
		case 0x9F07:
			print("Application Usage Control: " + value.toString(HEX));
			this.decodeAUC(value);
			print();
			break;
		case 0x9F0D:
			print("Issuer Action Code - Default: " + value.toString(HEX));
			this.decodeActionCode(value);
			print();
			break;
		case 0x9F0E:
			print("Issuer Action Code - Denial: " + value.toString(HEX));
			this.decodeActionCode(value);
			print();
			break;
		case 0x9F0F:
			print("Issuer Action Code - Online: " + value.toString(HEX));
			this.decodeActionCode(value);
			print();
			break;
		case 0x9F38: 
			print("Processing Options Data Object List (PDOL): " + value.toString(HEX));
			this.decodeDataObjectList(value);
			print();
			break;
		case 0x9F49: 
			print("Dynamic Data Authentication Data Object List (DDOL): " + value.toString(HEX));
			this.decodeDataObjectList(value);
			print();
			break;
		default:
			if(typeof(EMVView.DE[tag]) == "undefined"){
				print("Unknown Class: " + tag.toString(HEX));
					print()
				}
				else{
					print(EMVView.DE[tag] + value.toString(HEX));
					print();
				}
				break;				 
		}
}

/**
 * Decode a data object list into a human readable form
 *
 * <p>A data object list is a concatenation of data object identifiers, which each consist of
 *    a tag and a length field.</p>
 *
 * @param {ByteString} dol the data object list
 */
EMVView.prototype.decodeDataObjectList = function(dol) {
	while (dol.length > 0) {
		var b = dol.byteAt(0);
		if((b&0x1F)==0x1F){
			var tag = dol.left(2).toUnsigned();
			var length = dol.byteAt(2);		
			var dol = dol.bytes(3);	//Remove Tag and Length Byte		
		}
		else {
			var tag = dol.left(1).toUnsigned();
			var length = dol.byteAt(1);
			var dol = dol.bytes(2);   //Remove Tag and Length Byte
		}
		print("  " + tag.toString(HEX) + " - " + length + " - " + DOL[tag]);
	}
}

/**
 * Decode an action code into a human readable form
 *
 * @param {ByteString} actionCode the Action Code
 */
EMVView.prototype.decodeActionCode = function(actionCode) {

	for (var j = 0; j < 5; j++) {
		var b = actionCode.byteAt(j);
		print("  Byte " + (j + 1) + ": ");
	
		for (var i = 0; i < 8; i++) {
			var bit = 0x80 >> i;
			if ((b & bit) == bit) {
				print("    " + TVR[j][i]);
			}
		}
	}
}

/**
 * Decode an application interchange profile into a human readable form
 *
 * @param {ByteString} aip the Application Interchange Profile
 */
EMVView.prototype.decodeAIP = function(aip) {
	for (var j = 0; j < 2; j++) {
		var b = aip.byteAt(j);
		print("  Byte " + (j + 1) + ": ");
		
		for (var i = 0; i < 8; i++) {
			var bit = 0x80 >> i;
			if ((b & bit) == bit) {
				print("    " + AIP[j][i]);
			}
		}
	}
}

/**
 * Decode an application file locator into a human readable form
 *
 * @param {ByteString} afl the Application File Locator
 */
EMVView.prototype.decodeAFL = function(afl) {
	for (var i = 0; i < afl.length;) {
		for (var j = 0; j < 4; j++) {
			var b = afl.byteAt(i);
			//print("Hex: " + b.toString(HEX));
			switch(j) {
				case 0:
					var b = b >> 3;
					print("  SFI: " + b);
					break;
				case 1:
					print("  First/Only Record Number: " + b);
					break;
				case 2:
					print("  Last Record Number: " + b);
					break;
				case 3:
					print("  Number of records involved in offline data authentication: " + b);
					print();
					break;
				default:
					print("  Default: " + j);
					break;
			}
			i++;
		}
	}
}

/**
 * Decode a Cardholder Verification Method List into a human readable form
 *
 * @param {ByteString} cvmlist the Cardholder Verification Method List
 */
EMVView.prototype.decodeCVM = function(cvmlist) {
	for (var i = 8; i<cvmlist.length; i = i+2) {
		var b = cvmlist.byteAt(i);
		if((b&0x40)==0x40) {
			print("  Apply succeeding CV Rule if this CVM is unsucccessful");
		}
		else {
		print("  Fail cardholder verification if this CVM is unsuccessful");
		}
		print("    " + CVM[b & 0x3F]);
		print("  " + CVM2[cvmlist.byteAt(i+1)]);
		print();
	}
}

/**
 * Decode the Application Usage Control into a human readable form
 *
 * @param {ByteString} auc the Application Usage Control
 */
EMVView.prototype.decodeAUC = function(auc) {
	var byte1 = auc.byteAt(0);
	var byte2 = auc.byteAt(1);
	print("  Byte 1:");
	for (var i = 0; i <=7; i++) {		
		if(byte1 & Math.pow(2,i) == Math.pow(2,i)) {
			print("    " + AUC1[Math.pow(2,i)]);
		}
	}
	print("  Byte 2:");
	for (var i = 0; i <=7; i++) {		
		if(byte2 & Math.pow(2,i) == Math.pow(2,i)) {
			print("    " + AUC2[Math.pow(2,i)]);
		}
	}
}


AUC1 = [];
AUC1[0x01] = "Valid at terminals other than ATMs";
AUC1[0x02] = "Valid at ATMs";
AUC1[0x04] = "Valid for international services";
AUC1[0x08] = "Valid for domestic services";
AUC1[0x10] = "Valid for international goods";
AUC1[0x20] = "Valid for domestic goods";
AUC1[0x40] = "Valid for international cash transactions";
AUC1[0x80] = "Valid for domestic cash transactions";

AUC2 = [];
AUC2[0x01] = "RFU";
AUC2[0x02] = "RFU";
AUC2[0x04] = "RFU";
AUC2[0x08] = "RFU";
AUC2[0x10] = "RFU";
AUC2[0x20] = "RFU";
AUC2[0x40] = "International cashback allowed";
AUC2[0x80] = "Domestic cashback allowed";

TVR = [
		[	"Offline data authentication was not performed (b8)",
			"SDA failed (b7)",
			"ICC data missing (b6)",
			"Card appears on terminal exception file (b5)",
			"DDA failed (b4)",
			"CDA failed (b3)",
			"RFU (b2)",
			"RFU (b1)"
		],
		[   "ICC and terminal have different application versions (b8)",
		  	"Expired application (b7)",
		  	"Application not yet effective (b6)",
		  	"Requested service not allowed for card product (b5)",
		  	"New card (b4)",
			"RFU (b3)",
		  	"RFU (b2)",
		  	"RFU (b1)",
		],
		[	"Cardholder verification was not successful (b8)",
			"Unrecognised CVM (b7)",
			"PIN Try Limit exceeded (b6)",
			"PIN entry required and PIN pad not present or not working (b5)",
			"PIN entry required, PIN pad present, but PIN was not entered (b4)",
			"Online PIN entered (b3)",
			"RFU (b2)",
			"RFU (b1)",
		],
		[   "Transaction exceeds floor limit (b8)",
			"Lower consecutive offline limit exceeded (b7)",
			"Upper consecutive offline limit (b6)",
			"Transaction selected randomly for online processing (b5)",
			"Merchant forced transaction online (b4)",
			"RFU (b3)",
			"RFU (b2)",
			"RFU (b1)",
		],
		[	"Default TDOL used (b8)",
			"Issuer authentication failed (b7)",
			"Script processing failed before final GENERATE AC (b6)",
			"Script processing failed after final GENERATE AC (b5)",
			"RFU (b4)",
			"RFU (b3)",
			"RFU (b2)",
			"RFU (b1)",
		],	
	];

AIP = [
		[	"RFU (b8)",
			"SDA supported (b7)",
			"DDA supported (b6)",
			"Cardholder verification is supported (b5)",
			"Terminal risk management is to be performed (b4)",
			"Issuer authentication is supported (b3)",
			"RFU (b2)",
			"CDA supported (b1)",
		],
		[	"RFU (b8)",
			"RFU (b7)",
			"RFU (b6)",
			"RFU (b5)",
			"RFU (b4)",
			"RFU (b3)",
			"RFU (b2)",
			"RFU (b1)",
		],
	];

CVM = [];
CVM[0] = "Fail CVM processing";
CVM[1] = "Plaintext PIN verification performed by ICC";
CVM[2] = "Enciphered PIN verified online";
CVM[3] = "Plaintext PIN verification performed by ICC and signature (paper)";
CVM[4] = "Enciphered PIN verification performed by ICC";
CVM[5] = "Enciphered Pin verification performed by ICC and signature (paper)";
CVM[0x1E] = "Signature (paper)";
CVM[0x1F] = "No CVM required";

CVM2 = [];
CVM2[0] = "Always";
CVM2[1] = "If unattended cash";
CVM2[2] = "If not unattended cash and not manual cash and not purchase with cashback";
CVM2[3] = "If terminal supports the CVM";
CVM2[4] = "If manual cash";
CVM2[5] = "If purchase with cashback";
CVM2[6] = "If transaction is in the application currency and is under X value";
CVM2[7] = "If transaction is in the application currency and is over X value";
CVM2[8] = "If transaction is in the application currency and is under Y value";
CVM2[9] = "If transaction is in the application currency and is over Y value";
CVM2[10] = "RFU";
CVM2[11] = "Reserved for use by individual payment systems";


DOL = [];
DOL[0x5F2A] = "Transaction Currency Code";
DOL[0x8A] = "Authorisation Response Code";
DOL[0x91] = "Issuer Authentication Data";
DOL[0x95] = "Terminal Verification Results";
DOL[0x9A] = "Transaction Date";
DOL[0x9C] = "Transaction Type";
DOL[0x9F02] = "Authorised amount of the transaction (excluding adjustments)";
DOL[0x9F03] = "Secondary amount associated with the transaction representing a cashback amount";
DOL[0x9F1A] = "Terminal Country Code";
DOL[0x9F33] = "Terminal Capabilities";
DOL[0x9F34] = "Cardholder Verification Method (CVM) Results";
DOL[0x9F35] = "Terminal Type";
DOL[0x9F37] = "Unpredictable Number";
DOL[0x9F40] = "Additional Terminal Capabilities";
DOL[0x9F45] = "Data Authentication Code";
DOL[0x9F4C] = "ICC Dynamic Number";


EMVView.DE = [];
EMVView.DE[0x4F] = "Application Identifier (AID) - card: ";
EMVView.DE[0x50] = "Application Label: ";
EMVView.DE[0x5A] = "Application Primary Account Number (PAN): ";
EMVView.DE[0x5F2D] = "Language Preference: ";

EMVView.DE[0x5F24] = "Application Expiration Date (YYMMDD): ";
EMVView.DE[0x5F25] = "Application Effective Date (YYMMDD): ";
EMVView.DE[0x5F28] = "Issuer Country Code: ";
EMVView.DE[0x5F34] = "Application Primary Account Number (PAN) Sequence Number: ";
EMVView.DE[0x87] = "Application Priority Indicator: ";
EMVView.DE[0x88] = "Short File Identifier (SFI): ";
EMVView.DE[0x8F] = "Certification Authority Public Key Index: ";
EMVView.DE[0x90] = "Issuer Public Key Certificate: ";
EMVView.DE[0x92] = "Issuer Public Key Remainder: ";
EMVView.DE[0x93] = "Signed Static Application Data: ";
EMVView.DE[0x9F07] = "Application Usage Control: ";
EMVView.DE[0x9F08] = "Application Version Number: ";
EMVView.DE[0x9F32] = "Issuer Public Key Exponent: ";
EMVView.DE[0x9F42] = "Application Currency Code: ";
EMVView.DE[0x9F44] = "Application Currency Exponent: ";
EMVView.DE[0x9F45] = "Data Authentication Code: ";
EMVView.DE[0x9F46] = "ICC Public Key Certificate: ";
EMVView.DE[0x9F47] = "ICC Public Key Exponent: ";
EMVView.DE[0x9F48] = "ICC Public Key Remainder: ";
EMVView.DE[0x9F4A] = "Static Data Authentication Tag List: ";

