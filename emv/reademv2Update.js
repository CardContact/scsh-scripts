//
//  ---------
// |.##> <##.|  CardContact Software & System Consulting
// |#       #|  32429 Minden, Germany (www.cardcontact.de)
// |#       #|  Copyright (c) 1999-2005. All rights reserved
// |'##> <##'|  See file COPYING for details on licensing
//  --------- 
//
// Read some data from MasterCard EMV card
// 


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

CVM = [];
CVM[0] = "Fail CVM processing";
CVM[1] = "Plaintext PIN verification performed by ICC";
CVM[2] = "Enciphered PIN verified online";
CVM[3] = "Plaintext PIN verification performed by ICC and signature (paper)";
CVM[4] = "Enciphered PIN verification performed by ICC";
CVM[5] = "Enciphered Pin verification performed by ICC and signature (paper)";
CVM[0x1E] = "Signature (paper)";
CVM[0x1F] = "No CVM required";

DOL = [];
DOL[0x9F02] = "Authorised amount of the transaction (excluding adjustments)";
DOL[0x9F03] = "Secondary amount associated with the transaction representing a cashback amount";
DOL[0x9F1A] = "Terminal Country Code";
DOL[0x8A] = "Authorisation Response Code";
DOL[0x91] = "Issuer Authentication Data";
DOL[0x95] = "Terminal Verification Results";
DOL[0x5F2A] = "Transaction Currency Code";
DOL[0x9A] = "Transaction Date";
DOL[0x9C] = "Transaction Type";
DOL[0x9F37] = "Unpredictable Number";
DOL[0x9F35] = "Terminal Type";
DOL[0x9F45] = "Data Authentication Code";
DOL[0x9F4C] = "ICC Dynamic Number";
DOL[0x9F34] = "Cardholder Verification Method (CVM) Results";

DE = [];
DE[0x5A] = "Application Primary Account Number (PAN): ";
DE[0x87] = "Application Priority Indicator: ";
DE[0x88] = "Short File Identifier (SFI): ";
DE[0x8F] = "Certification Authority Public Key Index: ";
DE[0x90] = "Issuer Public Key Certificate: ";
DE[0x92] = "Issuer Public Key Remainder: ";
DE[0x93] = "Signed Static Application Data: ";
DE[0x5F24] = "Application Expiration Date (YYMMDD): ";
DE[0x5F25] = "Application Effective Date (YYMMDD): ";
DE[0x5F28] = "Issuer Country Code: ";
DE[0x5F34] = "Application Primary Account Number (PAN) Sequence Number: ";
DE[0x9F07] = "Application Usage Control: ";
DE[0x9F08] = "Application Version Number: ";
DE[0x9F32] = "Issuer Public Key Exponent: ";
DE[0x9F42] = "Application Currency Code: ";
DE[0x9F44] = "Application Currency Exponent: ";
DE[0x9F46] = "ICC Public Key Certificate: ";
DE[0x9F47] = "ICC Public Key Exponent: ";
DE[0x9F48] = "ICC Public Key Remainder: ";
DE[0x9F4A] = "Static Data Authentication Tag List: ";

/*
 * Decode an action code into a human readable form
 *
 * @param {ByteString} list the action code
 */
function decodeActionCode(list) {

	for (var j = 0; j < 5; j++) {
		var b = list.byteAt(j);
		print("  Byte " + (j + 1) + ": ");
	
		for (var i = 0; i < 8; i++) {
			var bit = 0x80 >> i;
			if ((b & bit) == bit) {
				print("    " + TVR[j][i]);
			}
		}
	}
}

/*
 * Decode a cardholder verification method list into a human readable form
 *
 * @param {ByteString} list the cardholder verification method list
 */
function decodeCVM(list) {
	for (var i = 8; i<list.length; i = i+2) {
		var b = list.byteAt(i);
		if((b&0x40)==0x40) {
			print("  Apply succeeding CV Rule if this CVM is unsuccessful");
		}
		else {
		print("  Fail cardholder verification if this CVM is unsuccessful");
		}
		print("    " + CVM[b & 0x3F]);
	}
}
/*
 * Decode a data object list into a human readable form
 *
 * <p>A data object list is a concatenation of data object identifiers, which each consist of
 *    a tag and a length field.</p>
 *
 * @param {ByteString} list the data object list
 */
function decodeDataObjectList(list) {

	var subL = list;
	
	while (subL.length > 0) {
		var b = subL.byteAt(0);
		if((b&0x1F)==0x1F){
			var tag2 = subL.left(2);
			var tag2 = tag2.toUnsigned();
			var	subL = subL.bytes(2);
			var subL = subL.bytes(1);	//Length Byte 			
		}
		else {
			var tag2 = subL.left(1);
			var tag2 = tag2.toUnsigned();
			var subL = subL.bytes(1);
			var subL = subL.bytes(1);   //Length Byte 	
		}
	print("  " + DOL[tag2]);
	}
}


/**
 * Decodes a template containing TLV data object into a human readable form
 *
 * @param {ASN1} asn the template containing TLV data objects
 */
function decodeDataElement(asn) {
	//print(asn);
	for ( var i = 0 ; i < asn.elements; i++) {
		var de = asn.get(i);
			
		var tag = de.tag;
		switch (tag) {
			case 0x57:
				var str = de.value.toString(HEX);
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
			case 0x8C:
				print("Card Risk Management Data Object List 1 (CDOL1): " + de.value.toString(HEX));
				decodeDataObjectList(de.value);
				print();
				break;
			case 0x8D: 
				print("Card Risk Management Data Object List 2 (CDOL2): " + de.value.toString(HEX));
				decodeDataObjectList(de.value);
				print();
				break;
			case 0x8E: 
				print("Cardholder Verification Method (CVM) List: " + de.value.toString(HEX));
				decodeCVM(de.value);
				print();
				break;
			case 0x5F20:
				print("Cardholder Name : " + de.value.toString(ASCII));
				break;
			case 0x5F30: 
				var string2 = de.value.toString(HEX);
				print("Service Code: " + string2.substr(1));
				print();
				break;
			case 0x9F0D:
				print("Issuer Action Code - Default: " + de.value.toString(HEX));
				decodeActionCode(de.value);
				print();
				break;
			case 0x9F0E:
				print("Issuer Action Code - Denial: " + de.value.toString(HEX));
				decodeActionCode(de.value);
				print();
				break;
			case 0x9F0F:
				print("Issuer Action Code - Online: " + de.value.toString(HEX));
				decodeActionCode(de.value);
				print();
				break;
			case 0x9F49: 
				print("Dynamic Data Authentication Data Object List (DDOL): " + de.value.toString(HEX));
				decodeDataObjectList(de.value);
				print();
				break;
			default:
				if(typeof(DE[tag]) == "undefined"){
					print("Unknown Class: " + de.tag.toString(HEX));
					print()
				}
				else{
					print(DE[tag] + de.value.toString(HEX));
					print();
				}
				break;					 
		}
	}
}



//try	{
	var card = new Card(_scsh3.reader);
	card.reset(Card.RESET_COLD);
	
//	var aid = new ByteString("A0000000041010", HEX); // MC
	var aid = new ByteString("A0000000031010", HEX); // VISA
	
//	var aid = new ByteString("1PAY.SYS.DDF01", ASCII);

	
	var fcp = card.sendApdu(0x00, 0xA4, 0x04, 0x00, aid, 0x00, [0x9000]);
	print("FCP returned in SELECT: ", new ASN1(fcp));
	
	for (var sfi = 1; sfi <= 31; sfi++) {
		for (var rec = 1; rec <= 16; rec++) {
			var tlv = card.sendApdu(0x00, 0xB2, rec, (sfi << 3) | 4, 0x00);
			if (card.SW == 0x9000) {
				print();
				print("SFI " + sfi.toString(16) + " record #" + rec);
				//print(tlv);
				var asn = null;
				try	{
					asn = new ASN1(tlv);
				}
				catch(e) {
					print("Can not decode TLV structure: " + e);
					print(tlv.toString(HEX));
				}
				if (asn != null) {
					decodeDataElement(asn);
					print("---------------");
				}
			}
		}
	}
//}

//catch(e) {
//	print("Exception reading from Credit Card Application: " + e.toString());
//}

