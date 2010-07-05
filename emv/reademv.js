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

try	{
	var card = new Card(_scsh3.reader);
	card.reset(Card.RESET_COLD);
	
	var aid = new ByteString("A0000000041010", HEX); // MC
//	var aid = new ByteString("A0000000031010", HEX); // VISA
	
//	var aid = new ByteString("1PAY.SYS.DDF01", ASCII);


	
	var fcp = card.sendApdu(0x00, 0xA4, 0x04, 0x00, aid, 0x00, [0x9000]);
	
	print("FCP returned in SELECT: ", new ASN1(fcp));
	
	for (var sfi = 1; sfi <= 31; sfi++) {
		for (var rec = 1; rec <= 16; rec++) {
			//print(((sfi << 3) | 4).toString(16));
			
			var tlv = card.sendApdu(0x00, 0xB2, rec, (sfi << 3) | 4, 0x00);
			if (card.SW == 0x9000) {
				print("SFI " + sfi.toString(16) + " record #" + rec);
				try	{
					var asn = new ASN1(tlv);
					print(asn);
				}
				catch(e) {
					print(tlv.toString(HEX));
				}
			}
		}
	}
}

catch(e) {
	print("Exception reading from Credit Card Application: " + e.toString());
}
