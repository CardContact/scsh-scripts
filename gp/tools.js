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
 *  Global Platform Card Tools
 */

function GPAuthenticate(card, crypto, masterSENC, masterSMAC) {

	print("Sending INIT-UPDATE with host challenge...");
	var hostchallenge = crypto.generateRandom(8);
	var responseAPDU = card.sendApdu(0x80, 0x50, 0x00, 0x00, hostchallenge, 0x00, [0x9000]);
            
	var scp = responseAPDU.byteAt(11);
	
	if (scp == 1) {		// SCP01
		print("Using SCP01...");
		// Extract card challenge
		var cardChallenge = responseAPDU.bytes(12, 8);
		var cardCryptogram = responseAPDU.bytes(20, 8);
		
		var derivationParam = cardChallenge.bytes(4, 4).concat(
				      hostchallenge.bytes(0, 4)).concat(
				      cardChallenge.bytes(0, 4)).concat(
				      hostchallenge.bytes(4, 4));
				     
		print("Input to session key derivation: " + derivationParam);

		// Derive S-ENC session key

		var sessionSENC = new Key();
		crypto.deriveKey(masterSENC, Crypto.DES_ECB, derivationParam, sessionSENC);
            
            
		// Derive S-MAC session key
            
		var sessionSMAC = new Key();
		crypto.deriveKey(masterSMAC, Crypto.DES_ECB, derivationParam, sessionSMAC);
            
            
		// Determine input to card cryptogram verification
            
		var cardCryptogramInput = hostchallenge;
		cardCryptogramInput = cardCryptogramInput.concat(cardChallenge);
		cardCryptogramInput = cardCryptogramInput.concat(new ByteString("8000000000000000", HEX));
            
		print("Input to card cryptogram verification: " + cardCryptogramInput);
            
		if (!crypto.verify(sessionSENC, Crypto.DES_MAC, cardCryptogramInput, cardCryptogram)) {
		        print("Warning: Card cryptogram verification failed");
	//	        throw Error("Card cryptogram verification failed");
		}
            
            
		// Determine input to host cryptogram calculation
            
		var hostCryptogramInput = cardChallenge;
		hostCryptogramInput = hostCryptogramInput.concat(hostchallenge);
		hostCryptogramInput = hostCryptogramInput.concat(new ByteString("8000000000000000", HEX));
            
		print("Input to host cryptogram calculation: " + hostCryptogramInput);
            
		var hostCryptogram = crypto.sign(sessionSENC, Crypto.DES_MAC, hostCryptogramInput);
            
		print("Host cryptogram: " + hostCryptogram);

            
		// Create EXTERNAL AUTHENTICATE APDU 
            
		var extAutAPDU = new ByteString("8482000010", HEX);
		extAutAPDU = extAutAPDU.concat(hostCryptogram);
            
		var extAutAPDUPadded = extAutAPDU.concat(new ByteString("800000", HEX));
            
		var mac = crypto.sign(sessionSMAC, Crypto.DES_MAC, extAutAPDUPadded);
            
		var cdata = hostCryptogram.concat(mac);

		print("Performing external authentication...");
		card.sendApdu(0x84, 0x82, 0x00, 0x00, cdata, [0x9000]);
	} else {	// SCP 02
		print("Using SCP02...");
		// Extract sequence number and card challenge
		var sequence = responseAPDU.bytes(12, 2);
             
		var cardChallenge = responseAPDU.bytes(14, 6);
		var cardCryptogram = responseAPDU.bytes(20, 8);
		var derivationPostfix = sequence.concat(new ByteString("000000000000000000000000", HEX));
            
		// Derive S-ENC session key
            
		var derivationPrefix = new ByteString("0182", HEX);
		var derivationParam = derivationPrefix.concat(derivationPostfix);
            
		print("Input to session S-ENC derivation: " + derivationParam);

		var sessionSENC = new Key();            
		crypto.deriveKey(masterSENC, Crypto.DES_CBC, derivationParam, sessionSENC);
            
            
		// Derive S-MAC session key
            
		var derivationPrefix = new ByteString("0101", HEX);
		var derivationParam = derivationPrefix.concat(derivationPostfix);
            
		print("Input to session S-MAC derivation: " + derivationParam);

		var sessionSMAC = new Key();
		crypto.deriveKey(masterSMAC, Crypto.DES_CBC, derivationParam, sessionSMAC);
            
            
		// Determine input to card cryptogram verification
            
		var cardCryptogramInput = hostchallenge.concat(sequence);
		cardCryptogramInput = cardCryptogramInput.concat(cardChallenge);
		cardCryptogramInput = cardCryptogramInput.concat(new ByteString("8000000000000000", HEX));
            
		print("Input to card cryptogram verification: " + cardCryptogramInput);
            
		if (!crypto.verify(sessionSENC, Crypto.DES_MAC, cardCryptogramInput, cardCryptogram)) {
		        print("Warning: Card cryptogram verification failed");
	//	        throw Error("Card cryptogram verification failed");
		}
            
            
		// Determine input to host cryptogram calculation
            
		var hostCryptogramInput = sequence.concat(cardChallenge);
		hostCryptogramInput = hostCryptogramInput.concat(hostchallenge);
		hostCryptogramInput = hostCryptogramInput.concat(new ByteString("8000000000000000", HEX));
            
		print("Input to host cryptogram calculation: " + hostCryptogramInput);
            
		var hostCryptogram = crypto.sign(sessionSENC, Crypto.DES_MAC, hostCryptogramInput);
            
		print("Host cryptogram: " + hostCryptogram);

            
		// Create EXTERNAL AUTHENTICATE APDU 
            
		var extAutAPDU = new ByteString("8482000010", HEX);
		extAutAPDU = extAutAPDU.concat(hostCryptogram);
            
		var extAutAPDUPadded = extAutAPDU.concat(new ByteString("800000", HEX));
            
		var mac = crypto.sign(sessionSMAC, Crypto.DES_MAC_EMV, extAutAPDUPadded);
            
		var cdata = hostCryptogram.concat(mac);

		print("Performing external authentication...");
		card.sendApdu(0x84, 0x82, 0x00, 0x00, cdata, [0x9000]);
	}
	print("Done...");
}

 
