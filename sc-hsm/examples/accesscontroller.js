/**
 *  ---------
 * |.##> <##.|  SmartCard-HSM Support Scripts
 * |#       #|  
 * |#       #|  Copyright (c) 2011-2012 CardContact Software & System Consulting
 * |'##> <##'|  Andreas Schwier, 32429 Minden, Germany (www.cardcontact.de)
 *  --------- 
 *
 * Consult your license package for usage terms and conditions.
 * 
 * @fileoverview Simple Physical Access Control Terminal Simulation
 *
 * <p>This simulation shows the use of a SmartCard-HSM card for physical access control. The device authentication key and cv certificate
 *    is used to authenticate the card towards the reader and to establish a secure communication channel to read access control data.</p>
 * <p>If a PIN code is entered at the reader, then the code will be presented to the card using the secure communication channel, 
 *    thereby protecting the PIN code against eavesdropping at the air interface.
 *    As the verification response from the card is protected with a message authentication code, the terminal
 *    can proof that the verification was actually performed by the card.
 * <p>This demo requires at least the 3.7.1574 version of the Smart Card Shell.</p>
 */
 
load("../lib/smartcardhsm.js");

 
function AccessController(crdreader) {
	this.crdreader = crdreader;
	this.accessTerminal = new AccessTerminal();

	// Create a crypto object
	this.crypto = new Crypto();
}



AccessController.prototype.cardInserted = function(readername) {
	var card = new Card(readername);
	this.check(card);
	card.close();
}



AccessController.prototype.cardRemoved = function() {
	this.accessTerminal.red();
}



AccessController.prototype.waitForCardInsertion = function() {
	this.card = null;

	do	{
		try	{
			this.card = new Card(this.crdreader);
//			card.reset(Card.RESET_COLD);
		}
		catch(e) {
//			print(e);
			this.card = null;
		}
	} while (this.card == null);
}



AccessController.prototype.waitForCardRemoval = function() {
	while (true) {
		try	{
			var card = new Card(this.crdreader);
			card.close();
		}
		catch(e) {
			return;
		}
	}
}



AccessController.prototype.checkAccessWithSCHSM = function(card) {
	var starttime = new Date();
	print("Started at " + starttime);

	try	{
		var ac = new SmartCardHSM(card);
	}
	catch(e) {
		print(e);
		return false;
	}
	
	var rsp = ac.readBinary(SmartCardHSM.C_DevAut);
	var chain = SmartCardHSM.validateCertificateChain(this.crypto, rsp);

	try	{
		ac.openSecureChannel(this.crypto, chain.publicKey);
		var pin = this.accessTerminal.getPIN();
		if (pin.length > 0) {
			var sw = ac.verifyUserPIN(new ByteString(pin, ASCII));
			if (sw != 0x9000) {
				print("PIN wrong !!!");
				return false;
			}
		}
	}
	catch(e) {
		return false;
	}

	var stoptime = new Date();

	print("Ended at " + stoptime);

	var duration = stoptime.valueOf() - starttime.valueOf();

	print("Duration " + duration + " ms");
	
	print("Card id : " + chain.path);
	return true;
}



AccessController.prototype.check = function(card) {

	var grant = this.checkAccessWithSCHSM(card);
	if (grant) {
		this.accessTerminal.green();
	} else {
		this.accessTerminal.off();
		GPSystem.wait(200);
		this.accessTerminal.red();
		GPSystem.wait(200);
		this.accessTerminal.off();
		GPSystem.wait(200);
		this.accessTerminal.red();
		GPSystem.wait(200);
	}
}



AccessController.prototype.loop = function() {
	this.run = true;
	while (this.run) {
		this.accessTerminal.red();
		this.waitForCardInsertion();
		this.check(this.card);
		this.card.close();
		this.waitForCardRemoval();
	}
}



AccessController.prototype.stop = function() {
	this.run = false;
}



AccessController.test = function() {
	ac = new AccessController(_scsh3.reader);
	try	{
		Card.setCardEventListener(ac);
		ac.accessTerminal.red();
	}
	catch(e) {
//		ac.loop();
	}
}


AccessController.test();