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
 * @fileoverview SmartCard-HSM Explorer
 */


load("tools/CardOutlineFactory2.0.js");
load("../lib/smartcardhsm.js");



/**
 * SmartCard-HSM Outline that displays all contained EFs
 *
 * @param {Object} factory the factory creating this instance
 * @param {Application} instance the application instance created from the application profile
 */
function scHSMOutline(factory, instance) {
	this.factory = factory;
	this.instance = instance;

	// Create OutlineNode object and register in OutlineDF object
	var view = new OutlineNode("SmartCard-HSM Applet", true);
	view.setUserObject(this);
	view.setContextMenu([scHSMOutline.VERIFY_PIN]);
	this.view = view;
}

scHSMOutline.VERIFY_PIN = "Verify USER.PIN";


/**
 * Expand listener that enumerates files
 */
scHSMOutline.prototype.expandListener = function() {
	var view = this.view;

	try	{
		this.factory.schsm = new SmartCardHSM(this.factory.card);
		var files = this.factory.schsm.enumerateObjects();

		for (var i = 0; i < files.length; i += 2) {
			var fid = files.bytes(i, 2);
			var fidstr = fid.toString(HEX);
			var name = "EF." + fidstr;

			if (fidstr == "2F02") {
				name = "EF.C_DevAut";
			}
			if (fid.byteAt(0) == SmartCardHSM.KEYPREFIX) {
				name = "Key " + fid.byteAt(1);
			}
			var profile = { fid: fid.toString(HEX), format: "asn1" };
			var ef = this.factory.newOutlineEF(this.factory.schsm.card, name, profile);
			view.insert(ef.view);
		}
	}

	catch(e) {
		print("Error reading EF.DIR: " + e);
	}
}



/**
 * Collapse listener that removes files from the view
 */
scHSMOutline.prototype.collapseListener = function() {
	var view = this.view;
	while (view.childs.length > 0) {
		view.remove(view.childs[0]);
	}
}



scHSMOutline.prototype.actionListener = function(source, action) {
	if (action == scHSMOutline.VERIFY_PIN) {
		this.factory.schsm.verifyUserPIN();
	}
}



/**
 * Create an EF view elements
 *
 */
function scHSMOutlineEF(factory, df, name, profile) {
	if (arguments.length == 0)
		return;

	this.factory = factory;
	this.df = df;

	// Create OutlineNode object and register in OutlineEF object
	var view = new OutlineNode(name, true);
	view.setIcon("document");
	view.setUserObject(this);
	this.view = view;

	this.profile = profile;
}



/**
 * Expand listener that reads file content
 */
scHSMOutlineEF.prototype.expandListener = function() {
	if (this.expanded)
		return;

	var view = this.view;
	var efdesc = this.profile;

	try	{
		var ef = new CardFile(this.df, ":" + efdesc.fid);
	}
	catch(e) {
		print(e);
		return;
	}

	var fcp = ef.getFCPBytes();
	if (fcp && (fcp.length > 1)) {
		var fcpmodel = this.factory.newOutlineFCP(fcp);
		view.insert(fcpmodel.view);
	}

	if (efdesc.fid.substr(0, 2) != "CC") {
		var bs = this.factory.schsm.readBinary(new ByteString(efdesc.fid, HEX));

		var bindata = this.factory.newDataOutline(bs, efdesc.format);
		view.insert(bindata.view);

		if (efdesc.fid.substr(0, 2) == "C4") {
			var cio = new PKCS15_PrivateKey(bindata.asn);
			print("---- EF." + efdesc.fid + " Private Key Information Object ----");
			print(cio);
		}
		if (efdesc.fid.substr(0, 2) == "C8") {
			print("---- EF." + efdesc.fid + " Certificate Information Object ----");
			var cio = new PKCS15_Certificate(bindata.asn);
			print(cio);
		}
		if (efdesc.fid.substr(0, 2) == "C9") {
			print("---- EF." + efdesc.fid + " Data Container Information Object ----");
			var cio = new PKCS15_DataContainerObject(bindata.asn);
			print(cio);
		}
	}


	this.expanded = true;
}



/**
 * Class overwriting the default CardOutlineFactory
 *
 */
function scHSMCardOutlineFactory(card) {
	this.card = card;
}

// Inherit from prototype
scHSMCardOutlineFactory.prototype = new CardOutlineFactory();

// Restore constructor
scHSMCardOutlineFactory.constructor = scHSMCardOutlineFactory;



/**
 * Overwrite newOutlineApplet() function
 */
scHSMCardOutlineFactory.prototype.newOutlineApplet = function(instance) {

	return new scHSMOutline(this, instance);
}



/**
 * Overwrite newOutlineApplet() function
 */
scHSMCardOutlineFactory.prototype.newOutlineEF = function(df, name, profile) {
	return new scHSMOutlineEF(this, df, name, profile);
}



//
// Context menu
//
function OutlineCardActionListener(node, action) {
	switch(action) {
	case "Verify USER.PIN":
		var card = node.userObject.card;
		var dialog = new Packages.opencard.core.service.DefaultCHVDialog();
		var pin = dialog.getCHV(1);

		if ((pin != null) && (pin.length > 0)) {
			card.sendApdu(0x00, 0x20, 0x00, 0x01, new ByteString(pin, ASCII));
			if (this.card.SW != 0x9000) {
				throw new GPError("GeneratorCard", GPError.DEVICE_ERROR, this.card.SW, "PIN Verification Error - SW1/SW2 = " + this.card.SW.toString(16) + " - " + this.card.SWMSG);
			}
		} else {
			print("PIN entry cancelled");
		}

		break;
	}
}



// Create crypto object
var crypto = new Crypto();

// Create application factory that holds all application profiles
var af = new ApplicationFactory(crypto);

// Add application profiles
af.addApplicationProfile("ap_sc_hsm.xml");

// Create card object
var card = new Card(_scsh3.reader, "cp_sc_hsm.xml");

// Create card outline factory
var of = new scHSMCardOutlineFactory(card);

// Create list of AIDs, just in case the EF.DIR is empty
// This is just temporary to make sure the explorer works
// even for card with a defect in EF.DIR

var aidlist = new Array();

// and go...
try	 {
	var sc = new OutlineCard(of, card, af, aidlist);
//	sc.view.setContextMenu(["Verify USER.PIN"]);
	sc.view.setToolTip("Click right to access context menu");
	sc.actionListener = OutlineCardActionListener;
	sc.view.show();
}

catch(e) {
	print("Problem accessing the card: " + e);
}
