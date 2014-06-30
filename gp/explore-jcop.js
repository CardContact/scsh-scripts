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
 *  Global Platform Card Explorer
 */

load("tools.js");
load("tools/CardOutlineFactory.js");

if (typeof(masterSENC) == "undefined")
	masterSENC = new Key("kp_jcop_default_s-enc.xml");

if (typeof(masterSMAC) == "undefined")
	masterSMAC = new Key("kp_jcop_default_s-mac.xml");


function OutlineCardManager(factory, application) {
	this.factory = factory;
	this.application = application;
	this.card = application.card; 	// Required by OutlineDataObject
	
	this.issuerSecurityDomain = null;
	this.applications = null;
	this.loadfiles = null;
	
	// Create OutlineNode object and register in OutlineCardManager object
	var view = new OutlineNode("Card Manager (" + application.aid + ")", true);
	view.setUserObject(this);
	view.setContextMenu(["Authenticate"]);
	this.view = view;

	this.authenticated = false;
}



//
// Event handler for expand notifications
//
OutlineCardManager.prototype.expandListener = function() {

	if (this.expanded)
		return;

	var view = this.view;

	try	{
		var fcp = this.application.select();
		this.fcp = fcp;
				
		if (fcp && (fcp.length > 1)) {
			var fcpmodel = this.factory.newOutlineFCP(fcp);
			view.insert(fcpmodel.view);
		}

		var d = this.factory.newOutlineDataObject(this, 0x42, "Issuer Identification Number", "");
		view.insert(d.view);

		var d = this.factory.newOutlineDataObject(this, 0x45, "Card Image Number", "");
		view.insert(d.view);
		
		var d = this.factory.newOutlineDataObject(this, 0x66, "Card Data", "asn1");
		view.insert(d.view);

		var d = this.factory.newOutlineDataObject(this, 0xE0, "Key Information Template", "tlvlist");
		view.insert(d.view);

		var d = this.factory.newOutlineDataObject(this, 0xC1, "Sequence Counter of the default Key Version Number", "");
		view.insert(d.view);

		var d = this.factory.newOutlineDataObject(this, 0xC2, "Confirmation Counter", "");
		view.insert(d.view);
		
		var d = this.factory.newOutlineDataObject(this, 0x9F7F, "Card Production Life Cycle (JCOP)", "");
		view.insert(d.view);
	}

	catch(e) {
		print(e);
	}

	this.expanded = true;
}




OutlineCardManager.prototype.authenticate = function() {

	if (!this.expanded) {
		print("Please expand card manager before authentication");
		return;
	}
	
	GPAuthenticate(this.application.card, this.application.crypto, masterSENC, masterSMAC);

	this.authenticated = true;
	
	var filter = new ByteString("4F00", HEX);
	var view = this.view;

	if (this.issuerSecurityDomain) {
		view.remove(this.issuerSecurityDomain.view);
	}

	var r = this.application.sendApdu(0x80, 0xF2, 0x80, 0x00, filter, 0x00, [0x9000]);
	this.issuerSecurityDomain = new OutlineModuleList(this.application, "Issuer Security Domain", r, 0, false);
	view.insert(this.issuerSecurityDomain.view);
	
	if (this.applications) {
		view.remove(this.applications.view);
	}

	var r = this.application.sendApdu(0x80, 0xF2, 0x40, 0x00, filter, 0x00, [0x9000, 0x6A88]);
	this.applications = new OutlineModuleList(this.application, "Application Instances", r, 1, true);
	view.insert(this.applications.view);

	if (this.loadfiles) {
		view.remove(this.loadfiles.view);
	}

	// 2.1.x cards support option P1 = 0x10 to list load files and modules
	// 2.0.1 cards only support P1 = 0x20 to list load files
	var r = this.application.sendApdu(0x80, 0xF2, 0x10, 0x00, filter, 0x00, [0x9000, 0x6A88, 0x6A86]);
	if (this.application.card.SW == 0x6A86) {
		var r = this.application.sendApdu(0x80, 0xF2, 0x20, 0x00, filter, 0x00, [0x9000, 0x6A88]);
		this.loadfiles = new OutlineModuleList(this.application, "Load Files", r, 2, true);
		view.insert(this.loadfiles.view);
	} else {
		this.loadfiles = new OutlineModuleList(this.application, "Load Files and Modules", r, 3, true);
		view.insert(this.loadfiles.view);
	}
}


//
// Action handler
//
OutlineCardManager.prototype.actionListener = function(node, action) {
	switch(action) {
		case "Authenticate":
			node.userObject.authenticate();
			break;
	}
}



//
// Return a string for a Global Platform Life Cycle Status
//
function lcs2string(type, lcs) {
	s = "UNKNOWN";
	if (type == 0) {		// Issuer Security Domain
		switch(lcs) {
		case 0x01: s = "OP_READY"; break;
		case 0x07: s = "INITIALIZED"; break;
		case 0x0F: s = "SECURED"; break;
		case 0x7F: s = "CARD_LOCKED"; break;
		case 0xFF: s = "TERMINATED"; break;
		}
	} else {
		switch(lcs & 0x8F) {
		case 0x01: s = "LOADED"; break;
		case 0x03: s = "INSTALLED"; break;
		case 0x07: s = "SELECTABLE"; break;
		case 0x0F: s = "PERSONALIZED"; break;
		case 0x8F: s = "LOCKED"; break;
		}
	}
	return s;
}



//
// Return a string for a Global Platform application privilege
//
function priv2string(priv) {
	if (priv == 0)
		return("");
	
	s = "(";
	if (priv & 0x80)
		s += "SecDom ";
	if (priv & 0x40)
		s += "DAP ";
	if (priv & 0x20)
		s += "DelMan ";
	if (priv & 0x10)
		s += "CrdLck ";
	if (priv & 0x08)
		s += "CrdTrm ";
	if (priv & 0x04)
		s += "DefSel ";
	if (priv & 0x02)
		s += "CVM ";
	if (priv & 0x01)
		s += "MDAP ";
	s += ")";
	return s;
}



//
// Create an outline for AID identified objects managed by the card manager
// 
// cm		Card manager application object
// name		Name of module list
// desc		Descriptor returned by GET_STATUS
// type		0 - Issuer Security Domain, 1 - Application, 2 - Load File
// deletable	true, if module can be deleted
//
function OutlineModuleList(cm, name, desc, type, deletable) {
	this.cm = cm;
	this.name = name;
	
	var view = new OutlineNode(name, true);
	view.setUserObject(this);
	this.view = view;

	var offset = 0;
	while(offset < desc.length) {
		var lenaid = desc.byteAt(offset++);
		var aid = desc.bytes(offset, lenaid);
		offset += lenaid;
		var lcs = desc.byteAt(offset++);
		var priv = desc.byteAt(offset++);
		
		var name = aid.toString(16) + " " + lcs2string(type, lcs) + " " + priv2string(priv);
		var n = new OutlineModuleListEntry(cm, name, aid, deletable);
		
		view.insert(n.view);
		
		if (type == 3) {
			var count = desc.byteAt(offset++);
			while (count--) {
				lenaid = desc.byteAt(offset++);
				aid = desc.bytes(offset, lenaid);
				offset += lenaid;
				
				var m = new OutlineNode("Module " + aid.toString(16));
				n.view.insert(m);
			}
		}
	}
}



function OutlineModuleListEntry(cm, name, aid, deletable) {
	this.cm = cm;
	this.aid = aid;
	
	var view = new OutlineNode(name, false);
	view.setUserObject(this);
	if (deletable) {
		view.setContextMenu(["Delete"]);
	}
	this.view = view;
}



OutlineModuleListEntry.prototype.actionListener = function(node, action) {
	var aid = node.userObject.aid;
	
/*	
	var b = new ByteString("4F", HEX);
	b = b.concat(aid.getLV(TLV.EMV));
	
	this.cm.sendApdu(0x80, 0xE4, 0x00, 0x00, b);
*/
	this.cm.deleteAID(aid);
	print("Delete " + aid + " : " + this.cm.card.SWMSG);
	
	node.remove();
}




//
// Overwrite default outline factory to tailor some nodes
//
function GPCardOutlineFactory() {

}

// Inherit from prototype
GPCardOutlineFactory.prototype = new CardOutlineFactory();

// Restore constructor
GPCardOutlineFactory.constructor = GPCardOutlineFactory;

// Overwrite newOutlineApplet() function
GPCardOutlineFactory.prototype.newOutlineApplet = function(instance) {
	assert(instance instanceof GPSecurityDomain);
	return new OutlineCardManager(this, instance);
}




var card = new Card(_scsh3.reader, "../profiles/cp_jcop41.xml");

var crypto = new Crypto();

// Create card outline factory
var of = new GPCardOutlineFactory();

// Create application factory that holds all application profiles
var af = new ApplicationFactory(crypto);

af.addApplicationProfile("ap_jcop_cardmanager.xml");

var aidlist = null;

try {
	var jcop = new OutlineCard(of, card, af, aidlist);
	jcop.view.show();
}

catch(e) {
	print("No card in reader or problem with reset: " + e);
}


