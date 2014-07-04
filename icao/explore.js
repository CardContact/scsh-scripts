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
 * @fileoverview Explore an MRTD using Basic Access Control
 */


var mrzlist = [	"L898902C<3UTO6908061F9406236ZE184226B<<<<<14", 
		"WG30004036UTO6007078M0511014<<<<<<<<<<<<<<06",
		];

var mrz2 = mrzlist[0];
var bacforced = false;

load("tools.js");
load("tools/OutlineCore.js");



//
// CTOR - Outline node for DFs
//
function OutlineLDS(card, id, name, profile) {
        this.card = card;
        this.id = id;

        // Create OutlineNode object and register in OutlineDF object
        var view = new OutlineNode(name, true);
        view.setUserObject(this);
        view.setToolTip("Click right mouse button to select MRZ for BAC");
        view.setContextMenu(mrzlist);
        this.view = view;
        
        this.profile = profile;
}



//
// Event handler for expand notifications
//
OutlineLDS.prototype.expandListener = function() {

        if (this.expanded)
                return;

        var view = this.view;
        var eflist = this.profile.EF;
        
        try	{
        	var df = new CardFile(this.card, this.id);
		this.df = df;
				
		var fcp = df.getFCPBytes();
		if (fcp && (fcp.length > 1)) {
			var fcpmodel = new OutlineFCP(fcp);
			view.insert(fcpmodel.view);	
		}
		
		// Try reading EF_COM to figure out if BAC is needed
		this.card.sendApdu(0x00, 0xB0, 0x9E, 0x00, 0x01);

		var secureChannel = null;
		
		if (bacforced || (this.card.SW != 0x9000)) {
			// Calculate kenc and kmac for mutual authentication from the MRZ data
			print("Trying BAC with MRZ2=" + mrz2);
	
			var crypto = new Crypto();
			var kenc = calculateBACKey(crypto, mrz2, 1);
			var kmac = calculateBACKey(crypto, mrz2, 2);

			// Dummy to load crypto libraries (Saves some time later)
			crypto.encrypt(kenc, Crypto.DES_CBC, new ByteString("0000000000000000", HEX), new ByteString("0000000000000000", HEX));

			secureChannel = openSecureChannel(this.card, crypto, kenc, kmac);
		}
				
		for (var i = 0; i < eflist.length; i++) {
		        var ef = new OutlineSMEF(this.df, eflist[i].name, eflist[i], secureChannel);
		        view.insert(ef.view);
		}
	}
	catch(e) {
		print(e);
	}
        
        this.expanded = true;
}



//
// Event handler for expand notifications
//
OutlineLDS.prototype.collapseListener = function() {
        var view = this.view;
        while(view.childs.length > 0) {
        	view.remove(view.childs[0]);
        }
        this.expanded = false;
}


//
// Event handler for selection from context menu
//
OutlineLDS.prototype.actionListener = function(node, action) {
	if (this.expanded) {
		print("Please collapse and expand LDS to execute BAC again");
	}
	
	mrz2 = action;
	print("Selected MRZ2 = " + mrz2);
	bacforced = true;
}



//
// CTOR - Outline node for EFs
//
function OutlineSMEF(df, name, profile, secureChannel) {
        this.df = df;
	this.secureChannel = secureChannel;
	
        // Create OutlineNode object and register in OutlineEF object
        var view = new OutlineNode(name, true);
        view.setIcon("document");
        view.setUserObject(this);
        this.view = view;
        
        this.profile = profile;
}



//
// Event handler for expand notification
//
OutlineSMEF.prototype.expandListener = function() {
        if (this.expanded)
                return;

        var view = this.view;
        var efdesc = this.profile;

	try	{        
	        var ef = new CardFile(this.df, ":" + efdesc.fid);
	        if (this.secureChannel) {	
			// Set secure channel as credential for read access
			ef.setCredential(CardFile.READ, Card.ALL, this.secureChannel);
		}
	}
	catch(e) {
		print(e);
		return;
	}
		
	var isTransparent = true;
	
	if (efdesc.fid.length > 2) {  // Select by FID or SFI
		var fcp = ef.getFCPBytes();
		if (fcp && (fcp.length > 1)) {
			var fcpmodel = new OutlineFCP(fcp);
			view.insert(fcpmodel.view);
			isTransparent = ef.isTransparent();
		} else {
			isTransparent = (efdesc.type == "T");
		}
	}
		
        if (isTransparent) {
        	if (fcp) {
	        	var filesize = ef.getLength();
	       	
	        	if (filesize > 1024)
	        		print("Please wait, reading " + filesize + " bytes...");
	        } else {
        		print("Please wait, reading card...");
	        }
        		
		try	{
	                var bs = ef.readBinary();
	        }
	        catch(e) {
	       		print(e);
	       		this.expanded = true;
	       		return;
		}
		print("Reading done...");
		
		var bindata = new DataOutline(bs, efdesc.format);
		view.insert(bindata.view);
		
        } else {
                for (var rec = 1; rec < 255; rec++) {
                        try     {
                                ef.readRecord(rec);
                                var record = new OutlineRecord(ef, rec, efdesc);
                                view.insert(record.view);
                        }
                        catch(e) {
                              	if ((e instanceof GPError) && (e.reason == 0x6A83))
                			break;
                                print(e);
                                break;
                        }
                }
        }
        
        this.expanded = true;
}




function MRTDOutlineCard() {

        // Create card object
        var card = new Card(_scsh3.reader);
        this.atr = card.reset(Card.RESET_COLD);

        this.card = card;

        // Create OutlineNode object and register in MRTD object
        this.view = new OutlineNode("ICAO MRTD");
        
        // Register MRTD object in OutlineNode object
        this.view.model = this;
        
        // Set a wrapper to receive expand() notifications from the OutlineNode object
        this.view.expandListener = function() { var model = this.model; model.expand() };
}



//
// Expand clicked on node
//
function MRTDOutlineCard_expand() {
        if (this.expanded)
                return;
                
        var view = this.view;

        //
        // Display ATR
        //
        var atrnode = new OutlineATR(this.atr);
        view.insert(atrnode.view);

        //
        // Explore files in MF
        //
        
        var struct_lds = GPXML.parse("lds.xml");
        this.lds = new OutlineLDS(this.card, "#A0000002471001", "LDS", struct_lds);
        
        view.insert(this.lds.view);

        this.expanded = true;
}


MRTDOutlineCard.prototype.expand = MRTDOutlineCard_expand;



//
// Outline root node erzeugen
// 
var mrtd = new MRTDOutlineCard();

mrtd.view.show();
