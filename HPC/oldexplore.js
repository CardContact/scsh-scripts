//
//  ---------
// |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
// |#       #|  
// |#       #|  Copyright (c) 1999-2006 CardContact Software & System Consulting
// |'##> <##'|  Andreas Schwier, 32429 Minden, Germany (www.cardcontact.de)
//  --------- 
//
//  This file is part of OpenSCDP.
//
//  OpenSCDP is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License Version 2 as
//  published by the Free Software Foundation.
//
//  OpenSCDP is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with OpenSCDP; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
//
//  HPC explorer

load("tools/OutlineCore.js");



function EGKOutlineCard() {

        // Create card object
        var card = new Card(_scsh3.reader);
        this.atr = card.reset(Card.RESET_COLD);

        this.card = card;

        // Create OutlineNode object and register in card object
        var view = new OutlineNode("HPC");
        view.setUserObject(this);
        this.view = view;
}



//
// Expand clicked on node
//
// Read application list from EF_DIR
//
EGKOutlineCard.prototype.expandListener = function() {
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
        
        var struct_mf = GPXML.parse("mf.xml");
        this.mf = new OutlineDF(this.card, ":3F00", "MF", struct_mf);
        
        view.insert(this.mf.view);

        //
        // Obtain list of applications from EF_DIR
        //

        try     {
                var efdir = new CardFile(this.card, ":2F00");
        }
        catch(e) {
                print("Exception selecting EF_DIR. Is this a HPC ?\n" + e);
                return;
        }
                
        for (var rec = 1; rec < 255; rec++) {
                var record;
                try     {
                        record = efdir.readRecord(rec);
                }
                catch(e) {
                        print(e);
                        break;
                }

                var tlv = new ASN1(record);
                
                var label = null;
                var aid = null;
                        
                for (var i = 0; i < tlv.elements; i++) {
                        var t = tlv.get(i);
                        switch(t.tag) {
                        case 0x50:
                                label = t.value.toString(UTF8);
                                break;
                        case 0x4F:
                                aid = t.value;
                                break;
                        }
                }

                if (label && aid) {
                        var applentry;

                        if (aid.toString(HEX) == "D27600004002") { // HPA
                                var struct = GPXML.parse("hpa.xml");
                                applentry = new OutlineDF(this.card, "#" + aid.toString(HEX), "DF.HPA", struct);
                                view.insert(applentry.view);
                        } else if (aid.toString(HEX) == "A000000167455349474E") { // ESIGN
                                var struct = GPXML.parse("esign.xml");
                                applentry = new OutlineDF(this.card, "#" + aid.toString(HEX), "DF.ESIGN", struct);
                                view.insert(applentry.view);
                        } else if (aid.toString(HEX) == "E828BD080FA000000167455349474E") { // CIA.ESIGN
                                var struct = GPXML.parse("ciaesign.xml");
                                applentry = new OutlineDF(this.card, "#" + aid.toString(HEX), "DF.CIA.ESIGN", struct);
                                view.insert(applentry.view);
                        } else if (aid.toString(HEX) == "D27600006601") { // QES
                                var struct = GPXML.parse("qes.xml");
                                applentry = new OutlineDF(this.card, "#" + aid.toString(HEX), "DF.QES", struct);
                                view.insert(applentry.view);
                        } else {
                                if (!label) {
                                        if (!aid) {
                                                label = "Invalid entry in EF.DIR";
                                        } else {
                                                label = aid.toString(HEX);
                                        }
                                }
                                
                                applentry = new OutlineNode(label);
                                applentry.insert(tlv);
                                view.insert(applentry);
                        }
                }
        }

        this.expanded = true;
}



//
// Outline root node erzeugen
// 
try     {
        var hpc = new EGKOutlineCard();
        hpc.view.show();
}

catch(e) {
        print("No card in reader or problem with reset: " + e);
}

