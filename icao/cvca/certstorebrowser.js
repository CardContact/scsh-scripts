/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|  
 * |#       #|  Copyright (c) 1999-2010 CardContact Software & System Consulting
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
 * @fileoverview A simple certificate store browser
 */



/**
 * Create a certificate store browser
 * 
 * @class Class implementing a simple certificate store web user interface
 * @constructor
 * @param {CVCertificateStore} certstore the certificate store to browse
 * @param {String} urlprefix the prefix to prepend to generated URLs
 */
function CertStoreBrowser(certstore) {
	this.certstore = certstore;
	this.listsize = 15;
}



/**
 * Parse operations string into object containing parameter and values
 *
 * <p>An operations string may contain multiple entries separated by an ampersand.</p>
 * <p>Entries may have a value assigned using the parameter=value notation.</p>
 * <p>Valid operations strings are "link", "link=all", "filer=true&start=0"</p>
 *
 * @param {String} op the operations string
 * @returns an object with properties matching entries.
 * @type Object
 */
CertStoreBrowser.parseQueryString = function(op) {
	var result = {};
	
	var elems = op.split("&");
	for (var i = 0; i < elems.length; i++) {
		var s = elems[i];
		var ofs = s.indexOf("=");
		if (ofs >= 0) {
			var p = s.substring(ofs + 1);
			s = s.substring(0, ofs);
			result[s] = p;
		} else {
			result[s] = true;
		}
	}
	return result;
}



/**
 * Generate a page navigator
 *
 * @param {String} urlprefix the prefix to prepend on generated URLs
 * @param {Number} start the current element offset
 * @param {Number} length the total number of elements
 * @returns the page navigator element
 * @type XML
 */
CertStoreBrowser.prototype.generatePageNavigator = function(urlprefix, start, length) {
	var nav = "<div align=\"right\"><b>";
	
	// The page we are on
	var currentpage = Math.floor(start / this.listsize);
	
	// The total number of pages
	var totalpages = Math.ceil(length / this.listsize);
	
	// Determine first entry in page list
	firstpage = currentpage - 2;
	if (firstpage < 0) {
		firstpage = 0;
	}
	
	// Determine number of page entries to display
	var pages = totalpages - firstpage;
	
	if (pages > 10) {
		pages = 10;
	} else {
		// Make sure we do not shorten the list at the end
		p = totalpages - 10;
		if (p < 0) {
			p = 0;
		}
		if (p < firstpage) {
			firstpage = p;
			pages = totalpages - firstpage;
		}
	}
	
	// Back to first page
	if (firstpage > 0) {
		var url = urlprefix + "start=0";
		nav += "<a href=\"" + url + "\">1</a> ";
	}
	
	if (firstpage > 1) {
		nav += "... ";
	} else {
		if (firstpage > 0) {
			nav += "| ";
		}
	}

	// Page links
	for (var i = 0; i < pages; i++) {
		if (firstpage + i == currentpage) {
			nav += (firstpage + i + 1) + " ";
		} else {
			var url = urlprefix + "start=" + (firstpage + i) * this.listsize;
			nav += "<a href=\"" + url + "\">" + (firstpage + i + 1) + "</a> ";
		}
		if (i < pages - 1) {
			nav += " | ";
		}
	}
	
	// More to follow
	if (firstpage + pages < totalpages) {
		nav += "... ";
	}
	
	// Navigate backwards
	if (currentpage > 0) {
		var url = urlprefix + "start=" + (currentpage - 1) * this.listsize;
		nav += "<a href=\"" + url + "\">&lt;&lt;</a> ";
	}
	
	// Navigate forward
	if ((currentpage + 1) < totalpages) {
		var url = urlprefix + "start=" + (currentpage + 1) * this.listsize;
		nav += " <a href=\"" + url + "\">&gt;&gt;</a>";
	}

	nav += "</b></div>";
	return new XML(nav);
}



/**
 * Generate a browser that allows to navigate the CA hierarchie
 *
 * @param {String} urlprefixholder the prefix to use for URLs addressing holder lists
 * @param {String} urlprefixlists the prefix to use for URLs addressing lists
 * @param {String} path the current path
 * @returns the table and navigator elements
 * @type XML
 */
CertStoreBrowser.prototype.generateHierachieNavigator = function(urlprefixholder, urlprefixlists, path) {
	var elem = path.substr(1).split("/");
	
	var nav = "<div align=\"left\">";
	
	if ((elem.length > 0) && (elem[0].length > 0)) {
		var newpath = "";
		for (var i = 0; i < elem.length; i++) {
			newpath += "/" + elem[i];
			nav += "<a href=\"" + urlprefixlists + "?path=" + newpath + "\">" + elem[i] + "</a>";
			nav += " <a href=\"" + urlprefixholder + "?path=" + newpath + "\">&gt;&gt;</a> ";
		}
	}
	
	nav += "</div>";
	return new XML(nav);
}



/**
 * Generate a table of certificates and the navigator elements
 *
 * @param {String} operations the operations part of the URL
 * @param {String} urlprefixholder the prefix to use for URLs addressing holder lists
 * @param {String} urlprefixlists the prefix to use for URLs addressing lists
 * @param {String} urlprefixcerts the prefix to use for URLs addressing certificates
 * @returns the table and navigator elements
 * @type XML
 */
CertStoreBrowser.prototype.generateCertificateList = function(operation, urlprefixholder, urlprefixlists, urlprefixcerts) {
	var div = <div/>;
	
	var op = CertStoreBrowser.parseQueryString(operation);
	if (typeof(op.path) == "undefined") {
		throw new GPError("CertStoreBrowser", GPError.INVALID_DATA, 0, "Parameter path missing in URL");
	}
	
	var start = 0;
	if (typeof(op.start) != "undefined") {
		start = parseInt(op.start);
	}
	
	var certlist = this.certstore.listCertificates(op.path);
	var cnt = certlist.length - start;
	if (cnt > this.listsize) {
		cnt = this.listsize;
	}
	
	var baseurl = urlprefixlists + "?" + "path=" + op.path + "&amp;";
	
	var nav = this.generatePageNavigator(baseurl, start, certlist.length);
	var hier = this.generateHierachieNavigator(urlprefixholder, urlprefixlists, op.path);

	var navt = <table width="100%"><tr><td>{hier}</td><td>{nav}</td></tr></table>;

	div.appendChild(navt);

	var t = <table class="content"/>;

	t.tr += <tr><th>CHR</th><th>CAR</th><th>Type</th><th>Effective</th><th>Expiration</th></tr>;
	
	for (var i = 0; i < cnt; i++) {
		var cvc = certlist[start + i];
		var selfsigned = cvc.getCHR().equals(cvc.getCAR());
		var refurl = urlprefixcerts + "?" +
		             "path=" + op.path + "&" +
		             "chr=" + cvc.getCHR().toString() + "&" +
		             "selfsigned=" + selfsigned;

		t.tr += <tr>
			<td><a href={refurl}>{cvc.getCHR().toString()}</a></td>
			<td>{cvc.getCAR().toString()}</td>
			<td>{cvc.getType()}</td>
			<td>{cvc.getCED().toLocaleDateString()}</td>
			<td>{cvc.getCXD().toLocaleDateString()}</td>
		</tr>
	}

	div.appendChild(t);
	div.appendChild(navt);
	return div;
}



/**
 * Generate a table of certificate holder and the navigator elements
 *
 * @param {String} operations the operations part of the URL
 * @param {String} urlprefixholder the prefix to use for URLs addressing holder lists
 * @param {String} urlprefixcerts the prefix to use for URLs addressing certificates
 * @returns the table and navigator elements
 * @type XML
 */
CertStoreBrowser.prototype.generateCertificateHolderList = function(operation, urlprefixholder, urlprefixcerts) {
	var div = <div id="holderlist"/>;
	
	var op = CertStoreBrowser.parseQueryString(operation);
	if (typeof(op.path) == "undefined") {
		throw new GPError("CertStoreBrowser", GPError.INVALID_DATA, 0, "Parameter path missing in URL");
	}
	
	var start = 0;
	if (typeof(op.start) != "undefined") {
		start = parseInt(op.start);
	}
	
	var holderlist = this.certstore.listHolders(op.path);
	var cnt = holderlist.length - start;
	if (cnt > this.listsize) {
		cnt = this.listsize;
	}
	
	var baseurl = urlprefixholder + "?" + "path=" + op.path + "&amp;";
	
	var nav = this.generatePageNavigator(baseurl, start, holderlist.length);
	var hier = this.generateHierachieNavigator(urlprefixholder, urlprefixcerts, op.path);

	var navt = <table width="100%"><tr><td>{hier}</td><td>{nav}</td></tr></table>;

	div.appendChild(navt);

	var t = <table class="content"/>;
	
	t.tr += <tr><th>Holder</th><th>Certificates</th></tr>
	for (var i = 0; i < cnt; i++) {
		var holder = holderlist[start + i];
		var refurl = urlprefixholder + "?" +
		             "path=" + op.path + "/" + holder;
		var certurl = urlprefixcerts + "?" +
		             "path=" + op.path + "/" + holder;
		
		t.tr += <tr>
				<td><a href={refurl}>{holder}</a></td>
				<td><a href={certurl}>...</a></td>
				</tr>
	}
	
	div.appendChild(t);
	div.appendChild(navt);
	return div;
}
