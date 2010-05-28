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
 * @fileoverview Configure services
 */

// --- Global settings ---

// The base URL at which services respond to webservice requests
var url = "http://localhost:8080";
// var url = "https://localhost:8443";

// The data directory for keys, requests, certificates and configurations
var datadir = "c:/data/eacpki";



// --- CVCA section ---

// Create an CVCA service
var cvca = new CVCAService(datadir +  "/cvca", "UTCVCA");

// The policy used to issue self-signed root certificates
var rootPolicy = { certificateValidityDays: 6,
				   chatRoleOID: new ByteString("id-IS", OID),
				   chatRights: new ByteString("E3", HEX),
				   includeDomainParameter: true,
				   extensions: null
				 };

cvca.setRootCertificatePolicy(rootPolicy);

// The policy used to issue link certificates
var linkPolicy = { certificateValidityDays: 6,
				   chatRoleOID: new ByteString("id-IS", OID),
				   chatRights: new ByteString("E3", HEX),
				   includeDomainParameter: true,
				   extensions: null
				 };

cvca.setLinkCertificatePolicy(linkPolicy);

// The policy used to issue DV certificates
var dVPolicy = { certificateValidityDays: 4,
				   chatRoleOID: new ByteString("id-IS", OID),
				   chatRights: new ByteString("A3", HEX),
				   includeDomainParameter: false,
				   extensions: null,
				   authenticatedRequestsApproved: false,
				   initialRequestsApproved: false,
				   declineExpiredAuthenticatedRequest: true
				 };

// Default policy
cvca.setDVCertificatePolicy(dVPolicy);

var dVPolicy = { certificateValidityDays: 4,
				   chatRoleOID: new ByteString("id-IS", OID),
				   chatRights: new ByteString("A3", HEX),
				   includeDomainParameter: false,
				   extensions: null,
				   authenticatedRequestsApproved: true,
				   initialRequestsApproved: false,
				   declineExpiredAuthenticatedRequest: false
				 };

// Policy for UTDVCA
cvca.setDVCertificatePolicy(dVPolicy, /^UTDVCA.*$/);


/*
// Set signature key specification
var key = new Key();
key.setComponent(Key.ECC_CURVE_OID, new ByteString("brainpoolP384t1", OID));
cvca.setKeySpec(key, new ByteString("id-TA-ECDSA-SHA-384", OID));
*/


// Create GUI
var cvcaui = new CVCAUI(cvca);

SOAPServer.registerService("cvca", cvca, cvcaui);



// --- DVCA section ---

// Create a DVCA service

var dvca = new DVCAService(datadir + "/dvca", "UTDVCA", "UTCVCA", url + "/se/cvca");
dvca.setSendCertificateURL(url + "/se/dvca");

var terminalPolicy = { certificateValidityDays: 2,
				   chatRoleOID: new ByteString("id-IS", OID),
				   chatRights: new ByteString("23", HEX),
				   includeDomainParameter: false,
				   extensions: null,
				   authenticatedRequestsApproved: true,
				   initialRequestsApproved: false,
				   declineExpiredAuthenticatedRequest: false
				 };

dvca.setTerminalCertificatePolicy(terminalPolicy);

// Create GUI
var dvcaui = new DVCAUI(dvca);

SOAPServer.registerService("dvca", dvca, dvcaui);



// --- TCC section ---

// Create TCC service
var tcc = new TCCService(datadir + "/tcc", "/UTCVCA/UTDVCA/UTTERM", url + "/se/dvca");
tcc.setSendCertificateURL(url + "/se/tcc");

// Create GUI
var tccui = new TCCUI(tcc);

SOAPServer.registerService("tcc", tcc, tccui);
