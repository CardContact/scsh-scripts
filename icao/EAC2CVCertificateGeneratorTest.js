//
//  ---------
// |.##> <##.|  CardContact Software & System Consulting
// |#       #|  32429 Minden, Germany (www.cardcontact.de)
// |#       #|  Copyright (c) 1999-2005. All rights reserved
// |'##> <##'|  See file COPYING for details on licensing
//  --------- 
//
// EAC2CVCertificateGenerator Tests and API Documentation
//

/// <?xml version="1.0" encoding="ISO-8859-1"?>
/// <?xml-stylesheet type="text/xsl" href="docclass.xsl" ?>
/// <class xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
///     xsi:noNamespaceSchemaLocation="api_doc.xsd" name="X509">
///     <description><p>Class implementing support for CV certificates specified by TR-03110 Version 2.0</p>
///     <constant name="XOR" type="Number">Constant used in crc() method</constant>
///     <field name="length" type="Number">Number of bytes in the <type>ByteString</type></field>
///     <method name="">
///         <signature></signature>
///         <description></description>
///         <argument name="" type=""></argument>
///         <return type=""></return>
///         <example>
///         </example>
///         <exception name="GPError" value="GPError.ARGUMENTS_MISSING">Too few arguments in call</exception>
///         <exception name="GPError" value="GPError.INVALID_ARGUMENTS">Too many arguments in call</exception>
///         <exception name="GPError" value="GPError.INVALID_TYPE">Type of argument is invalid for call</exception>
///     </method>

load("EAC2CVCertificateGenerator.js");

// Some utility functions

/*
 * Write a byte string object to file
 *
 * The filename is mapped to the location of the script
 *
 * name		Name of file
 * content	ByteString content for file
 *
 */
function writeFileToDisk(name, content) {

	// Map filename
	var filename = GPSystem.mapFilename(name, GPSystem.CWD);
	print("Writing " + filename);

	var file = new java.io.FileOutputStream(filename);
	file.write(content);
	file.close();
}


/*
 * Read a byte string object from file
 *
 * The filename is mapped to the location of the script
 *
 * name		Name of file
 *
 */
function readFileFromDisk(name) {

	// Map filename
	var filename = GPSystem.mapFilename(name, GPSystem.CWD);
	print("Reading " + filename);

	var file = new java.io.FileInputStream(filename);
	
	var content = new ByteBuffer();
	var buffer = new ByteString("                                                                                                                                                                                                                                                                ", ASCII);
	var len;
	
	while ((len = file.read(buffer)) >= 0) {
		content.append(buffer.bytes(0, len));
	}
	
	file.close();
	return(content.toByteString());
}


///     <constructor>
///         <signature>EAC2CVCertificateGenerator(Crypto crypto)</signature>
///         <description>Create the certificate generator using the specified crypto object.</description>
///         <argument name="crypto" type="Crypto">The crypto engined to be used</argument>
///         <example>

var crypto = new Crypto();

generator = new EAC2CVCertificateGenerator(crypto);

///         </example>
///         <exception name="GPError" value="GPError.ARGUMENTS_MISSING">Too few arguments in call</exception>
///         <exception name="GPError" value="GPError.INVALID_ARGUMENTS">Too many arguments in call</exception>
///         <exception name="GPError" value="GPError.INVALID_TYPE">Type of argument is invalid for call</exception>

///     <method name="setCAR">
///         <signature>void setCAR(String car)</signature>
///         <description><p>Set the certification authority reference for the generated certificate</p></description>
///         <example>

var CAR = "decvca00000";

generator.setCAR(CAR);

///         </example>
///     </method>

///     <method name="setCHR">
///         <signature>void setCHR(String chr)</signature>
///         <description><p>Set the certificate holder reference for the generated certificate</p></description>
///         <example>

var CHR = "decvca00000";

generator.setCHR(CHR);

///         </example>
///     </method>

///     <method name="setEffectiveDate">
///         <signature>void setEffectiveDate(String effectiveDate)</signature>
///         <description><p>Set the effective date for the generated certificate</p></description>
///         <example>

var notBefore = "090210";

generator.setEffectiveDate(notBefore);

///         </example>
///     </method>

///     <method name="setExpiryDate">
///         <signature>void setExpiryDate(String expiryDate)</signature>
///         <description><p>Set the expiry date for the generated certificate</p></description>
///         <example>

var notAfter = "110225";
generator.setExpiryDate(notAfter);

///         </example>
///     </method>

///     <method name="setChatOID">
///         <signature>void setChatOID(ByteString oid)</signature>
///         <description><p>Set the object identifier of the authorization template for the generated certificate</p></description>
///         <example>

var chatOID = "0.4.0.127.0.7.3.1.2.1"; // inspection system

generator.setChatOID(new ByteString(chatOID, OID));

///         </example>
///     </method>

///     <method name="setChatAuthorizationLevel">
///         <signature>void setChatAuthorizationLevel(ByteString authLevel)</signature>
///         <description><p>Set the authorization level of the authorization template for the generated certificate</p></description>
///         <example>

var chatAuth = "E3"; // CVCA, read access to eID, DG3, DG4

generator.setChatAuthorizationLevel(new ByteString(chatAuth, HEX));

///         </example>
///     </method>

///     <method name="setPublicKey">
///         <signature>void setPublicKey(Key publicKey)</signature>
///         <description><p>Set the public key for the generated certificate</p></description>
///         <example>

// Create empty public key object
var pubKey = new Key("kp_cvca_ec_public.xml");

generator.setPublicKey(pubKey);

///         </example>
///     </method>

///     <method name="setProfileIdentifier">
///         <signature>void setProfileIdentifier(UnsignedInteger profileID)</signature>
///         <description><p>Set the profile identifier for the generated certificate</p></description>
///         <example>

var profileIdentifier = 0x00;

generator.setProfileIdentifier(profileIdentifier);

///         </example>
///     </method>

///     <method name="setTAAlgorithmIdentifier">
///         <signature>void setProfileIdentifier(UnsignedInteger profileID)</signature>
///         <description><p>Set the algorithm identifier for TA as specified in appendix A.6.4</p></description>
///         <example>

var taAlgorithmIdentifier = "0.4.0.127.0.7.2.2.2.2.3"; // ECDSA - SHA 256

generator.setTAAlgorithmIdentifier(new ByteString(taAlgorithmIdentifier, OID));

///         </example>
///     </method>

///     <method name="setExtensions">
///         <signature>void setExtensions(ASN1[] extensions)</signature>
///         <description><p>Set some extensions for a certificate</p></description>
///         <example>

//var extensions = new Array();
//extensions[0] = new ASN1("ext1", ASN1.OBJECT_IDENTIFIER, new ByteString("2A1200", HEX));
//extensions[1] = new ASN1("ext2", ASN1.OBJECT_IDENTIFIER, new ByteString("2A1200", HEX));

//generator.setExtensions(extensions);

///         </example>
///     </method>

///     <method name="setIncludeDomainParameters">
///         <signature>void setProfileIdentifier(boolean indicator)</signature>
///         <description><p>Specify whether domain parameters should be included in the generated certificate.</p></description>
///         <example>

generator.setIncludeDomainParameters(true);

///         </example>
///     </method>

///     <method name="generateCVCertificate">
///         <signature>ByteString generateCVCertificate(Key privateKey)</signature>
///         <description><p>Create a CV certificate.</p></description>
///         <example>

// Create empty private key object
var priKey = new Key("kp_cvca_ec_private.xml");

var certificate = generator.generateCVCertificate(priKey);

///         </example>
///     </method>

writeFileToDisk("cvca-certificate.crt", certificate);

outline = new OutlineNode("CV-Certificate");
outline.insert(new ASN1(certificate));
outline.show();
