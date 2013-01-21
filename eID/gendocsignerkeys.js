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
 * @fileoverview Generate Document Signer key pair and save to GP profile
 */

 
load("tools/x509certificategenerator.js");


/**
 * Write key profile
 * 
 * @param {String} filename the absolute file name to write the file to
 * @param {XML} xml the structure to write 
 */
function writeXML(filename, xml) {
	print("Writing " + filename + "...");
	var fw = new java.io.FileWriter(filename);
	fw.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
	fw.write(xml.toXMLString());
	fw.close();
}



/**
 * Generate an ECC key pair on brainpoolP256r1 and save as GP key profile
 * 
 * @param name the name of the key
 */
function generateECCKeyPair(name) {
	var curve = new ByteString("brainpoolP256r1", OID);
	var keysize = 256;

	var pubKey = new Key();
	pubKey.setType(Key.PUBLIC);
	pubKey.setComponent(Key.ECC_CURVE_OID, curve);

	var priKey = new Key();
	priKey.setType(Key.PRIVATE);
	priKey.setComponent(Key.ECC_CURVE_OID, curve);

	var crypto = new Crypto();
	crypto.generateKeyPair(Crypto.EC, pubKey, priKey);

	var gp = new Namespace("http://namespaces.globalplatform.org/systems-profiles/1.1.0");

	var priKeyXML = 
		<gp:KeyProfile xmlns:gp={gp} UniqueID="2B0601040181C31F100006" ProfileVersion="1.1.0" ErrataVersion="0">
			<gp:Description>{"PrK_" + name + " ECDSA Private Key"}</gp:Description>
			<gp:Revisions arrayElement="Revision" arrayIndex="#">
				<gp:Revision Version="1.0.0" Date="2011-11-11" Time="00:00:00" By="www.smartcard-hsm.org" Digest="00000000"/>
			</gp:Revisions>
			<gp:KeyInfo Name="ECPrivate" Type="PRIVATE" SubType="EC" Size={keysize} Mode="TEST"/>
			<gp:Attribute Sensitive="false" Importable="true" Exportable="true"/>
			<gp:Usage Encrypt="true" Decrypt="true" DecryptEncrypt="true" Sign="true" Verify="true" Wrap="true" Unwrap="true" UnwrapWrap="true" Derive="true"/>
			<gp:Value Format="ECPRIVATE" arrayElement="Component" arrayIndex="#">
				<gp:Component Name="ECC_CURVE_OID" Encoding="HEX" Value={curve.toString(HEX)}></gp:Component>
				<gp:Component Name="ECC_D" Encoding="HEX" Value={priKey.getComponent(Key.ECC_D).toString(HEX)}></gp:Component>
			</gp:Value>
		</gp:KeyProfile>
		
	var pubKeyXML =
		<gp:KeyProfile xmlns:gp={gp} UniqueID="2B0601040181C31F100008" ProfileVersion="1.1.0" ErrataVersion="0">
			<gp:Description>{"PuK_" + name + " ECDSA Public Key"}</gp:Description>
			<gp:Revisions arrayElement="Revision" arrayIndex="#">
				<gp:Revision Version="1.0.0" Date="2011-11-11" Time="00:00:00" By="www.smartcard-hsm.org" Digest="00000000"/>
			</gp:Revisions>
			<gp:KeyInfo Name="ECPublic" Type="PUBLIC" SubType="EC" Size={keysize} Mode="TEST"/>
			<gp:Attribute Sensitive="false" Importable="true" Exportable="true"/>
			<gp:Usage Encrypt="true" Decrypt="true" DecryptEncrypt="true" Sign="true" Verify="true" Wrap="true" Unwrap="true" UnwrapWrap="true" Derive="true"/>
			<gp:Value Format="ECPUBLIC" arrayElement="Component" arrayIndex="#">
				<gp:Component Name="ECC_CURVE_OID" Encoding="HEX" Value={curve.toString(HEX)}></gp:Component>
				<gp:Component Name="ECC_QX" Encoding="HEX" Value={pubKey.getComponent(Key.ECC_QX).toString(HEX)}></gp:Component>
				<gp:Component Name="ECC_QY" Encoding="HEX" Value={pubKey.getComponent(Key.ECC_QY).toString(HEX)}></gp:Component>
			</gp:Value>
		</gp:KeyProfile>
		
	var fname = GPSystem.mapFilename("kp_prk_" + name + ".xml", GPSystem.CWD);
	writeXML(fname, priKeyXML);

	var fname = GPSystem.mapFilename("kp_puk_" + name + ".xml", GPSystem.CWD);
	writeXML(fname, pubKeyXML);
	
	var x = new X509CertificateGenerator(this.crypto);

	x.reset();
	x.setSerialNumber(new ByteString("01", HEX));
	x.setSignatureAlgorithm(Crypto.ECDSA_SHA256);
	var issuer = { C:"DE", O:"CardContact", CN:"CardContact Document Signer" };
	x.setIssuer(issuer);
	x.setNotBefore("111111111111Z");
	x.setNotAfter( "411111111111Z");
	var subject = issuer;
	x.setSubject(subject);
	x.setPublicKey(pubKey);
	x.addKeyUsageExtension(	X509CertificateGenerator.digitalSignature );
	x.addSubjectKeyIdentifierExtension();

	var cert = x.generateX509Certificate(priKey);

	cert.verifyWith(cert);
	
	var filename = GPSystem.mapFilename("C_" + name + ".cer", GPSystem.CWD);
	print("Writing " + filename);

	var file = new java.io.FileOutputStream(filename);
	file.write(cert.getBytes());
	file.close();
}



generateECCKeyPair("DocSigner");
