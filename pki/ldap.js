//
// Obtain current root certificate for German qualified signature
//

print("Connecting to LDAP server for German Bundesnetzagentur...");
var ldap = new LDAP("ldap://ldap.nrca-ds.de:389/dc=ldap,dc=nrca-ds,dc=de");

print("Obtaining current root certificate...");
var node = ldap.get("x509serialNumber=42,cn=10R-CA 1:PN,o=Bundesnetzagentur,c=DE");

print("LDAP entry contains:");
for (i in node) {
	print(i + " = " + node[i]);
}

// Create X509 object from DER encoded LDAP entry
var rootCert = new X509(node["x509caCert"]);

print("Information from certificate:");
print("Issuer DN : " + rootCert.getIssuerDNString());
print("Subject DN: " + rootCert.getSubjectDNString());

