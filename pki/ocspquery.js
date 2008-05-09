//
// Query OCSP Responder of RegTP
//

root = new X509("BNetzA-CA.cer");
cacrl = new X509("BNetzA-CRL.cer");
caocsp = new X509("BNetzA-OCSP.cer");

root.verifyWith(root);

o = new OCSPQuery(root);

o.add(root);

o.execute();

print("Status " + root.getSubjectDNString() + " : " + o.getStatusString(root));


o = new OCSPQuery(root);

o.add(cacrl);

o.execute();

print("Status " + cacrl.getSubjectDNString() + " : " + o.getStatusString(cacrl));


o = new OCSPQuery(root);

o.add(caocsp);

o.execute();

print("Status " + caocsp.getSubjectDNString() + " : " + o.getStatusString(caocsp));

