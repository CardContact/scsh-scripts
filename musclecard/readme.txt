
Scripts for the MuscleCard Applet (www.musclecard.com)

The applet must be installed with AID A0 00 00 00 01 01

tools.js		Library of useful functions
init.js			Format applet, setting memory size and initial PINs. Must be run first
status.js		Display the status of the applet, list PINs, objects and keys
genrsa1024.js		Generate a 1024 bit RSA key pair as key 0/1
signrsa1024.js		Sign using the key generated with genrsa1024.js
genrsa2048.js		Generate a 2048 bit RSA key pair as key 2/3
signrsa2048.js		Sign using the key generated with genrsa2048.js
loadintojcop.js		Load applet into GP compliant JCOP card
loadintocyberflex64.js	Load applet into GP compliant Cyberflex 64K card
deleteapplet.js		Remove applet from card
CardEdge.cap		CAP file containing the applet
CardEdgeCF.cap		CAP file containing the applet converted for Cyberflex cards
