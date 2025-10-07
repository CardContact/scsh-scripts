/**
 * Datenfeld EF_NOTEPAD in HBCI Chipkarte nach Beschreiben mit Moneyplex reparieren.
 *
 * Moneyplex kodiert das Längenfeld am ersten Tag 'F0' fehlerhaft. Bei einer Länge
 * im Value von mehr als 127 Byte muss das Längenfeld mit 8x <x Byte Länge> kodiert werden,
 * Die Länge 133 wird nicht als '85' kodiert sondern '81 85'. Die '81' bedeutet dabei
 * erweitertes Längenfeld in den nächsten 1 Byte.
 *
 * Dieses Script dumped den Inhalt des ersten Records im EF_NOTEPAD und ermittelt ob der Fehler besteht.
 * Wenn ja, dann kann der Eintrag in Record 1 korrigiert werden.
 *
 * Zur Sicherheit sollte man vor dem Reparaturversuch den Inhalt des EF_NOTEPAD per Cut&Paste in das
 * Script restore_notepad.js sichern. Damit lässt sich der alte Zustand wieder herstellen.
 */

var card = new Card(_scsh3.reader);

var pin = Dialog.prompt("Enter PIN", "");
if (pin == null) {
	throw new Error("User abort");
}

card.sendApdu(0x00, 0x20, 0x00, 0x03, new ByteString(pin, ASCII), [0x9000]);

var mf = new CardFile(card, ":3F00");
var df_notepad = new CardFile(card, "#D2760000254E500100");

var ef_notepad = new CardFile(df_notepad, ":1A");
var record = ef_notepad.readRecord(1);

print("Inhalt des EF_NOTEPAD. Bitte sichern zur Wiederherstellung bei Bedarf (restore_notepad.js)");
print("--->8------>8------>8------>8------>8------>8------>8------>8------>8------>8------>8---");
print(record.toString(HEX));
print("--->8------>8------>8------>8------>8------>8------>8------>8------>8------>8------>8---");

try	{
	var a = new ASN1(record);
	print(a);
}
catch(e) {
	print("EF_NOTEPAD fehlerhaft: " + e);

	var body = record.bytes(2);
	var a = new ASN1(record.byteAt(0), record.bytes(2));
	var a = new ASN1(a.getBytes());
	print(a);

	var str = Dialog.prompt("Reparatur versuchen ?");
	if (str != null) {
		record = a.getBytes();
		ef_notepad.updateRecord(1, record);
	}
}
