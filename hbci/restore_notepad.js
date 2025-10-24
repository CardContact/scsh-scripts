/**
 * Restore EF_NOTEPAD
 */

var card = new Card(_scsh3.reader);

var mf = new CardFile(card, ":3F00");

var pin = Dialog.prompt("<html><p>FinTS PIN</p><p>(Für Eingabe am PINPAD leer lassen)</p></html>", "");
if (pin == null) {
	throw new Error("User abort");
}

if (pin.length > 0) {
	pin = new ByteString(pin, ASCII);
} else {
	pin = undefined;
}

mf.pinFormat = "String encoding";
if (!mf.performCHV(true, 0x03, pin)) {
	throw new Error("PIN Prüfung fehlgeschlagen");
}

var df_notepad = new CardFile(card, "#D2760000254E500100");

var ef_notepad = new CardFile(df_notepad, ":1A");

var record = new ByteString("EF_NOTEPAD aus dump_notepad.js", HEX);

ef_notepad.updateRecord(1, record);
