/**
 * Restore EF_NOTEPAD
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

var record = new ByteString("EF_NOTEPAD aus dump_notepad.js", HEX);

ef_notepad.updateRecord(1, record);
