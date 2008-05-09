//
//  ---------
// |.##> <##.|  CardContact Software & System Consulting
// |#       #|  32429 Minden, Germany (www.cardcontact.de)
// |#       #|  Copyright (c) 1999-2005. All rights reserved
// |'##> <##'|  See file COPYING for details on licensing
//  --------- 
//
// Read open Maschine Readable Travel Document (MRTD)

card = new Card(_scsh3.reader);

lds = new CardFile(card, "#A0000002471001");

ef_com = new CardFile(lds, ":011E");
val = ef_com.readBinary();
print(val.length);

ef_dg1 = new CardFile(lds, ":0101");
val = ef_dg1.readBinary();
print(val.length);

ef_dg2 = new CardFile(lds, ":0102");
val = ef_dg2.readBinary();
print(val.length);

ef_sod = new CardFile(lds, ":011D");
val = ef_sod.readBinary();
print(val.length);

