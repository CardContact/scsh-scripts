//
//  ---------
// |.##> <##.|  CardContact Software & System Consulting
// |#       #|  32429 Minden, Germany (www.cardcontact.de)
// |#       #|  Copyright (c) 1999-2005. All rights reserved
// |'##> <##'|  See file COPYING for details on licensing
//  --------- 
//
// Global Platform ApplicationFactory Class Tests and API Documentation
//

// Create a default crypto object
var crypto = new Crypto();

// Create an application factory that can create application instances from profiles

var af = new ApplicationFactory(crypto);

// Add key profiles to repository
af.addKeyProfile("kp_single_des_1.xml");
af.addKeyProfile("kp_double_des.xml");
af.addKeyProfile("kp_triple_des.xml");

// Add application profiles to repository
af.addApplicationProfile("ap_test.xml");


// Create default card object
var card = new Card(_scsh3.reader);

// AID associated with application
var aid = new ByteString("A0000002471001", HEX);

// ID of profile for application instance
var id = new ByteString("2B0601040181C31F0000", HEX);

// Simple data mapper that returns the name of the data element as value
// The data mapper is called whenever a script fragment in an application instance is run
var dataMapper = new Object();
dataMapper.get = function(name, fixed, length) { return new ByteString("DE " + name + " Fixed=" + fixed + " Length=" + length, ASCII); };

// Create the application object from the profile
var appl = af.getApplicationInstance(dataMapper, aid, card, id);

// Run the script fragment named "Hello World Test"
// The script fragment uses GPSystem.trace() for output
appl.run("Hello World Test");

