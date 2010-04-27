//
//  ---------
// |.##> <##.|  CardContact Software & System Consulting
// |#       #|  32429 Minden, Germany (www.cardcontact.de)
// |#       #|  Copyright (c) 2010. All rights reserved
// |'##> <##'|  See file COPYING for details on licensing
//  --------- 
//
// BlackListGenerator Tests and API Documentation
//

/// <?xml version="1.0" encoding="ISO-8859-1"?>
/// <?xml-stylesheet type="text/xsl" href="docclass.xsl" ?>
/// <class xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
///     xsi:noNamespaceSchemaLocation="api_doc.xsd" name="X509">
///     <description><p>Class implementing support for black lists specific by TR-03129, Version 1.0</p>
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

load("BlackListGenerator.js");

///     <constructor>
///         <signature>BlackListGenerator()</signature>
///         <description>Create the vlack list generator.</description>
///         <example>

generator = new BlackListGenerator();

///         </example>

///     <method name="setVersion">
///         <signature>void setVersion(ByteString version)</signature>
///         <description><p>Set the version number of the black list (must be 0 for Version 1.00 of TR-03129)</p></description>
///         <example>

var version = new ByteString("00", HEX);

generator.setVersion(version);

///         </example>
///     </method>

///     <method name="setType">
///         <signature>void setType(ByteString type)</signature>
///         <description><p>Set the type of the black list. Use one of the already defined constants:
///				BlackListGEnerator.COMPLETE_LIST - for a complete black list
///				BlackListGEnerator.ADDED_LIST - for a black list containing added items
///				BlackListGEnerator.REMOVED_LIST - for a black list containing removed items
///			</p></description>
///         <example>

generator.setType(BlackListGenerator.REMOVED_LIST);

///         </example>
///     </method>


///     <method name="setListID">
///         <signature>void setListID(ByteString listID)</signature>
///         <description><p>Set the unique ID of the black list.</p></description>
///         <example>

var listID = new ByteString("201003200001", ASCII); 

generator.setListID(listID);

///         </example>
///     </method>


///     <method name="setDeltaBase">
///         <signature>void setDeltaBase(ByteString deltaBase)</signature>
///         <description><p>Set the unique ID of the delta base of the black list.</p></description>
///         <example>

var deltaBase = new ByteString("201003150001", HEX); 

generator.setDeltaBase(deltaBase);

///         </example>
///     </method>

///     <method name="addBlackListDetails">
///         <signature>ByteString addBlackListDetails(ByteString sectorID, ByteString[] sectorSpecificIDs)</signature>
///         <description><p>Add details to the black list.</p></description>
///         <example>

var sector_A = new ByteString("0xFFFFFF", HEX);
var sectorSpecificIDs_A = [new ByteString("0x0101", HEX), new ByteString("0x0202", HEX)];

generator.addBlackListDetails(sector_A, sectorSpecificIDs_A);

var sector_B = new ByteString("0xEEEEEE", HEX);
var sectorSpecificIDs_B = [new ByteString("0x0303", HEX), new ByteString("0x0404", HEX)];

generator.addBlackListDetails(sector_B, sectorSpecificIDs_B);

///         </example>
///     </method>

///     <method name="generateBlackList">
///         <signature>ByteString generateBlackList()</signature>
///         <description><p>Create the black list.</p></description>
///         <example>

var blackList = generator.generateBlackList();

var bl = new ASN1(blackList);
print(bl);

///         </example>
///     </method>

/// </class>
