/**
 * @fileoverview
 * 
 * A simple personalisation server
 */


/**
 * Creates a personalisation server instance.
 *
 * @class <p>Provides for a simple personalisation server that runs as instance in the
 *           MiniServer container on the Scripting Server.</p>
 *
 * @constructor
 */
function PersoServer() {
	this.crypto = new Crypto();
	this.af = new ApplicationFactory(this.crypto);

	this.apParser = new GPXML();
	this.apParser.defineArrayElement("/ApplicationProfile", "Key,DataElement,Function,ScriptFragment", "Name,Name,Name,Name");
	this.apParser.defineArrayElement("/ApplicationProfile/ScriptFragment", "KeyDeclaration,Declaration", "Name,Name");

	this.kpParser = new GPXML();
}



/**
 * Handle incoming XML requests.
 *
 * @param {String} method the method (POST/GET etc) from the HTTP request
 * @param {String[]} urllist the list of elements in the URL
 * @param {Number} urlindex the index of the component up to which the URL has been processed
 *   already.
 * @param {InputStream} entity the body of the HTTP request as Java InputStream
 * @return The body of the HTTP response.
 * @type String
 */
PersoServer.prototype.handleRequest = function (method, urllist, urlindex, entity) {
	var xmlentity;

	GPSystem.trace("Selector: " + urllist[urlindex]);
	
	switch(urllist[urlindex]) {
		case "ap" :
			if ((method != "PUT") || !entity) {
				throw new GPError("PersoServer", GPError.INVALID_ARGUMENTS, 0, "Method must be PUT and application profile contained");
			}
			xmlentity = this.apParser.parse(entity);
			this.af.addApplicationProfile(xmlentity);
			return("Application profile loaded");
			break;
		case "kp" :
			if ((method != "PUT") || !entity) {
				throw new GPError("PersoServer", GPError.INVALID_ARGUMENTS, 0, "Method must be PUT and application profile contained");
			}
			xmlentity = this.kpParser.parse(entity);
			this.af.addKeyProfile(xmlentity);
			return("Key profile loaded");
			break;
		case "reader":
			return this.handleReaderRequest(method, urllist, urlindex + 1, entity);
			break;
	}
	return "Unknown selector";
}



/**
 * Handle a reader related request, usually a card personalisation request for that reader
 *
 * @param {String} method the method (POST/GET etc) from the HTTP request
 * @param {String[]} urllist the list of elements in the URL
 * @param {Number} urlindex the index of the component up to which the URL has been processed
 *   already.
 * @param {InputStream} entity the body of the HTTP request as Java InputStream
 * @return The body of the HTTP response.
 * @type String
 */
PersoServer.prototype.handleReaderRequest = function (method, urllist, urlindex, entity) {

	var reader = decodeURIComponent(urllist[urlindex]);
	GPSystem.trace("Reader: " + reader);
	
	var card = new Card(reader);
	
	if (entity) {
		var parser = new GPXML();
		parser.defineArrayElement("/CardCustomization/ModuleIdentifierCode", "ApplicationData");
		parser.defineArrayElement("/CardCustomization/ModuleIdentifierCode/ApplicationData", "ProcessingStep");
		parser.defineArrayElement("/CardCustomization/ModuleIdentifierCode/ApplicationData/ICCData", "DataSet");
		parser.defineArrayElement("/CardCustomization/ModuleIdentifierCode/ApplicationData/ICCData/DataSet", "Data");
		parser.defineScriptElement("//");
		
		xmlentity = parser.parse(entity);
	}
	
	var adlist = new Array();
	var adl = xmlentity.ModuleIdentifierCode.ApplicationData;
	for (var i = 0; i < adl.length; i++) { 	
		var ad = new ApplicationData(adl[i]);
		adlist.push(ad);
		this.runScript(ad, card);
	}
		
	card.close();
	
	return this.createResponse(adlist);

}



/**
 * Run script from application profile with application data provided
 *
 * @param {ApplicationData} ad the application data to be used when running the script.
 * @param {Card} card the card object to use
 */
PersoServer.prototype.runScript = function (ad, card) {
	// AID associated with application
	var aid = ad.getAID();
	
	// ID of profile for application instance
	var id = ad.getProfileID();

	var dm = ad.getDataMapper();
		
	// Create the application object from the profile
	var appl = this.af.getApplicationInstance(dm, aid, card, id);

	var i = 0;
	do	{
		var script = ad.getScriptName(i);
		if (script) {
			appl.run(script);
		}
		i++;
	} while (script);
}



/**
 * Create response containing data created by script
 *
 * @param {ApplicationData[]} adlist the list of application data objects
 * @return the body of the reponse as CardAuditTrail message
 * @type String
 */
PersoServer.prototype.createResponse = function (adlist) {

	var result = 
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + 
"<CardAuditTrail xmlns=\"http://namespaces.globalplatform.org/systems-messaging/1.1.0\"\n" +
"     xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" +
"     xsi:schemaLocation=\"http://namespaces.globalplatform.org/systems-messaging/1.1.0 file:/C:/document/Specification/globalplatform/system/Messaging/piv.xsd\">\n" +
"  <LogIdentifierCode Identifier=\"ELECTRICAL\">\n" +
"    <CardConfigurationLog>\n" +
"      <CRN Number=\"2A01020304\"/>\n" +
"      <PhysicalCardIdentifier IdentifierType=\"CIN\" IdentifierValue=\"1234\">\n" +
"        <CardLifeCycleState>CardLifeCycleState</CardLifeCycleState>\n" +
"      </PhysicalCardIdentifier>\n" +
"    </CardConfigurationLog>\n";

	for (var i = 0; i < adlist.length; i++) {
		var ad = adlist[i];

		// AID associated with application
		var aid = ad.getAID();
	
		// ID of profile for application instance
		var id = ad.getProfileID();

		var dm = ad.getDataMapper();

		result += 
"    <ApplicationLog>\n" +
"      <AID AID=\"" + aid.toString(HEX) + "\" Order=\"1\"/>\n" +
"      <ApplicationProfileUniqueID>" + id.toString(HEX) + "</ApplicationProfileUniqueID>\n" +
"      <LogData>\n" +
"      	<DataSet>\n";

		for (var i in dm.response) {
			result +=
"      	  <Data DataElement=\"" + i + "\" Value=\"" + dm.response[i] + "\"/>\n";
		}
	
		result += 
"      	</DataSet>\n" +
"      </LogData>\n" +
"    </ApplicationLog>\n";
	}
	
	result +=
"  </LogIdentifierCode>\n" +
"</CardAuditTrail>\n";

	return result;
}



/**
 * Create an ApplicationData object containing the application data.
 *
 * @class <p>The ApplicationData class holds the inbound and outbound
 *           application data during script execution.</p>
 * @constructor
 * @param {Object} xml the XML tree of objects from the deserialized request
 */
function ApplicationData (xml) {
	this.xml = xml;
}



/**
 * Gets the AID from application data
 *
 * @return the AID
 * @type ByteString
 */
ApplicationData.prototype.getAID = function() {
	return new ByteString(this.xml.AID.AID, HEX);
}



/**
 * Gets the profile ID from application data
 *
 * @return the Profile ID
 * @type ByteString
 */
ApplicationData.prototype.getProfileID = function() {
	return new ByteString(this.xml.ApplicationProfileUniqueID.elementValue, HEX);
}



/**
 * Get the script name for the specified processing step
 *
 * @param {Number} index the index into the list of processing steps
 * @return the processing steps script name or null
 * @type String
 */
ApplicationData.prototype.getScriptName = function(index) {
	var ps = this.xml.ProcessingStep[index];

	if (!ps) {
		return null;
	} 
	return ps.Script.elementValue; 
}



/**
 * Create a data mapper for this application data
 *
 * @return the data mapper object
 * @type DataMapper
 */
ApplicationData.prototype.getDataMapper = function() {
	if (!this.dm) {
		this.dm = new DataMapper(this.xml.ICCData);
	}
	return this.dm;
}



/**
 * Create a data mapper object that is used by script execution
 * to retrieve and store data elements
 *
 * @class <p>The DataMapper is a container for data elements using during
 *           the execution of scripts in an application profile.</p>
 *
 * @constructor
 * @param {Object} xml the XML tree containing the DataSet node
 */
function DataMapper(xml) {
	this.xml = xml;
	this.data = new Array();		// Data repository
	this.response = new Array();	// List of updated fields
		
	for (var i = 0; i < this.xml.DataSet.length; i++) {
		var dataset = this.xml.DataSet[i];
		for (var j = 0; j < dataset.Data.length; j++) {
			this.data[dataset.Data[j].DataElement] = dataset.Data[j].Value; 
		}
	}
}



/**
 * Gets a data element from application data.
 *
 * This method is called from the application instance when a script execution
 * requires a data element.
 * 
 * @param {String} name the name of the data element
 * @param {Boolean} fixed true if the length of the data element is fixed
 * @param {Number} length the maximum or fixed length of the data element
 * @param {Number} encoding the encoding as per application profile
 * @return the data element
 * @type ByteString
 */
DataMapper.prototype.get = function(name, fixed, length, encoding) {
	var d = this.data[name];
	if (!d) {
		return null;
	}
	if (encoding == -1) {
		encoding = HEX;	// Default encoding is HEX unless specified in profile
	}
	return new ByteString(d, encoding);		
}



/**
 * Saves a data element modified or created by script
 *
 * @param {String} name the name of the data element
 * @param {ByteString} value the value of the data element
 * @param {Number} encoding the encoding as per application profile
 */
DataMapper.prototype.put = function(name, value, encoding) {
	if (encoding == -1) {
		encoding = HEX;	// Default encoding is HEX unless specified in profile
	}

	this.data[name] = value.toString(encoding);
	this.response[name] = this.data[name];
}



//
// Create server instance
//
var persoServer = new PersoServer();

function handleRequest(req, res) {
	var uri = req.pathInfo.substr(1);
	var urilist = uri.split("/");
	var result = persoServer.handleRequest(req.method, urilist, 0, req.getEntityAsInputStream());
	res.print(result);
}

GPSystem.trace("persoserver.js processed...");