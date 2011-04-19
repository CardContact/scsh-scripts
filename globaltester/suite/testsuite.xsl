<?xml version="1.0" encoding="iso-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="/">
 <html>
 	<head>
 		
 	</head>
 	<body style="font-family:Verdana; font-size:10pt; color:black">
 	<p><img src="HJP_Logo_schrift.gif"/></p>
 	<strong style="font-family:Verdana; font-size:14pt; color:black">GlobalTester TestSuite</strong>

  <xsl:apply-templates />
 </body></html>
</xsl:template>

<xsl:template match="testsuiteid">
 <p style="font-family:Verdana; font-size:12pt; color:black">
   <strong>ID:</strong>
   <xsl:apply-templates />
 </p>
</xsl:template>

<xsl:template match="version">
 <p style="font-family:Verdana; font-size:12pt; color:black">
   <strong>Version: </strong> 
   <xsl:apply-templates />
 </p>
</xsl:template>

<xsl:template match="date">
 <p style="font-family:Verdana; font-size:12pt; color:black">
   <strong>Date: </strong>
   <xsl:apply-templates />
 </p>
</xsl:template>


<xsl:template match="author">
 <p style="font-family:Verdana; font-size:12pt; color:black">
   <strong>Author: </strong>
   <xsl:apply-templates />
 </p>
</xsl:template>

<xsl:template match="company">
 <p style="font-family:Verdana; font-size:12pt; color:black">
   <strong>Company: </strong>
   <xsl:apply-templates />
 </p>
</xsl:template>


<xsl:template match="shortdescription">
 <p style="font-family:Verdana; font-size:12pt; color:black">
   <strong>Short Description: </strong>
   <xsl:apply-templates />
 </p>
</xsl:template>

<xsl:template match="description">
 <p style="font-family:Verdana; font-size:12pt; color:black">
   <strong>Description: </strong>
   <xsl:apply-templates />
 </p>
</xsl:template>

<xsl:template match="specificationname">
 <p style="font-family:Verdana; font-size:12pt; color:black">
   <strong>Specification: </strong>
   <xsl:apply-templates />
 </p>
</xsl:template>

<xsl:template match="specificationversion">
 <p style="font-family:Verdana; font-size:12pt; color:black">
   <strong>Specification Version: </strong>
   <xsl:apply-templates />
 </p>
</xsl:template>

<xsl:template match="globalpreconditions">
 <p style="font-family:Verdana; font-size:12pt; color:black">
   <strong>Global Preconditions: </strong>
   <xsl:apply-templates />
 </p>
</xsl:template>


<xsl:template match="testcase">
  <p>
  <a>
    <xsl:attribute name="href"><xsl:value-of select="."/> </xsl:attribute>
    <xsl:apply-templates />
  </a>
  </p>
</xsl:template>


</xsl:stylesheet>