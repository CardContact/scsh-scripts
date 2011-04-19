<?xml version="1.0" encoding="iso-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="/">
 <html>
        <head>
                
        </head>
        <body style="font-family:Verdana; font-size:14pt; color:black">
        <p><img src="../HJP_Logo_schrift.gif"/></p>
        <strong>GlobalTester TestCase</strong>
  <xsl:apply-templates />
 </body></html>
</xsl:template>

<xsl:template match="testsuiteid">
 <p style="font-family:Verdana; font-size:12pt; color:black">
   <strong>TestSuite ID:</strong>
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

<xsl:template match="references">
 <p style="font-family:Verdana; font-size:12pt; color:black">
   <strong>References: </strong>
   <xsl:apply-templates />
 </p>
</xsl:template>

<xsl:template match="testcase">
 <p style="font-family:Verdana; font-size:12pt; color:black">
   <strong>Test case ID: </strong>
   <xsl:apply-templates />
 </p>
</xsl:template>

<xsl:template match="quality">
 <p style="font-family:Verdana; font-size:12pt; color:black">
   <strong>Quality: </strong>
   <xsl:apply-templates />
 </p>
</xsl:template>

<xsl:template match="preconditions">
 <strong>Preconditions: </strong>
 <p style="font-family:Courier; font-size:8pt; color:black">
   <pre><xsl:apply-templates /></pre>
 </p>
</xsl:template>

<xsl:template match="testscript">
 <strong>Testscript: </strong>
 <p style="font-family:Courier; font-size:8pt; color:black">
   <pre><xsl:apply-templates /></pre>
 </p>
</xsl:template>

<xsl:template match="postconditions">
 <strong>Postconditions: </strong>
 <p style="font-family:Courier; font-size:8pt; color:black">
   <pre><xsl:apply-templates /></pre>
 </p>
</xsl:template>
</xsl:stylesheet>
