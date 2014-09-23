<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
	<xsl:output method="html"/>
	
	<xsl:template match="/requirements">
		<html>
			<head>
			<style type="text/css">
				h2 { margin-top:1cm; background-color: #e8e8e8; }			
				h1 { margin-top:0.5cm; }			
			</style>
				<title><xsl:value-of select="@id"/> - Requirements</title>
			</head>
			<body>

				<h1><xsl:value-of select="@id"/> - <xsl:value-of select="name"/></h1>

				<h2>Description</h2>
				<p><xsl:apply-templates select="description"/></p>

				<xsl:apply-templates select="requirement" mode="full"/>

			</body>
		</html>
	</xsl:template>
	

	<xsl:template match="requirement" mode="full">

		<h2><xsl:attribute name="id"><xsl:value-of select="@id"/></xsl:attribute><xsl:value-of select="@id"/></h2>

		<xsl:apply-templates select="description"/>

		<h3>Refines</h3>
		<ul>
		    <xsl:apply-templates select="refines/refine"/>
		</ul>
	</xsl:template>



	<xsl:template match="description" name="description">
		<xsl:copy-of select="*"/>
	</xsl:template>



	<xsl:template match="refine" name="refine">
		<li><a>	<xsl:attribute name="href">
				<xsl:if test="@source != ''">
					<xsl:value-of select="@source" />
					<xsl:text>.html</xsl:text>
				</xsl:if>
				<xsl:text>#</xsl:text>
				<xsl:value-of select="@id" />
			</xsl:attribute>
		<xsl:value-of select="@id"/></a></li>
	</xsl:template>

</xsl:stylesheet>
