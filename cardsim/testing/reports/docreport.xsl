<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="2.0">
	<xsl:output method="html" encoding="ISO-8859-1"/>
	
	<xsl:template match="/testreport">
		<html>
			<head>
			<style type="text/css">
				h2 { margin-top:1cm; background-color: #e8e8e8; }
				h1 { margin-top:0.5cm; }
				table {
					width: 100%;
					table-layout: fixed;
					border: 1px solid #d8d8d8;
					border-collapse: collapse;
					border-spacing: 0px;
				}

				table td {
					border: 1px solid #d8d8d8;
					overflow: hidden;
					text-overflow: ellipsis;
				}

				table th {
					border: 1px solid #d8d8d8;
					text-align: left;
				}
			</style>
			<title>Test Report</title>
			</head>
			<body>
				<h1>Test Results</h1>

				<table border="1">
				<colgroup><col width="250"/><col/><col width="60"/></colgroup>
				<tr><th>Id</th><th>Description</th><th>Verdict</th></tr>
				<xsl:apply-templates select="testcaseresult" mode="table"/>
				</table>
				
			</body>
		</html>
	</xsl:template>



	<xsl:template match="testcaseresult" mode="table">

	<tr>
	<td><xsl:value-of select="@id"/></td><td><xsl:value-of select="description"/></td>
	
	<xsl:if test="verdict='Passed'">
		<td style="background-color:green;color:white"><xsl:value-of select="verdict"/></td>
	</xsl:if>

	<xsl:if test="verdict='Failed'">
		<td style="background-color:red"><xsl:value-of select="verdict"/></td>
	</xsl:if>

	</tr>
	
	</xsl:template>
</xsl:stylesheet>
