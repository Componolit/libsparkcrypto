<?xml version="1.0"?>

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

   <xsl:output method="text" omit-xml-declaration="yes" indent="no"/>

	<xsl:template match="/GNATstack_Information">
      <xsl:apply-templates match="/global/unboundedset/unbounded/unboundedobjectset/unboundedobject"/>
      <xsl:text>Stack analysis done.</xsl:text>
      <xsl:text>&#xa;</xsl:text>
	</xsl:template>

	<xsl:template match="unboundedobject">
      <xsl:value-of select="@file"/>
      <xsl:text>:</xsl:text>
      <xsl:value-of select="@line"/>
      <xsl:text>:</xsl:text>
      <xsl:value-of select="@column"/>
      <xsl:text>: Unbounded: </xsl:text>
      <xsl:value-of select="@object"/>
      <xsl:text>&#xa;</xsl:text>
	</xsl:template>

   <xsl:template match="text()"/>

</xsl:stylesheet>
