<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:template match="/Main">
		<p><strong><xsl:value-of select="//app_id"/></strong></p>
		<p><xsl:value-of select="//sender_id"/></p>
		<p><u><xsl:value-of select="//service_id"/></u></p>
	</xsl:template>
</xsl:stylesheet>