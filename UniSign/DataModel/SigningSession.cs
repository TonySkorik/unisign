using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Xsl;
using UniSign.DataModel.Enums;

namespace UniSign.DataModel {
	class SigningSession {

		#region [P & F]

		public string StartupArg;

		public XDocument ServerSessionMessage;
		public string SessionId;

		public string DataToSign;
		public XDocument DocToSign;

		public XDocument XslStylesheet;
		public string HumanReadableHtml;

		public SignatureInfo SignInfo;
		
		public string SignedData;

		#endregion

		#region [CONSTRUCTOR]
		public SigningSession(string sessionMessage) {
			ServerSessionMessage = XDocument.Parse(sessionMessage);
			SessionId = ServerSessionMessage.Root?.Attribute("session_id").Value;

			/*
			<SigningInfo id='SIGNED' session_id='...'>
				<DocumentToSign>
					<!-- XML BASE64 (Utf-8) -->
				</DocumentToSign>
				<DocumentXsl>
					<!-- XSLT Stylesheet BASE64 (Utf-8) -->
				</DocumentXsl>
				<SignatureInfo>
					<Type>detached|side-by-side|enveloped</Type>
					<SmevMode*>2|3</SmevMode>
					<NodeId*>
						<!-- Textual node ID or blank or abscent if signature must be placed inside (or side-by-side with) the root -->
					</NodeId>
				</SignatureInfo>
				<тут ЭП для SIGNED />
			</SigningInfo>
			*/

			DataToSign =
				Encoding.UTF8.GetString(
					Convert.FromBase64String(
						ServerSessionMessage.Root.Descendants("DocumentToSign").First().Value
					)
				);

			DocToSign = XDocument.Parse(DataToSign);
			
			XslStylesheet =
				XDocument.Parse(
					Encoding.UTF8.GetString(
						Convert.FromBase64String(
							ServerSessionMessage.Root.Descendants("DocumentXsl").First().Value
						)
					)
				);

			HumanReadableHtml = _transformDoc();

			SignInfo = new SignatureInfo(ServerSessionMessage.Root.Descendants("SignatureInfo").First());
		}
		#endregion

		private string _transformDoc() {
			XslCompiledTransform xslt = new XslCompiledTransform();
			xslt.Load(XslStylesheet.CreateReader());

			MemoryStream transformedData = new MemoryStream();
			XmlWriter transformedDocument = new XmlTextWriter(transformedData,Encoding.UTF8);

			xslt.Transform(DocToSign.CreateReader(), transformedDocument);
			transformedData.Position = 0L; // 'cause after conversion stream read pointer is already in the last position

			TextReader transformedHtmlReader = new StreamReader(transformedData);
			return transformedHtmlReader.ReadToEnd();
		}
	}
}
