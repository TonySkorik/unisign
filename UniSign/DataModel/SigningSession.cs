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
using UniSign.ViewModel;

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

		public readonly SignatureInfo SignInfo;
		
		public string SignedData;

		public bool Success;

		#endregion

		#region [CONSTRUCTOR]
		public SigningSession(string sessionMessage) {
			Success = true;
			ServerSessionMessage = XDocument.Parse(sessionMessage);
			if (ServerSessionMessage.Root.Attribute("version").Value != MainViewModel.ProgramVersion) {
				Success = false;
				return;
			}
			SessionId = ServerSessionMessage.Root?.Attribute("session_id").Value;

			/*
			 * <SessionResponse version='1.1'>
					<SigningInfo id="SIGNED_BY_SERVER" session_id="..." vsrsion="...">
							<DocumentToSign>PE1haW4+Cgk8YXBwX2lkPtCg0YPRgdGB0LrQuNC1INCx0YPQutCy0Ys8L2FwcF9pZD4KCTxzZW5kZXJfaWQ+0KHQvdC+0LLQsCDQsdGD0LrQstGLPC9zZW5kZXJfaWQ+Cgk8c2VydmljZV9pZD4xMDAwMTAwNTQ4NTwvc2VydmljZV9pZD4KPC9NYWluPg==</DocumentToSign> 
							<DocumentXsl>PHhzbDpzdHlsZXNoZWV0IHZlcnNpb249IjEuMCIgeG1sbnM6eHNsPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L1hTTC9UcmFuc2Zvcm0iPgoJPHhzbDp0ZW1wbGF0ZSBtYXRjaD0iL01haW4iPgoJCTxwPjxzdHJvbmc+PHhzbDp2YWx1ZS1vZiBzZWxlY3Q9Ii8vYXBwX2lkIi8+PC9zdHJvbmc+PC9wPgoJCTxwPjx4c2w6dmFsdWUtb2Ygc2VsZWN0PSIvL3NlbmRlcl9pZCIvPjwvcD4KCQk8cD48dT48eHNsOnZhbHVlLW9mIHNlbGVjdD0iLy9zZXJ2aWNlX2lkIi8+PC91PjwvcD4KCTwveHNsOnRlbXBsYXRlPgo8L3hzbDpzdHlsZXNoZWV0Pg==</DocumentXsl> 
							<SignatureInfo>
									<Type>enveloped</Type>									
									<NodeId> *
											SIGNED_1
									</NodeId>
							</SignatureInfo>
					</SigningInfo>
					<Signature/>
				</SessionResponse>  
			*/

			DataToSign =
				Encoding.UTF8.GetString(
					Convert.FromBase64String(
						ServerSessionMessage.Root.Descendants("DocumentToSign").First().Value
					)
				);

			DocToSign = XDocument.Parse(DataToSign);
			try {
				XslStylesheet =
					XDocument.Parse(
						Encoding.UTF8.GetString(
							Convert.FromBase64String(
								ServerSessionMessage.Root.Descendants("DocumentXsl").First().Value
								)
							)
						);
				HumanReadableHtml = _transformDoc();
			} catch (Exception e) {
				HumanReadableHtml = DocToSign.Root.ToString();
			}
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
