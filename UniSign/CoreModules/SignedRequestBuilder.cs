using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;

using UniSign.ViewModel;

namespace UniSign.CoreModules {
	static class SignedRequestBuilder {

		public static string GetSessionRequest(string sessionId, string interopSignatureThumb, StoreLocation interopSignatureStoreLocation) {
			XDocument ret =XDocument.Parse(UniSign.Properties.Resources.SessionRequest);
			ret.Root.Attribute("version").Value = MainViewModel.ProgramVersion;
			ret.Root.Element("SessionId").Value = sessionId;
			ret.Root.Element("SessionId").Attribute("timestamp").Value = DateTime.Now.ToString("s").Replace("T"," ");

			XmlDocument signThis = new XmlDocument();
			signThis.LoadXml(ret.ToString());

			X509Certificate2 cert = SignatureProcessor.GetCertificateByThumbprint(interopSignatureThumb,
																				interopSignatureStoreLocation);
			#if DEBUG
			return signThis.InnerXml;
			#endif

			#if !DEBUG
			return SignatureProcessor.Sign(SignatureProcessor.SignatureType.Smev2SidebysideDetached, cert, signThis, false, "SIGNED_BY_SIGNER");
			#endif
		}

		public static string GetSignedDataRequest(string sessionId, string signedData, string interopSignatureThumb, StoreLocation interopSignatureStoreLocation) {
			XDocument ret = XDocument.Parse(UniSign.Properties.Resources.SignedDataRequest);

			ret.Root.Attribute("version").Value = MainViewModel.ProgramVersion;
			ret.Root.Element("SignedData").Value = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedData));
			ret.Root.Element("SignedData").Attribute("sessionId").Value = sessionId;
			ret.Root.Element("SignedData").Attribute("timestamp").Value = DateTime.Now.ToString("s").Replace("T", " ");

			XmlDocument signThis = new XmlDocument();
			signThis.LoadXml(ret.ToString());

			X509Certificate2 cert = SignatureProcessor.GetCertificateByThumbprint(interopSignatureThumb,
																				interopSignatureStoreLocation);

			return SignatureProcessor.Sign(SignatureProcessor.SignatureType.Smev2SidebysideDetached, cert, signThis, false, "SIGNED_BY_SIGNER");
		}
	}
}
