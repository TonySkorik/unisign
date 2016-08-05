using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace UniSign.CoreModules {
	static class XmlBuilder {
		public static XDocument GetSessionRequest(string sessionId, string interopSignatureThumb, StoreLocation interopSignatureStoreLocation) {
			XDocument ret =new XDocument();

			return ret;
		}

		public static string GetSessionRequestString(string sessionId, string interopSignatureThumb, StoreLocation interopSignatureStoreLocation) {
			return GetSessionRequest(sessionId,interopSignatureThumb,interopSignatureStoreLocation).ToString();
		}

		public static XDocument GetSignedDataRequest(string signedData, string interopSignatureThumb, StoreLocation interopSignatureStoreLocation) {
			XDocument ret = new XDocument();

			return ret;
		}

		public static string GetSignedDataRequestString(string signedData, string interopSignatureThumb, StoreLocation interopSignatureStoreLocation) {
			return GetSignedDataRequest(signedData,interopSignatureThumb,interopSignatureStoreLocation).ToString();
		}
	}
}
