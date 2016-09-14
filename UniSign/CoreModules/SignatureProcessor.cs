using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using exp=System.Linq.Expressions;
using System.Reflection;
using System.Resources;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using CryptoPro.Sharpei.Xml;
using CryptoPro.Sharpei;
using Newtonsoft.Json;
using Formatting = Newtonsoft.Json.Formatting;

namespace UniSign.CoreModules {

	#region [XDOC <=> XMLDOC] extension methods
	public static class XdocConversionExtensions {
		public static XElement GetXElement(this XmlNode node) {
			XDocument xDoc = new XDocument();
			using(XmlWriter xmlWriter = xDoc.CreateWriter())
				node.WriteTo(xmlWriter);
			return xDoc.Root;
		}

		public static XmlNode GetXmlNode(this XElement element) {
			using(XmlReader xmlReader = element.CreateReader()) {
				XmlDocument xmlDoc = new XmlDocument();
				xmlDoc.Load(xmlReader);
				return xmlDoc;
			}
		}

		public static XDocument GetXDocument(this XmlDocument document) {
			XDocument xDoc = new XDocument();
			XmlWriterSettings settings = new XmlWriterSettings() {
				OmitXmlDeclaration = true,
				NewLineHandling = NewLineHandling.None
			};
			//using (XmlWriter xmlWriter = xDoc.CreateWriter()) {
			using(XmlWriter xmlWriter = XmlWriter.Create(xDoc.CreateWriter(),settings)) {
				document.WriteTo(xmlWriter);
			}
			/*
			XmlDeclaration decl =
			    document.ChildNodes.OfType<XmlDeclaration>().FirstOrDefault();
			if(decl != null)
				xDoc.Declaration = new XDeclaration(decl.Version, decl.Encoding,
				    decl.Standalone);
			*/
			return xDoc;
		}

		public static XmlDocument GetXmlDocument(this XDocument document) {
			using(XmlReader xmlReader = document.CreateReader()) {
				XmlDocument xmlDoc = new XmlDocument();
				xmlDoc.Load(xmlReader);
				if(document.Declaration != null) {
					XmlDeclaration dec = xmlDoc.CreateXmlDeclaration(document.Declaration.Version,
					    document.Declaration.Encoding, document.Declaration.Standalone);
					xmlDoc.InsertBefore(dec, xmlDoc.FirstChild);
				}
				return xmlDoc;
			}
		}
	}
	#endregion
	public static class SignatureProcessor {

		#region [SIGN]
		public enum SignatureType { Smev2BaseDetached, Smev2ChargeEnveloped, Smev2SidebysideDetached, Smev3BaseDetached, Smev3SidebysideDetached, Smev3Ack, SigDetached, Unknown };
		public enum StoreType : int {LocalMachine = 1, CurrentUser = 2}
		

		#region [CERTIFICATE] Search

		#region [BY THUMBPRINT]
		private static X509Certificate2 _searchCertificateByThumbprint(string certificateThumbprint) {
			try {
				certificateThumbprint = Regex.Replace(certificateThumbprint, @"[^\da-zA-z]", string.Empty).ToUpper();
				X509Store compStore =
					new X509Store("My", StoreLocation.LocalMachine);
				compStore.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);

				X509Store store =
					new X509Store("My", StoreLocation.CurrentUser);
				store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);

				X509Certificate2Collection found =
					compStore.Certificates.Find(
						X509FindType.FindByThumbprint,
//						X509FindType.FindBySerialNumber, 
						certificateThumbprint,
						false
						);

				if (found.Count == 0) {
					found = store.Certificates.Find(
						X509FindType.FindByThumbprint,
//							X509FindType.FindBySerialNumber,
						certificateThumbprint,
						false
						);
					if (found.Count != 0) {
						// means found in Current User store
					} else {
						throw new Exception($"Certificate with thumbprint {certificateThumbprint} not found");
					}
				} else {
					// means found in LocalMachine store
				}

				if (found.Count == 1) {
					return found[0];
				} else {
					throw new Exception($"More than one certificate with thumbprint {certificateThumbprint} found!");
				}
			} catch (CryptographicException e) {
				throw new Exception($"Unnknown cryptographic exception! Original message : {e.Message}");
			}
		}

		public static X509Certificate2 GetCertificateByThumbprint(string thumbprint, StoreLocation storeLocation) {
			X509Store compStore =
					new X509Store("My", storeLocation);
			compStore.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
			
			X509Certificate2Collection found =
				compStore.Certificates.Find(
					X509FindType.FindByThumbprint,
					thumbprint,
					false
				);
			return found.Count > 0 ? found[0] : null;
		}

		#endregion

		#region [GET ALL CERTS FROM STORAGE]

		public static List<X509Certificate2> GetAllCertificatesFromStore(StoreType storeType) {
			X509Store store = 
				storeType == StoreType.CurrentUser? 
				new X509Store("My", StoreLocation.CurrentUser) 
				: 
				new X509Store("My", StoreLocation.LocalMachine);
			
			store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly | OpenFlags.MaxAllowed);
			return store.Certificates.Cast<X509Certificate2>().ToList();
		}

		public static List<X509Certificate2> GetAllCertificatesFromStore(StoreLocation storeLocation) {
			X509Store store = new X509Store("My", storeLocation);
			store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly | OpenFlags.MaxAllowed);
			return store.Certificates.Cast<X509Certificate2>().ToList();
		}

		#endregion

		#endregion
		public static string Sign(SignatureType mode, X509Certificate2 cert, XmlDocument signThis, bool assignDs, string nodeToSign) {
			if(nodeToSign == null) {
				nodeToSign = "ID_SIGN";
			}
			XmlDocument signedXmlDoc = new XmlDocument();
			//AsymmetricAlgorithm privateKey;

			if(!cert.HasPrivateKey) {
				throw new Exception($"PRIVATE_KEY_MISSING] Certificate (subject: <{cert.Subject}>) private key not found.");
			}
			
			try {
				switch(mode) {
					case SignatureType.Smev2SidebysideDetached:
						if(string.IsNullOrEmpty(nodeToSign)) {
							throw new Exception($"NODE_ID_REQUIRED] <node_id> value is empty. This value is required");
						}
						signedXmlDoc = SignXmlNode(signThis, cert, nodeToSign);
						break;
					case SignatureType.Smev2ChargeEnveloped:
						signedXmlDoc = SignXmlFileEnveloped(signThis, cert);
						break;
					case SignatureType.Smev2BaseDetached:
						signedXmlDoc = SignXmlFileSmev2(signThis, cert);
						break;
					case SignatureType.Smev3BaseDetached:
						if(string.IsNullOrEmpty(nodeToSign)) {
							throw new Exception($"NODE_ID_REQUIRED] <node_id> value is empty. This value is required");
						}
						signedXmlDoc = SignXmlFileSmev3(signThis, cert, nodeToSign, assignDs);
						break;
					case SignatureType.Smev3SidebysideDetached:
						if(string.IsNullOrEmpty(nodeToSign)) {
							throw new Exception($"NODE_ID_REQUIRED] <node_id> value is empty. This value is required");
						}
						signedXmlDoc = SignXmlFileSmev3(signThis, cert, nodeToSign, assignDs, isAck: false, isSidebyside: true);
						break;
					case SignatureType.Smev3Ack:
						if(string.IsNullOrEmpty(nodeToSign)) {
							throw new Exception($"NODE_ID_REQUIRED] <node_id> value is empty. This value is required");
						}
						signedXmlDoc = SignXmlFileSmev3(signThis, cert, nodeToSign, assignDs, isAck: true);
						break;
					case SignatureType.SigDetached:
						return Convert.ToBase64String(SignXmlFileDetached(signThis, cert, nodeToSign, assignDs));
				}
			} catch(Exception e) {
				throw new Exception($"UNKNOWN_SIGNING_EXCEPTION] Unknown signing exception. Original message: {e.Message}");
			}
			return signedXmlDoc.InnerXml;
		}

		#region [SIMPLE NODE SIGN]

		private static XmlNode getNodeWithAttributeValue(XmlNodeList nodelist, string attributeValue) {
			XmlNode ret = null;
			foreach(XmlNode xn in nodelist) {
				if(xn.HasChildNodes) {
					ret = getNodeWithAttributeValue(xn.ChildNodes, attributeValue);
					if(ret != null)
						break;
				}
				if(xn.Attributes != null && xn.Attributes.Count != 0) {
					foreach(XmlAttribute xa in xn.Attributes) {
						if(xa.Value == attributeValue) {
							ret = xn;
							break;
						}
					}
				}
			}
			return ret;
		}

		public static XmlDocument SignXmlNode(XmlDocument doc, X509Certificate2 certificate, string nodeId) {

			//----------------------------------------------------------------------------------------------CREATE SIGNED XML
			SignedXml signedXml = new SignedXml(doc) { SigningKey = certificate.PrivateKey };
			//----------------------------------------------------------------------------------------------REFERNCE
			Reference reference = new Reference {
				Uri = "#" + nodeId,
				#pragma warning disable 612
				DigestMethod = CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3411UrlObsolete
				#pragma warning disable 612
			};

			XmlDsigExcC14NTransform c14 = new XmlDsigExcC14NTransform();
			reference.AddTransform(c14);

			// Add the reference to the SignedXml object.
			signedXml.AddReference(reference);
			//----------------------------------------------------------------------------------------------SIGNATURE SETUP
			signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
			signedXml.SignedInfo.SignatureMethod = CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3410UrlObsolete;
			//----------------------------------------------------------------------------------------------KEYINFO
			KeyInfo keyInfo = new KeyInfo();
			KeyInfoX509Data X509KeyInfo = new KeyInfoX509Data(certificate);
			keyInfo.AddClause(X509KeyInfo);
			signedXml.KeyInfo = keyInfo;
			//----------------------------------------------------------------------------------------------SIGN DOCUMENT
			signedXml.ComputeSignature();
			//----------------------------------------------------------------------------------------------GET XML
			XmlElement xmlDigitalSignature = signedXml.GetXml();
			//=============================================================================APPEND SIGNATURE TO DOCUMENT

			getNodeWithAttributeValue(doc.ChildNodes, nodeId)?.ParentNode?.AppendChild(xmlDigitalSignature);

			return doc;
		}
		#endregion

		#region [SIMPLE ENVELOPED SIGN]

		public static XmlDocument SignXmlFileEnveloped(XmlDocument doc, X509Certificate2 certificate, string nodeId = null) {
			nodeId = string.Empty;
			//----------------------------------------------------------------------------------------------CREATE SIGNED XML
			SignedXml signedXml = new SignedXml(doc) { SigningKey = certificate.PrivateKey };
			//----------------------------------------------------------------------------------------------REFERNCE
			Reference reference = new Reference {
				Uri = nodeId,
#pragma warning disable 612
				DigestMethod = CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3411UrlObsolete
#pragma warning disable 612
			};

			XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
			reference.AddTransform(env);
			XmlDsigExcC14NTransform c14 = new XmlDsigExcC14NTransform();
			reference.AddTransform(c14);

			// Add the reference to the SignedXml object.
			signedXml.AddReference(reference);
			//----------------------------------------------------------------------------------------------SIGNATURE SETUP
			signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
			signedXml.SignedInfo.SignatureMethod = CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3410UrlObsolete;
			//----------------------------------------------------------------------------------------------KEYINFO
			KeyInfo keyInfo = new KeyInfo();
			KeyInfoX509Data X509KeyInfo = new KeyInfoX509Data(certificate);
			keyInfo.AddClause(X509KeyInfo);
			signedXml.KeyInfo = keyInfo;
			//----------------------------------------------------------------------------------------------SIGN DOCUMENT
			signedXml.ComputeSignature();
			//----------------------------------------------------------------------------------------------GET XML
			XmlElement xmlDigitalSignature = signedXml.GetXml();
			//----------------------------------------------------------------------------------------------APPEND SIGNATURE
			XmlNode root = doc.SelectSingleNode("/*");
			root?.AppendChild(doc.ImportNode(xmlDigitalSignature, true));

			return doc;
		}

		#endregion

		#region [SMEV 2]

		#region [UTILITY]

		public const string WSSecurityWSSENamespaceUrl =
			"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
		public const string WSSecurityWSUNamespaceUrl =
			"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

		public class Smev2SignedXml : SignedXml {
			public Smev2SignedXml(XmlDocument document)
				: base(document) { }

			public override XmlElement GetIdElement(XmlDocument document, string idValue) {
				XmlNamespaceManager nsmgr = new XmlNamespaceManager(document.NameTable);
				nsmgr.AddNamespace("wsu", WSSecurityWSUNamespaceUrl);
				return document.SelectSingleNode("//*[@wsu:Id='" + idValue + "']", nsmgr) as XmlElement;
			}
		}
		//----------------------------------------------------------------------------------------------------------------------------------------------------ADD TEMPLATE
		public static string wsu_ = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
		public static string soapenv_ = "http://schemas.xmlsoap.org/soap/envelope/";
		public static string wsse_ = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
		public static string ds_ = "http://www.w3.org/2000/09/xmldsig#";

		#endregion

		#region [TEMPLATE GENERATION]

		static XmlDocument AddTemplate(XmlDocument base_document, X509Certificate2 certificate) {

			base_document.PreserveWhitespace = true;

			XmlNode root = base_document.SelectSingleNode("/*");
			string rootPrefix = root.Prefix;

			XmlElement security = base_document.CreateElement("wsse", "Security", wsse_);
			security.SetAttribute("actor", soapenv_, "http://smev.gosuslugi.ru/actors/smev");
			XmlElement securityToken = base_document.CreateElement("wsse", "BinarySecurityToken", wsse_);
			securityToken.SetAttribute("EncodingType",
						"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
			securityToken.SetAttribute("ValueType",
						"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
			securityToken.SetAttribute("Id", wsu_, "CertId");
			securityToken.Prefix = "wsse";
			securityToken.InnerText = Convert.ToBase64String(certificate.RawData);
			XmlElement signature = base_document.CreateElement("Signature");
			XmlElement canonicMethod = base_document.CreateElement("CanonicalizationMethod");
			canonicMethod.SetAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");
			XmlElement signatureMethod = base_document.CreateElement("SignatureMethod");
			signatureMethod.SetAttribute("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411");
			XmlElement keyInfo = base_document.CreateElement("KeyInfo");
			keyInfo.SetAttribute("Id", "key_info");
			XmlElement securityTokenReference = base_document.CreateElement("wsse", "SecurityTokenReference", wsse_);
			XmlElement reference = base_document.CreateElement("wsse", "Reference", wsse_);
			reference.SetAttribute("URI", "#CertId");
			reference.SetAttribute("ValueType",
						"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");

			XmlElement startElement = base_document.GetElementsByTagName(rootPrefix + ":Header")[0] as XmlElement;
			startElement?.AppendChild(security).AppendChild(securityToken);
			startElement = base_document.GetElementsByTagName("wsse:Security")[0] as XmlElement;
			startElement?.AppendChild(signature);

			startElement = base_document.GetElementsByTagName("Signature")[0] as XmlElement;
			startElement?.AppendChild(keyInfo).AppendChild(securityTokenReference).AppendChild(reference);

			return base_document;
		}

		#endregion

		#region [SIGN SMEV 2]
		public static XmlDocument SignXmlFileSmev2(XmlDocument doc, X509Certificate2 certificate) {

			XmlNode root = doc.SelectSingleNode("/*");
			string rootPrefix = root.Prefix;
			//----------------------------------------------------------------------------------------------CREATE STRUCTURE
			XmlDocument tDoc = AddTemplate(doc, certificate);
			//----------------------------------------------------------------------------------------------ROOT PREFIX 
			XmlElement bodyElement = tDoc.GetElementsByTagName(rootPrefix + ":Body")[0] as XmlElement;
			string referenceUri = bodyElement.GetAttribute("wsu:Id");
			//----------------------------------------------------------------------------------------------SignedXML CREATE
			//нужен для корректной отработки wsu:reference 
			Smev2SignedXml signedXml = new Smev2SignedXml(tDoc) {
				SigningKey = certificate.PrivateKey
			};
			//----------------------------------------------------------------------------------------------REFERNCE
			Reference reference = new Reference {
				DigestMethod = CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3411UrlObsolete,
				Uri = "#" + referenceUri
			};

			XmlDsigExcC14NTransform c14 = new XmlDsigExcC14NTransform();
			reference.AddTransform(c14);

			signedXml.AddReference(reference);
			//----------------------------------------------------------------------------------------------SIGNATURE SETUP
			signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
#pragma warning disable 612
			signedXml.SignedInfo.SignatureMethod = CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3410UrlObsolete;
#pragma warning disable 612
			//----------------------------------------------------------------------------------------------KEYINFO
			KeyInfo keyInfo = new KeyInfo();
			KeyInfoX509Data X509KeyInfo = new KeyInfoX509Data(certificate);
			keyInfo.AddClause(X509KeyInfo);
			signedXml.KeyInfo = keyInfo;
			//----------------------------------------------------------------------------------------------SIGN DOCUMENT
			signedXml.ComputeSignature();
			//----------------------------------------------------------------------------------------------GET XML
			XmlElement xmlDigitalSignature = signedXml.GetXml();
			//----------------------------------------------------------------------------------------------APPEND SIGNATURE TAGS
			tDoc.GetElementsByTagName("Signature")[0].PrependChild(
				tDoc.ImportNode(xmlDigitalSignature.GetElementsByTagName("SignatureValue")[0], true));
			tDoc.GetElementsByTagName("Signature")[0].PrependChild(
				tDoc.ImportNode(xmlDigitalSignature.GetElementsByTagName("SignedInfo")[0], true));
			((XmlElement)tDoc.GetElementsByTagName("Signature")[0]).SetAttribute("xmlns", ds_);

			return tDoc;
		}

		#endregion

		#endregion

		#region [SMEV 3]

		#region [UTILITY]
		private static void _assignNsPrefix(XmlElement element, string prefix) {
			element.Prefix = prefix;
			foreach(var child in element.ChildNodes) {
				if(child is XmlElement) {
					_assignNsPrefix(child as XmlElement, prefix);
				}
			}
		}
		#endregion

		#region [SIGN SMEV 3]
		public static XmlDocument SignXmlFileSmev3(XmlDocument doc, X509Certificate2 certificate, string signingNodeId, bool assignDs, bool isAck = false, bool isSidebyside = false) {
			XmlNamespaceManager nsm = new XmlNamespaceManager(doc.NameTable);
			nsm.AddNamespace("ns", "urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1");
			nsm.AddNamespace("ns1", "urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1");
			nsm.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");


			SignedXml sxml = new SignedXml(doc) { SigningKey = certificate.PrivateKey };

			//=====================================================================================REFERENCE TRASFORMS
			Reference reference = new Reference {
				Uri = "#" + signingNodeId,
#pragma warning disable 612
				//Расчет хеш-суммы ГОСТ Р 34.11-94 http://www.w3.org/2001/04/xmldsig-more#gostr3411
				DigestMethod = CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3411UrlObsolete
#pragma warning disable 612
			};

			XmlDsigExcC14NTransform excC14n = new XmlDsigExcC14NTransform();
			reference.AddTransform(excC14n);

			XmlDsigSmevTransform smevTransform = new XmlDsigSmevTransform();
			reference.AddTransform(smevTransform);

			if(isAck) {
				XmlDsigEnvelopedSignatureTransform enveloped = new XmlDsigEnvelopedSignatureTransform();
				reference.AddTransform(enveloped);
			}

			sxml.AddReference(reference);

			//=========================================================================================CREATE SIGNATURE
			sxml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

			//Формирование подписи ГОСТ Р 34.10-2001 http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411 
			sxml.SignedInfo.SignatureMethod = CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3410UrlObsolete;
			KeyInfo keyInfo = new KeyInfo();
			KeyInfoX509Data X509KeyInfo = new KeyInfoX509Data(certificate);
			keyInfo.AddClause(X509KeyInfo);
			sxml.KeyInfo = keyInfo;

			sxml.ComputeSignature();

			XmlElement signature = sxml.GetXml();
			//==================================================================================================add ds:
			if(assignDs) {
				_assignNsPrefix(signature, "ds");
				XmlElement xmlSignedInfo = signature.SelectSingleNode("ds:SignedInfo", nsm) as XmlElement;

				XmlDocument document = new XmlDocument();
				document.PreserveWhitespace = false;
				document.LoadXml(xmlSignedInfo.OuterXml);

				//create new canonicalization object based on original one
				Transform canonicalizationMethodObject = sxml.SignedInfo.CanonicalizationMethodObject;
				canonicalizationMethodObject.LoadInput(document);

				//get new hshing object based on original one
				SignatureDescription description =
					CryptoConfig.CreateFromName(sxml.SignedInfo.SignatureMethod) as SignatureDescription;
				if(description == null) {
					throw new CryptographicException(
						$"Не удалось создать объект SignatureDescription по имени [{sxml.SignedInfo.SignatureMethod}]");
				}
				HashAlgorithm hash = description.CreateDigest();
				if(hash == null) {
					throw new CryptographicException(
						$"Не удалось создать объект HashAlgorithm из SignatureDescription по имени [{sxml.SignedInfo.SignatureMethod}]");
				}

				//compute new SignedInfo digest value
				byte[] hashVal = canonicalizationMethodObject.GetDigestedOutput(hash);

				//compute new signature
				XmlElement xmlSignatureValue = signature.SelectSingleNode("ds:SignatureValue", nsm) as XmlElement;
				xmlSignatureValue.InnerText =
					Convert.ToBase64String(description.CreateFormatter(sxml.SigningKey).CreateSignature(hashVal));
			}
			//=============================================================================APPEND SIGNATURE TO DOCUMENT
			if(!isSidebyside) {
				doc.GetElementsByTagName("CallerInformationSystemSignature",
										"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1")[0].InnerXml = "";
				doc.GetElementsByTagName("CallerInformationSystemSignature",
										"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1")[0].AppendChild(signature);
			} else {
				getNodeWithAttributeValue(doc.ChildNodes, signingNodeId)?.ParentNode?.AppendChild(signature);
			}
			return doc;
		}
		#endregion

		#endregion

		#region [DETACHED]

		public static byte[] SignXmlFileDetached(XmlDocument doc, X509Certificate2 certificate, string signingNodeId, bool assignDs) {

			ContentInfo contentInfo = new ContentInfo(Encoding.UTF8.GetBytes(doc.OuterXml));
			SignedCms signedCms = new SignedCms(contentInfo, true);
			CmsSigner cmsSigner = new CmsSigner(certificate) { IncludeOption = X509IncludeOption.EndCertOnly };
			cmsSigner.SignedAttributes.Add(
				new CryptographicAttributeObject(
					new Oid("1.2.840.113549.1.9.3"),
					new AsnEncodedDataCollection(
						new AsnEncodedData(Encoding.UTF8.GetBytes("1.2.840.113549.1.7.1"))
					)
				)
			);
			signedCms.ComputeSignature(cmsSigner);
			//  Кодируем CMS/PKCS #7 подпись сообщения.
			return signedCms.Encode();
		}

		#endregion

		#endregion

		#region [READ CERTIFICATE]
		
		public static X509Certificate2 ReadCertificateFromXml(XDocument signedXml) {
			X509Certificate2 cert = null;

			XElement signatureElement = (
				from elt in signedXml.Root.Descendants()
				where elt.Name == (XNamespace)SignedXml.XmlDsigNamespaceUrl + "Signature"
				//where elt.Name == UnismevData.NamespaceStorage.Ns2 + "SenderInformationSystemSignature"
				select elt
			).DefaultIfEmpty(null).First();

			if (signatureElement != null) {
				string certificateNodeContent = (
					from node in signatureElement.Descendants()
					where node.Name == (XNamespace)SignedXml.XmlDsigNamespaceUrl + "X509Certificate"
					select node.Value.ToString()
					).DefaultIfEmpty(
						//means Signature may be not named with an xmlns:ds
						(
							from node in signatureElement.Descendants()
							where node.Name == "X509Certificate"
							select node.Value.ToString()
							).DefaultIfEmpty("").First()
					).First();

				if (certificateNodeContent == "") {
					// means signatureInfo appears to be empty
				} else {
					cert = new X509Certificate2(Encoding.UTF8.GetBytes(certificateNodeContent));
				}
			} else {
				//means tere is no SenderInformationSystemSignature node
				// cert = null
			}
			return cert;
		}
		
		public static X509Certificate2 SelectCertificateUI(StoreLocation storeLocation) {
			X509Store store = new X509Store("MY", storeLocation);
			store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
			X509Certificate2Collection collection =
				(X509Certificate2Collection)store.Certificates;
			
			X509Certificate2Collection scollection =
				X509Certificate2UI.SelectFromCollection(collection,
				$"Выбор сертификата. Хранилище : {storeLocation.ToString()}",
				"Выберите сертификат для взаимодействия.",
				X509SelectionFlag.SingleSelection);

			return scollection.Count>0 ? scollection[0] : null;
		}

		#endregion

		#region [VERIFY]

		#region [STANDARD]
		
		public static bool VerifySignature(SignatureType mode, XmlDocument message, X509Certificate2 cert = null, string certificateThumb = null, string nodeId = null) {
			SignedXml signedXml = new SignedXml(message);
			Smev2SignedXml smev2SignedXml = null;

			Dictionary<string, XmlElement> signatures = new Dictionary<string, XmlElement>();

			XmlNodeList signaturesInDoc =
					message.GetElementsByTagName(
						"Signature", SignedXml.XmlDsigNamespaceUrl
						);
			if (signaturesInDoc.Count < 1) {
				throw new Exception($"NO_SIGNATURES_FOUND] No signatures found in the input file.");
			}
			signatures =
				signaturesInDoc
				.Cast<XmlElement>()
				.ToDictionary((elt) => {
					XNamespace ns = elt.GetXElement().Name.Namespace;
					string sigRef = elt.GetXElement().Descendants(ns + "Reference").First().Attributes("URI").First().Value;
					return elt.GetXElement().Descendants(ns + "Reference").First().Attributes("URI").First().Value.Replace("#", "");
				},
					(elt => elt)
				);

			if(!string.IsNullOrEmpty(nodeId) && !signatures.ContainsKey(nodeId)) {
				throw new Exception($"REFERENCED_SIGNATURE_NOT_FOUND] Referenced signature (-node_id=<{nodeId}>) not found in the input file.");
			}
			
			switch(mode) {
				case SignatureType.Smev2BaseDetached:
					smev2SignedXml = new Smev2SignedXml(message);
					try {
						smev2SignedXml.LoadXml(!string.IsNullOrEmpty(nodeId) ? signatures[nodeId] : signatures["body"]);
					} catch(Exception e) {
						throw new Exception($"CERTIFICATE_CONTENT_CORRUPTED] <X509Certificate> node content appears to be corrupted. Message: {e.Message}");
					}
					XmlNodeList referenceList = smev2SignedXml.KeyInfo
						.GetXml()
						.GetElementsByTagName("Reference", WSSecurityWSSENamespaceUrl);
					if(referenceList.Count == 0) {
						throw new Exception("SMEV2_CERTIFICATE_REFERENCE_NOT_FOUND] No certificate reference found in input file");
					}
					string binaryTokenReference = ((XmlElement)referenceList[0]).GetAttribute("URI");
					if(string.IsNullOrEmpty(binaryTokenReference) || binaryTokenReference[0] != '#') {
						throw new Exception("SMEV2_MALFORMED_CERTIFICATE_REFERENCE] Certificate reference appears to be malformed");
					}

					XmlElement binaryTokenElement = smev2SignedXml.GetIdElement(message, binaryTokenReference.Substring(1));
					if(binaryTokenElement == null) {
						throw new Exception($"SMEV2_CERTIFICATE_NOT_FOUND] Referenced certificate not found. Reference: <{binaryTokenReference.Substring(1)}>");
					}

					try {
						cert = new X509Certificate2(Convert.FromBase64String(binaryTokenElement.InnerText));
					} catch(Exception e) {
						throw new Exception($"SMEV2_CERTIFICATE_CORRUPTED] Smev2 certificate node content appears to be corrupted. Message: {e.Message}");
					}
					break;
				case SignatureType.Smev2ChargeEnveloped:
					if(signaturesInDoc.Count > 1) {
						throw new Exception($"CHARGE_TOO_MANY_SIGNATURES_FOUND] More than one signature found. Found: {signaturesInDoc.Count} sigantures.");
					}
					if(!_chargeStructureOk(message)) {
						throw new Exception($"CHARGE_MALFORMED_DOCUMENT] Document structure is malformed. <Signature> node must be either root node descendant or root node descentant descendant.");
					}

					try {
						signedXml.LoadXml(signatures.First().Value);
					} catch(Exception e) {
						throw new Exception($"CERTIFICATE_CONTENT_CORRUPTED] <X509Certificate> node content appears to be corrupted. Message: {e.Message}");
					}

					break;
				case SignatureType.Smev2SidebysideDetached:
				case SignatureType.Smev3BaseDetached:
				case SignatureType.Smev3SidebysideDetached:
					try {
						signedXml.LoadXml(!string.IsNullOrEmpty(nodeId) ? signatures[nodeId] : signatures.First().Value);
					} catch(Exception e) {
						throw new Exception($"CERTIFICATE_CONTENT_CORRUPTED] <X509Certificate> node content appears to be corrupted. Message: {e.Message}");
					}
					break;
				case SignatureType.SigDetached:
				case SignatureType.Smev3Ack:
					throw new Exception($"UNSUPPORTED_SIGNATURE_TYPE] Signature type <{mode}> is unsupported. Possible values are : <smev2_base.enveloped>, <smev2_charge.enveloped>, <smev2_sidebyside.detached>, <smev3_base.detached>");
			}

			bool result = smev2SignedXml == null ?
				cert == null ? signedXml.CheckSignature() : signedXml.CheckSignature(cert, true) :
				smev2SignedXml.CheckSignature(cert.PublicKey.Key);

			return result;
		}

		private static bool _chargeStructureOk(XmlDocument charge) {
			XDocument x = charge.GetXDocument();
			XNamespace ds = SignedXml.XmlDsigNamespaceUrl;
			if(x.Root.Descendants(ds + "Signature").Ancestors().First().Equals(x.Root) ||
				x.Root.Descendants(ds + "Signature").Ancestors().First().Ancestors().First().Equals(x.Root)) {
				return true;
			}
			return false;
		}

		#endregion

		#region [DS: PREFIXED] Some heavy wizardry here
		private static Type tSignedXml = typeof(SignedXml);
		private static ResourceManager SecurityResources = new ResourceManager("system.security", tSignedXml.Assembly);

		//these methods from the SignedXml class still work with prefixed Signature elements, but they are private
		private static exp.ParameterExpression thisSignedXmlParam = exp.Expression.Parameter(tSignedXml);
		private static Func<SignedXml, bool> CheckSignatureFormat
			= exp.Expression.Lambda<Func<SignedXml, bool>>(
				exp.Expression.Call(thisSignedXmlParam, tSignedXml.GetMethod("CheckSignatureFormat", BindingFlags.NonPublic | BindingFlags.Instance)),
				thisSignedXmlParam).Compile();
		private static Func<SignedXml, bool> CheckDigestedReferences
			= exp.Expression.Lambda<Func<SignedXml, bool>>(
				exp.Expression.Call(thisSignedXmlParam, tSignedXml.GetMethod("CheckDigestedReferences", BindingFlags.NonPublic | BindingFlags.Instance)),
				thisSignedXmlParam).Compile();

		public static bool CheckSignatureDs(XmlDocument xmlDoc, RSACryptoServiceProvider key) {
			if(key == null)
				throw new ArgumentNullException("key");

			SignedXml signedXml = new SignedXml(xmlDoc);

			//For XPath
			XmlNamespaceManager namespaceManager = new XmlNamespaceManager(xmlDoc.NameTable);
			namespaceManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#"); //this prefix is arbitrary and used only for XPath

			XmlElement xmlSignature = xmlDoc.SelectSingleNode("//ds:Signature", namespaceManager) as XmlElement;

			signedXml.LoadXml(xmlSignature);

			//These are the three methods called in SignedXml's CheckSignature method, but the built-in CheckSignedInfo will not validate prefixed Signature elements
			return CheckSignatureFormat(signedXml) && CheckDigestedReferences(signedXml) && CheckSignedInfo(signedXml, key);
		}

		private static bool CheckSignedInfo(SignedXml signedXml, AsymmetricAlgorithm key) {
			//Copied from reflected System.Security.Cryptography.Xml.SignedXml
			SignatureDescription signatureDescription = CryptoConfig.CreateFromName(signedXml.SignatureMethod) as SignatureDescription;
			if(signatureDescription == null)
				throw new CryptographicException(SecurityResources.GetString("Cryptography_Xml_SignatureDescriptionNotCreated"));

			Type type = Type.GetType(signatureDescription.KeyAlgorithm);
			Type type2 = key.GetType();
			if(type != type2 && !type.IsSubclassOf(type2) && !type2.IsSubclassOf(type))
				return false;

			HashAlgorithm hashAlgorithm = signatureDescription.CreateDigest();
			if(hashAlgorithm == null)
				throw new CryptographicException(SecurityResources.GetString("Cryptography_Xml_CreateHashAlgorithmFailed"));

			//Except this. The SignedXml class creates and cananicalizes a Signature element without any prefix, rather than using the element from the document provided
			byte[] c14NDigest = GetC14NDigest(signedXml, hashAlgorithm);

			AsymmetricSignatureDeformatter asymmetricSignatureDeformatter = signatureDescription.CreateDeformatter(key);
			return asymmetricSignatureDeformatter.VerifySignature(c14NDigest, signedXml.Signature.SignatureValue);
		}

		private static byte[] GetC14NDigest(SignedXml signedXml, HashAlgorithm hashAlgorithm) {
			Transform canonicalizeTransform = signedXml.SignedInfo.CanonicalizationMethodObject;
			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.LoadXml(signedXml.SignedInfo.GetXml().OuterXml);
			canonicalizeTransform.LoadInput(xmlDoc);
			return canonicalizeTransform.GetDigestedOutput(hashAlgorithm);
		}
		#endregion

		#endregion
	}
}
