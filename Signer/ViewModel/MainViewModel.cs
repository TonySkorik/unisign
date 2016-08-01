using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Web;
using System.Xml;
using Signer.CoreModules;
using Signer.DataModel;
using Signer.DataModel.Enums;

namespace Signer.ViewModel {
	class MainViewModel:INotifyPropertyChanged {

		public event PropertyChangedEventHandler PropertyChanged;
		private void NotifyPropertyChanged([CallerMemberName] string propertyName = "") {
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
		}

		#region [P & F]
		private SigningSession _s;
		private string _humanRadableDataToSign;
		private string _serverHtmlMessage;
		private string _originalXmlDataToSign;
		private bool _messageIsError;
		private ObservableCollection<X509Certificate2> _certificates;

		public string HumanRadableDataToSign {
			get { return _humanRadableDataToSign; }
			set {
				_humanRadableDataToSign = value;
				NotifyPropertyChanged();
			}
		}
		public string ServerHtmlMessage {
			get { return _serverHtmlMessage; }
			set {
				_serverHtmlMessage = value;
				NotifyPropertyChanged();
			}
		}
		public string OriginalXmlDataToSign {
			get { return _originalXmlDataToSign; }
			set {
				_originalXmlDataToSign = value;
				NotifyPropertyChanged();
			}
		}
		public ObservableCollection<X509Certificate2> Certificates {
			get { return _certificates; }
			set {_certificates = value; }
		}
		public bool MessageIsError {
			get { return _messageIsError; }
			set {
				_messageIsError = value;
				NotifyPropertyChanged();
			}
		}

		#endregion

		public MainViewModel() {
			Certificates = new ObservableCollection<X509Certificate2>();
			LoadCertificatesFromStore(SignatureProcessor.StoreType.CurrentUser);

			System.Net.ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 |
															SecurityProtocolType.Tls;

			System.Net.ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => {
				X509Certificate2 c = (X509Certificate2)cert;
				return c.Thumbprint == Signer.Properties.Settings.Default.serverCertificateThumbprint;
			};
		}

		public async Task<HttpResponseMessage> GetServerSessionData(string startupArg) {

			//startupArg is like : unisign:session_id=12345-45-54545-12
			Uri startupUri = new Uri(startupArg);
			
			HttpClient client = new HttpClient() {
				Timeout = new TimeSpan(0,0,0,60)
			};
			
			UriBuilder serverUri = new UriBuilder(Signer.Properties.Settings.Default.getFileUri) {
				Query = $"oper=getfile&{startupUri.PathAndQuery}"
			};

			return await client.GetAsync(serverUri.Uri);
		}

		public void InitSession(string sessionDataString, string startupArg) {
			_s = new SigningSession(sessionDataString) {
				StartupArg = startupArg
			};
			//set viewModel fields
			OriginalXmlDataToSign = _s.DataToSign;
			HumanRadableDataToSign = _s.HumanReadableHtml;
		}

		public void LoadCertificatesFromStore(SignatureProcessor.StoreType storeType) {
			List<X509Certificate2> certs = SignatureProcessor.GetAllCertificatesFromStore(storeType);
			Certificates.Clear();
			//Certificates.Add(null);
			foreach (X509Certificate2 c in certs) {
				Certificates.Add(c);
			}
		}

		public string SignWithSelectedCert(X509Certificate2 cert) {
			//use SignInfo from _s

			SignatureInfo si = _s.SignInfo;
			SignatureProcessor.SigningMode signMode = SignatureProcessor.SigningMode.Simple;

			switch(_s.SignInfo.SigType) {
				case SignatureType.Detached:
					signMode = SignatureProcessor.SigningMode.Detached;
					break;
				case SignatureType.Enveloped:
					signMode = SignatureProcessor.SigningMode.Simple;
					break;
				case SignatureType.SideBySide:
					switch(_s.SignInfo.SmevMode) {
						case 2:
							signMode = SignatureProcessor.SigningMode.Smev2;
							break;
						case 3:
							signMode = SignatureProcessor.SigningMode.Smev3;
							break;
					}
					break;
			}

			XmlDocument docToSign = new XmlDocument();
			docToSign.LoadXml(_s.DataToSign);

			return SignatureProcessor.Sign(signMode, cert, docToSign, false, _s.SignInfo.NodeId);
		}

		public async Task<HttpResponseMessage> SendDataBackToServer(string signedData) {
			Uri startupUri = new Uri(_s.StartupArg);

			HttpClient client = new HttpClient() {
				Timeout = new TimeSpan(0, 0, 0, 60)
			};

			UriBuilder serverUri = new UriBuilder(Signer.Properties.Settings.Default.getFileUri) {
				Query = $"oper=signed&{startupUri.PathAndQuery}"
			};

			HttpContent content = new StringContent(signedData);
			content.Headers.ContentType = new MediaTypeHeaderValue("text/xml");

			return await client.PostAsync(serverUri.Uri,content);
		}
	}
}
