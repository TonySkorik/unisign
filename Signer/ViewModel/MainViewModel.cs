using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Web;


using Signer.DataModel;


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
		private string _originalXmlDataTOSign;
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
			get { return _originalXmlDataTOSign; }
			set {
				_originalXmlDataTOSign = value;
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
		
		public async Task<HttpResponseMessage> GetServerSessionData(string startupArg) {

			//startupArg is like : unisign:session_id=12345-45-54545-12
			Uri startupUri = new Uri(startupArg);

			System.Net.ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 |
															SecurityProtocolType.Tls;

			System.Net.ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => {
				X509Certificate2 c = (X509Certificate2)cert;
				return c.Thumbprint == Signer.Properties.Settings.Default.serverCertificateThumbprint;
			};

			/*
			var filter = new HttpBaseProtocolFilter();
			filter.IgnorableServerCertificateErrors.Add(ChainValidationResult.Expired);
			filter.IgnorableServerCertificateErrors.Add(ChainValidationResult.Untrusted);
			filter.IgnorableServerCertificateErrors.Add(ChainValidationResult.InvalidName);
			*/
			HttpClient client = new HttpClient() {
				Timeout = new TimeSpan(0,0,0,60)
			};
			
			UriBuilder serverUri = new UriBuilder(Signer.Properties.Settings.Default.getFileUri) {
				Query = $"oper=getfile&{startupUri.PathAndQuery}"
			};

			return await client.GetAsync(serverUri.Uri);
			//return await client.GetAsync(Signer.Properties.Settings.Default.getFileUri);

			//HttpWebRequest Request = (HttpWebRequest)WebRequest.Create(Signer.Properties.Settings.Default.getFileUri);
			//HttpWebResponse r = (HttpWebResponse)await Request.GetResponseAsync();

			//return new HttpResponseMessage();
		}

		public void InitSession(string sessionDataString) {
			_s = new SigningSession(sessionDataString);
			//set viewModel fields
			OriginalXmlDataToSign = _s.DataToSign;
			HumanRadableDataToSign = _s.HumanReadableHtml;
		}
	}
}
