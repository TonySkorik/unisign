using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Web;
using System.Windows;
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
		private bool _configIsGo;
		private bool _publicConfigIsGo;
		private XDocument _publicConfig;

		//from binary config
		private X509Certificate2 _ourCertificate;
		private Uri _serverUri;
		private string _serverHttpsCertificateThumbprint;
		//===============================================

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
		public bool ConfigIsGo {
			get { return _configIsGo; }
			set {
				_configIsGo = value;
				NotifyPropertyChanged();
			}
		}
		public bool PublicConfigIsGo {
			get { return _publicConfigIsGo; }
			set {
				_publicConfigIsGo = value;
				NotifyPropertyChanged();
			}
		}

		#endregion

		public MainViewModel() {
			Certificates = new ObservableCollection<X509Certificate2>();
			LoadCertificatesFromStore(SignatureProcessor.StoreType.CurrentUser);
			
			LoadConfig();

			if(ConfigIsGo) {
				//setup our makeshift certificate check procedure
				System.Net.ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 |
																SecurityProtocolType.Tls;

				System.Net.ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => {
					X509Certificate2 c = (X509Certificate2)cert;
					return c.Thumbprint == _serverHttpsCertificateThumbprint;
				};
			}
		}
		#region [SET CONFIG & CERT]

		private void _setPathToConfig(string element, string path) {
			if(File.Exists(path)) {
				string nearExe = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location),
											Path.GetFileName(path));
				File.Copy(path,nearExe,true);

				_publicConfig.Root.Element(element).Value = nearExe;
			}
			_publicConfig.Save(Signer.Properties.Settings.Default.publicCfgPath);
		}

		public void SetConfig(string fname) {
			_setPathToConfig("CfgBinPath", fname);
			LoadConfig();
		}

		public void SetCertificate(string fname) {
			_setPathToConfig("CertificateFilePath", fname);
			LoadConfig();
		}
		#endregion

		#region [LOAD && CHECK PRIVATE CONFIG]
		public void LoadConfig() {
			try {
				_publicConfig = XDocument.Load(Signer.Properties.Settings.Default.publicCfgPath);
				PublicConfigIsGo = true;
				ConfigIsGo = checkConfig(_publicConfig);
			} catch (Exception e) {
				ConfigIsGo = false;
				MessageBox.Show(
					$"Основной конфигурационный файл не найден или поврежден! Обратитесь к разработчику.\n\n{e.Message}",
					"Ошибка загрузки начальной конфигурации.", MessageBoxButton.OK, MessageBoxImage.Error);
			} finally {
				ConfigIsGo = false;
			}

		}

		private bool checkConfig(XDocument cfg) {
			string binConfigPath = cfg.Root?.Element("CfgBinPath")?.Value;
			string certFilePath = cfg.Root?.Element("CertificateFilePath")?.Value;
			
			//signed (and siphered) binary config
			if(string.IsNullOrEmpty(binConfigPath)) {
				MessageBox.Show("Личный конфигурационный файл не найден.\nСкачайте новый личный конфигурационный файл с корпоративного портала.",
								"Ошибка загрузки начальной конфигурации.", MessageBoxButton.OK, MessageBoxImage.Error);
				return false;
			} else {
				//means htere is a config
				//check it's signature, but first load our certificate
				if(string.IsNullOrEmpty(certFilePath)) {
					MessageBox.Show("Файл сертификата не найден.\nСкачайте новый файл сертификата с корпоративного портала.",
								"Ошибка загрузки начальной конфигурации.", MessageBoxButton.OK, MessageBoxImage.Error);
					return false;
				} else {
					//means certificate && config present
					//check config expiration date
					X509Certificate2 cert = new X509Certificate2();
					try {
						cert.Import(certFilePath);
						if (cert.NotAfter > DateTime.Now) {
							//cert ok
							//check config signature

							//TODO: maybe decompile / decrypt the config  ??
							string configContents = decryptConfig(binConfigPath);

							XmlDocument xdocConfig = new XmlDocument();
							xdocConfig.LoadXml(configContents);
							if (SignatureProcessor.VerifySignature(xdocConfig, true, cert)) {
								//config signature OK - loading contents
								XDocument privateConfig = XDocument.Parse(configContents);

								_ourCertificate = cert;
								_serverUri = new Uri(privateConfig.Root?.Element("GetFileUri")?.Value ?? "");
								_serverHttpsCertificateThumbprint = privateConfig.Root?.Element("ServerCertificateThumbprint")?.Value ?? "";
							} else {
								//signature incorrect
								MessageBox.Show("Личный конфигурационный файл поврежден.\nСкачайте новый личный конфигурационный файл с корпоративного портала.",
									"Ошибка загрузки начальной конфигурации.", MessageBoxButton.OK, MessageBoxImage.Error);
								return false;
							}
						} else {
							//cert expired
							MessageBox.Show("Файл сертификата просрочен.\nСкачайте новый файл сертификата с корпоративного портала.",
								"Ошибка загрузки начальной конфигурации.", MessageBoxButton.OK, MessageBoxImage.Error);
							return false;
						}
					} catch (Exception e) {
						//certificate corrupted
						MessageBox.Show($"Ошибка загрузки сертификата. Файл поврежден.\nСкачайте новый файл сертификата с корпоративного портала.\n\n{e.Message}",
								"Ошибка загрузки начальной конфигурации.", MessageBoxButton.OK, MessageBoxImage.Error);
						return false;
					}
				}
			}
			return true;
		}

		private string decryptConfig(string configPath) {
			//TODO: decrypt config
			return File.ReadAllText(configPath);
		}
		#endregion

		#region [SIGNING SESSION START]
		public async Task<HttpResponseMessage> GetServerSessionData(string startupArg) {

			//startupArg is like : unisign:session_id=12345-45-54545-12
			Uri startupUri = new Uri(startupArg);
			
			HttpClient client = new HttpClient() {
				Timeout = new TimeSpan(0,0,0,60)
			};
			
			UriBuilder serverUri = new UriBuilder(_serverUri) {
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
		#endregion

		#region [SIGNING PORCESS]
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
		#endregion

		#region [SEND DATA BACK TO SRV]
		public async Task<HttpResponseMessage> SendDataBackToServer(string signedData) {
			Uri startupUri = new Uri(_s.StartupArg);

			HttpClient client = new HttpClient() {
				Timeout = new TimeSpan(0, 0, 0, 60)
			};

			UriBuilder serverUri = new UriBuilder(_serverUri) {
				Query = $"oper=signed&{startupUri.PathAndQuery}"
			};

			HttpContent content = new StringContent(signedData);
			content.Headers.ContentType = new MediaTypeHeaderValue("text/xml");

			return await client.PostAsync(serverUri.Uri,content);
		}
		#endregion
	}
}
