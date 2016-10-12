using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
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
using Microsoft.Win32;
using SevenZip;
using UniSign.CoreModules;
using UniSign.DataModel;
using utility;

namespace UniSign.ViewModel {
	class MainViewModel:INotifyPropertyChanged {

		public event PropertyChangedEventHandler PropertyChanged;
		private void NotifyPropertyChanged([CallerMemberName] string propertyName = "") {
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
		}

		#region [P & F]
		public const string SignedFilesFolder = "Signed_files";
		public static string ProgramFolder = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
		public static string ProgramVersion {
			get {
				Version ver = Assembly.GetExecutingAssembly().GetName().Version;
				return $"{ver.Major}.{ver.Minor}";
			}
		}
		public SigningSession Session;
		private string _humanRadableDataToSign;
		private string _serverHtmlMessage;
		private string _originalXmlDataToSign;
		private bool _messageIsError;
		private ObservableCollection<X509Certificate2> _certificates;
		private bool _configIsGo;
		private bool _publicConfigIsGo;
		private XDocument _publicConfig;
		private StoreLocation _certificateStore;
		private int _windowHeight;
		private int _windowWidth;
		private int _windowLeft;
		private int _windowTop;
		private int _certificateItem;
		private bool _sessionIsGo;

		private string _interopCertificateThumbprint;
		private StoreLocation _interopCertificateStoreLocation;

		//from binary config
		private X509Certificate2 _ourCertificate;
		private Uri _serverUri;
		private string _serverHttpsCertificateThumbprint;
		private string _serverSignatureCertificateThumbprint;

		private bool _isCertificateRejected;
		public bool IsCertificateRejected {
			get { return _isCertificateRejected; }
			set { _isCertificateRejected = value; }
		}
		//===============================================
		
		#region [FOR DATA BINDING]

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
		public StoreLocation CertificateStore {
			get { return _certificateStore; }
			set {
				_certificateStore = value;
				NotifyPropertyChanged();
			}
		}
		public int WindowHeight {
			get { return _windowHeight; }
			set {
				_windowHeight = value;
				NotifyPropertyChanged();
			}
		}
		public int WindowWidth {
			get { return _windowWidth; }
			set {
				_windowWidth = value;
				NotifyPropertyChanged();
			}
		}
		public int WindowLeft {
			get { return _windowLeft; }
			set {
				_windowLeft = value;
				NotifyPropertyChanged();
			}
		}
		public int WindowTop {
			get { return _windowTop; }
			set {
				_windowTop = value;
				NotifyPropertyChanged();
			}
		}
		public int CertificateItem {
			get { return _certificateItem; }
			set {
				_certificateItem = value;
				NotifyPropertyChanged();
			}
		}
		public bool SessionIsGo {
			get { return _sessionIsGo; }
			set {
				_sessionIsGo = value;
				NotifyPropertyChanged();
			}
		}

		#endregion

		#endregion

		public MainViewModel() {
			LoadConfig(); // this function has LOTS of side effects!
			Certificates = new ObservableCollection<X509Certificate2>();
			LoadCertificatesFromStore();

			if(ConfigIsGo) {
				//setup our makeshift certificate check procedure
				System.Net.ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 |
																SecurityProtocolType.Tls;

				System.Net.ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => {
					X509Certificate2 c = (X509Certificate2)cert;
					_isCertificateRejected = c.Thumbprint.ToLower() != _serverHttpsCertificateThumbprint.ToLower();
					return !_isCertificateRejected;
				};
			}
		}

		#region [SET / CLEAR / EDIT SERVER (ERROR) MESSAGE]
		public void SetErrorMessage(string message) {
			MessageIsError = true;
			ConfigIsGo = false;
			ServerHtmlMessage = $"<b>Ошибка:</b><br>{message}";
		}

		public void ClearError(string message = "OK") {
			MessageIsError = false;
			ServerHtmlMessage = $"<b>{message}</b>";
		}

		public void PrependMessage(string messageToPrepend) {
			ServerHtmlMessage = string.Concat(messageToPrepend,"<br><br>",ServerHtmlMessage);
		}

		public void AppendMessage(string messageToAppend) {
			ServerHtmlMessage = string.Concat(ServerHtmlMessage, "<br><br>", messageToAppend);
		}
		#endregion

		#region [SET CONFIG & CERT]

		private void _setPathToConfig(string element, string path) {
			if(File.Exists(path)) {
				string nearExe = Path.Combine(ProgramFolder, Path.GetFileName(path));
				File.Copy(path,nearExe,true);

				_publicConfig.Root.Element(element).Value = nearExe;
			}
			saveChangesToConfig();
		}

		public void SetConfigField(string fieldname, string value) {
			if (!string.IsNullOrEmpty(fieldname) && !string.IsNullOrEmpty(value)) {
				if (_publicConfig.Root.Elements(fieldname).Any()) {
					_publicConfig.Root.Element(fieldname).Value = value;
				} else {
					throw new Exception("Открытый конфигурационный файл поврежден!");
				}
			} else {
				throw new ArgumentNullException($"Fieldname or value content is null or empty");
			}
		}

		private void saveChangesToConfig() {
			_publicConfig.Save(Path.Combine(ProgramFolder,UniSign.Properties.Settings.Default.publicCfgPath));
		}

		public void RewriteConfig() {
			SetConfigField("CertificateStore", CertificateStore.ToString());
			SetConfigField("CertificateItem", CertificateItem.ToString());
			SetConfigField("WindowHeight", WindowHeight.ToString());
			SetConfigField("WindowWidth", WindowWidth.ToString());
			SetConfigField("WindowLeft", WindowLeft.ToString());
			SetConfigField("WindowTop", WindowTop.ToString());
			saveChangesToConfig();
		}

		public void SetPrivateConfig(string fname) {
			_setPathToConfig("CfgBinPath", fname);
			LoadConfig();
		}

		public void SetCertificate(string fname) {
			_setPathToConfig("CertificateFilePath", fname);
			LoadConfig();
		}

		public bool SelectInteropCertificate() {
			X509Certificate2 selectedCert = new X509Certificate2();
			StoreLocation certificateStore = StoreLocation.CurrentUser;
			if ((selectedCert = SignatureProcessor.SelectCertificateUI(StoreLocation.CurrentUser)) == null) {
				certificateStore = StoreLocation.LocalMachine;
				selectedCert = SignatureProcessor.SelectCertificateUI(StoreLocation.LocalMachine);
			}
			/*
			selectedCert = SignatureProcessor.SelectCertificateUI(StoreLocation.CurrentUser) ??
											SignatureProcessor.SelectCertificateUI(StoreLocation.LocalMachine);
			*/
			if (selectedCert != null) {
				SetConfigField("InteropCertificateThumbprint", selectedCert.Thumbprint);
				SetConfigField("InteropCertificateStore", certificateStore.ToString());
				saveChangesToConfig();
				//LoadConfig();
				return true;
			}
			return false;
		}

		#endregion

		#region [LOAD && CHECK PRIVATE CONFIG]
		public void LoadConfig() {
			try {
				_publicConfig = XDocument.Load(Path.Combine(ProgramFolder,UniSign.Properties.Settings.Default.publicCfgPath));
				PublicConfigIsGo = true;
				ConfigIsGo = checkConfig(_publicConfig);
			} catch (Exception e) {
				ConfigIsGo = false;
				PublicConfigIsGo = false;
				AppendMessage("Основной конфигурационный файл не найден или поврежден!");
				MessageBox.Show(
					$"Основной конфигурационный файл не найден или поврежден! Обратитесь к разработчику.\n\n{e.Message}",
					"Ошибка загрузки начальной конфигурации.", MessageBoxButton.OK, MessageBoxImage.Error);
			} 
		}

		private bool checkConfig(XDocument cfg) {
			string binConfigPath = cfg.Root?.Element("CfgBinPath")?.Value;
			string certFilePath = cfg.Root?.Element("CertificateFilePath")?.Value;

			StoreLocation storeLocation;
			StoreLocation.TryParse(cfg.Root?.Element("CertificateStore")?.Value, true, out storeLocation);
			if(storeLocation != 0) {
				CertificateStore = storeLocation;
			} else {
				CertificateStore = StoreLocation.CurrentUser;
				SetConfigField("CertificateStore", CertificateStore.ToString());
			}

			#region [set window position and size]

			string lastHeightStr = cfg.Root?.Element("WindowHeight")?.Value;
			string lastWidthStr = cfg.Root?.Element("WindowWidth")?.Value;
			string lastLeftStr = cfg.Root?.Element("WindowLeft")?.Value;
			string lastTopStr = cfg.Root?.Element("WindowTop")?.Value;

			if(!string.IsNullOrEmpty(lastHeightStr)) {
				WindowHeight = Int32.Parse(lastHeightStr);
			} else {
				WindowHeight = 600;
				SetConfigField("WindowHeight", WindowHeight.ToString());
			}

			if(!string.IsNullOrEmpty(lastWidthStr)) {
				WindowWidth = Int32.Parse(lastWidthStr);
			} else {
				WindowWidth = 590;
				SetConfigField("WindowWidth", WindowWidth.ToString());
			}

			if(!string.IsNullOrEmpty(lastLeftStr)) {
				WindowLeft = Int32.Parse(lastLeftStr);
			} else {
				WindowLeft = 100;
				SetConfigField("WindowLeft", WindowLeft.ToString());
			}

			if(!string.IsNullOrEmpty(lastTopStr)) {
				WindowTop = Int32.Parse(lastTopStr);
			} else {
				WindowTop = 20;
				SetConfigField("WindowTop", WindowTop.ToString());
			}
			#endregion

			string lastCertificateStr = cfg.Root?.Element("CertificateItem")?.Value;
			if(!string.IsNullOrEmpty(lastCertificateStr)) {
				CertificateItem = Int32.Parse(lastCertificateStr);
			} else {
				CertificateItem = 0;
				SetConfigField("CertificateItem", CertificateItem.ToString());
			}

			string interopCertificateThumb = cfg.Root?.Element("InteropCertificateThumbprint")?.Value;
			if (string.IsNullOrEmpty(interopCertificateThumb)) {
				MessageBox.Show(
					"Не указан сертификат подписи для взаимодействия.\nУкажите сертификат подписи, используя соответствующий пункт меню программы.",
					"Ошибка загрузки начальной конфигурации.", MessageBoxButton.OK, MessageBoxImage.Error);
				SetErrorMessage("Не указан сертификат подписи для взаимодействия");
				bool certSelected = SelectInteropCertificate();
				if (!certSelected) {
					return false;
				} else {
					StoreLocation.TryParse(cfg.Root?.Element("InteropCertificateStore")?.Value, true, out _interopCertificateStoreLocation);
				}
			} else {
				_interopCertificateThumbprint = interopCertificateThumb;
				StoreLocation.TryParse(cfg.Root?.Element("InteropCertificateStore")?.Value, true, out _interopCertificateStoreLocation);
			}

			saveChangesToConfig();

			//signed (and siphered) binary config
			if(string.IsNullOrEmpty(binConfigPath)) {
				MessageBox.Show("Личный конфигурационный файл не найден.\nСкачайте новый личный конфигурационный файл с корпоративного портала.",
								"Ошибка загрузки начальной конфигурации.", MessageBoxButton.OK, MessageBoxImage.Error);
				SetErrorMessage("Личный конфигурационный файл не найден");
				
				return false;
			} else {
				//means htere is a config
				//check it's signature, but first load our certificate
				if(string.IsNullOrEmpty(certFilePath)) {
					MessageBox.Show("Файл сертификата сервера не найден.\nСкачайте файл сертификата сервера с корпоративного портала.",
								"Ошибка загрузки начальной конфигурации.", MessageBoxButton.OK, MessageBoxImage.Error);
					SetErrorMessage("Файл сертификата сервера не найден");
					return false;
				} else {
					//means certificate && config present
					//check cert expiration date
					X509Certificate2 cert = new X509Certificate2();
					try {
						cert.Import(certFilePath);
						if (cert.NotAfter > DateTime.Now) {
							//cert ok
							//check config signature
							string configContents = Util.DecryptConfig(binConfigPath,ProgramFolder);
							if (string.IsNullOrEmpty(configContents)) {
								MessageBox.Show("Личный конфигурационный файл поврежден.\nСкачайте новый личный конфигурационный файл с корпоративного портала.",
									"Ошибка загрузки начальной конфигурации.", MessageBoxButton.OK, MessageBoxImage.Error);
								SetErrorMessage("Личный конфигурационный файл поврежден");
								return false;
							}
							XmlDocument xdocConfig = new XmlDocument();     // this stuff is for

							try {
								xdocConfig.LoadXml(configContents); // check signature further
							} catch (Exception e) {
								MessageBox.Show(
									$"Личный конфигурационный файл поврежден.\nСкачайте новый личный конфигурационный файл с корпоративного портала.\n\n{e.Message}",
									"Ошибка загрузки начальной конфигурации.", MessageBoxButton.OK, MessageBoxImage.Error);
								SetErrorMessage("Личный конфигурационный файл поврежден");
								return false;
							}

							XDocument privateConfig = XDocument.Parse(configContents);
							try {
								#if !DEBUG
								if (SignatureProcessor.VerifySignature(SignatureProcessor.SignatureType.Smev3SidebysideDetached, xdocConfig, cert)) {
								#endif
								#if DEBUG
								if(SignatureProcessor.VerifySignature(SignatureProcessor.SignatureType.Smev3SidebysideDetached, xdocConfig)) {
								#endif
									//config signature OK - loading contents
									if (privateConfig.Root?.Attribute("version").Value == ProgramVersion) {
										//means config version corresponds to a program version

										_ourCertificate = cert;
										_serverUri = new Uri(privateConfig.Root?.Element("Server").Element("GetFileUri")?.Value ?? "");
										_serverSignatureCertificateThumbprint = privateConfig.Root?.Element("Server").Element("CertificateThumbprint")?.Value ?? "";
										_serverHttpsCertificateThumbprint =
											privateConfig.Root?.Element("Server").Element("SSLCertificateThumbprint")?.Value ?? "";
										ClearError("Конфигурационный файл успешно загружен");
									} else {
										//means version in config is not right one
										MessageBox.Show(
											$"Текущая версия программы <{ProgramVersion}> устарела.\nСкачайте новую версию с корпоративного портала.",
											"Программа устарела.", MessageBoxButton.OK, MessageBoxImage.Error);
										SetErrorMessage($"Установленная версия программы <{ProgramVersion}> устарела");
										return false;
									}
								} else {
									//signature incorrect
									Debug.WriteLine("Invalid Signature");
									MessageBox.Show(
										"Личный конфигурационный файл поврежден.\nСкачайте новый личный конфигурационный файл с корпоративного портала.",
										"Ошибка загрузки начальной конфигурации.", MessageBoxButton.OK, MessageBoxImage.Error);
									SetErrorMessage("Личный конфигурационный файл поврежден");
									return false;
								}
							} catch (Exception e) {
								MessageBox.Show(
										$"Личный конфигурационный файл поврежден.\nСкачайте новый личный конфигурационный файл с корпоративного портала.\n\n{e.Message}",
										"Ошибка загрузки начальной конфигурации.", MessageBoxButton.OK, MessageBoxImage.Error);
								SetErrorMessage("Личный конфигурационный файл поврежден");
								return false;
							}

						} else {
							//cert expired
							MessageBox.Show("Файл сертификата сервера просрочен.\nСкачайте новый файл сертификата сервера с корпоративного портала.",
								"Ошибка загрузки начальной конфигурации.", MessageBoxButton.OK, MessageBoxImage.Error);
							SetErrorMessage("Файл сертификата сервера просрочен");
							return false;
						}
					} catch (Exception e) {
						//certificate corrupted
						MessageBox.Show($"Ошибка загрузки сертификата сервера. Файл поврежден.\nСкачайте новый файл сертификата сервера с корпоративного портала.\n\n{e.Message}",
								"Ошибка загрузки начальной конфигурации.", MessageBoxButton.OK, MessageBoxImage.Error);
						SetErrorMessage("Ошибка загрузки сертификата сервера");
						return false;
					}
				}
			}
			return true;
		}
		#endregion
		
		#region [SIGNING SESSION INIT]
		public async Task<HttpResponseMessage> GetServerSessionData(string startupArg) {

			//startupArg is like : unisign:session_id=12345-45-54545-12
			Uri startupUri = new Uri(startupArg);
			
			HttpClient client = new HttpClient() {
				Timeout = new TimeSpan(0,0,0,60) // 60 seconds
			};
			
			UriBuilder serverUri = new UriBuilder(_serverUri) {
				Query = $"oper=getfile&{startupUri.PathAndQuery}"
			};
			string sessionId = startupArg.Split('=')?[1];

			HttpContent content = new StringContent(SignedRequestBuilder.GetSessionRequest(sessionId,_interopCertificateThumbprint,_interopCertificateStoreLocation));
			content.Headers.ContentType = new MediaTypeHeaderValue("text/xml");
			
			return await client.PostAsync(serverUri.Uri,content);
		}

		public bool InitSession(string sessionDataString, string startupArg) {
			Session = new SigningSession(sessionDataString) {
				StartupArg = startupArg
			};
			
			//set viewModel fields
			OriginalXmlDataToSign = Session.DataToSign;
			HumanRadableDataToSign = Session.HumanReadableHtml;

			ConfigIsGo = Session.Success; //because this property is bound onto Sign button

			return Session.Success; //Session.Success == false when program version is not equal "vesrion" attribute value or server signature is invalid
		}
		#endregion

		#region [SIGNING PORCESS]
		public void LoadCertificatesFromStore() {
			int lastSelectedCertItem = CertificateItem;
			List<X509Certificate2> certs = SignatureProcessor.GetAllCertificatesFromStore(CertificateStore);
			Certificates.Clear();
			foreach (X509Certificate2 c in certs.Where((cert)=>cert.HasPrivateKey)) {
				Certificates.Add(c);
			}
			CertificateItem = lastSelectedCertItem;
		}

		public string SignWithSelectedCert(X509Certificate2 cert) {
			//use SignInfo from Session

			SignatureInfo si = Session.SignInfo;
			XmlDocument docToSign = new XmlDocument();
			docToSign.LoadXml(Session.DataToSign);
			string signedData = string.Empty;
			try {
				signedData = SignatureProcessor.Sign(Session.SignInfo.SigType, cert, docToSign, false, Session.SignInfo.NodeId);
			} catch (Exception e) {
				SetErrorMessage(e.Message);
			}

			return signedData;
		}
		#endregion

		#region [SEND DATA BACK TO SRV]
		public async Task<HttpResponseMessage> SendDataBackToServer(string signedData) {
			SaveDataToDisk(signedData);
			Uri startupUri = new Uri(Session.StartupArg);

			HttpClient client = new HttpClient() {
				Timeout = new TimeSpan(0, 0, 0, 60)
			};

			UriBuilder serverUri = new UriBuilder(_serverUri) {
				Query = $"oper=signed&{startupUri.PathAndQuery}"
			};
			
			HttpContent content = new StringContent(SignedRequestBuilder.GetSignedDataRequest(Session.SessionId, signedData, _interopCertificateThumbprint,_interopCertificateStoreLocation));
			content.Headers.ContentType = new MediaTypeHeaderValue("text/xml");

			return await client.PostAsync(serverUri.Uri,content);
		}
		#endregion

		#region [SAVE SIGNED DATA]
		private void SaveDataToDisk(string data) {
			DateTime now = DateTime.Now;
			string savePath = Path.Combine(ProgramFolder,SignedFilesFolder, now.ToString("yyyy"), now.ToString("MM"), now.ToString("dd"));
			Directory.CreateDirectory(savePath);
			File.WriteAllText(Path.Combine(savePath,$"{Session.SessionId}.xml"),data);
		}
		#endregion

		#region [UTILITY]
		public static bool? IsProtocolRegistered() {
			bool? ret = null;
			RegistryKey classesRoot = null;
			try {
				classesRoot = RegistryKey.OpenBaseKey(RegistryHive.ClassesRoot, RegistryView.Default);
				ret = classesRoot.OpenSubKey("unisign") != null;
			} catch(Exception e) {
				//means no rights to open the registry key
				ret = null; // actualluy no need to do this))
			}
			return ret;
		}
		#endregion
	}
}
