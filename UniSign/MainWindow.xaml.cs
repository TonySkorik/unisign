using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Timers;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Xsl;
using Microsoft.Win32;
using UniSign.DataModel;
using UniSign.ViewModel;

namespace UniSign {
	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow : Window {
		private MainViewModel _viewModel;

		private const int closeAfter = 5000; //5 seconds
		private readonly Timer _tmrClose = new Timer() {
			Interval = closeAfter
		};

		public MainWindow() {
			_viewModel = new MainViewModel();
			InitializeComponent();
			MainUI.DataContext = _viewModel;
			MainUI.Title = $"{MainUI.Title} v{MainViewModel.ProgramVersion}";
			_tmrClose.Elapsed += (o, args) => {
				Dispatcher.Invoke(Close);
			};
		}
		
		private async void MainWindow_OnLoaded(object sender,RoutedEventArgs e) {
			SignButton.IsEnabled = false;
			bool? isProtocolRegistered = MainViewModel.IsProtocolRegistered();
			if (!isProtocolRegistered.HasValue) {
				//means no rights to pen registry
				MessageBox.Show(
						"Невозможно проверить регистрацию протокола удаленного подписания в системе.\nВозможна утрата работоспособности программы.\nОбратитесь к разработчику или запустите программу от имени администратора.",
						"Невозможно проверить регистрацию протокола", MessageBoxButton.OK, MessageBoxImage.Exclamation);
			} else {
				//means registry opened
				if (!isProtocolRegistered.Value) {
					//means protocol unregistered
					MessageBox.Show(
						"Протокол удаленного подписания не зарегистрирован в системе.\nВызов программы по ссылке невозможен. Обратитесь к разработчику.",
						"Протокол не зарегистрирован", MessageBoxButton.OK, MessageBoxImage.Exclamation);
				}
			}
			
			if (!_viewModel.ConfigIsGo) {
				return;
			}

			string[] args = Environment.GetCommandLineArgs();
			if (args.Length == 2) {
				//List<X509Certificate2> certs = CertificatesInSelectedStore.Items.Cast<X509Certificate2>().ToList();
				HttpResponseMessage serverSessionData = null;
				try {
					serverSessionData = await _viewModel.GetServerSessionData(args[1]);
				} catch {
					_viewModel.SetErrorMessage(_viewModel.IsCertificateRejected
						? "SSL сертификат соединения недействиетлен."
						: "Ошибка соединения с сервером.");
					return;
				}

				if (serverSessionData.IsSuccessStatusCode) {
					_viewModel.MessageIsError = false;
					try {
						if (!_viewModel.InitSession(await serverSessionData.Content.ReadAsStringAsync(), args[1])) {
							//means session init ended with error
							if (_viewModel.Session.VersionIsCorrect) {
								if (!_viewModel.Session.SignatureIsCorrect) {
									_viewModel.SetErrorMessage($"Цифровая подпись сервера невалидна или отсутствует!");
									return;
								}
							} else {
								_viewModel.SetErrorMessage($"Версия программы (v{MainViewModel.ProgramVersion}) устарела, требуется новыя версия программы - v{_viewModel.Session.RequestedProgramVersion}");
								return;
							}
						}
						SignButton.IsEnabled = true;
					} catch (Exception ex) {
						if (ex.Message.Contains("NO_SIGNATURES_FOUND")) {
							_viewModel.SetErrorMessage("Цифровая подпись сервера не найдена");
							return;
						}
						
						_viewModel.SetErrorMessage($"Ошибка проверки цифровой подписи.\n{ex.Message}");
						return;
					}
				} else {
					//means server returned not OK or connection timed out
					_viewModel.SetErrorMessage(await serverSessionData.Content.ReadAsStringAsync());
					return;
				}
			}
			//make button active
		}
		private void MainWindow_OnClosing(object sender, CancelEventArgs e) {
			_viewModel.RewriteConfig();
		}

		#region [CERT & SIGN]
		private void CertificateStoreSelect_OnClick(object sender, RoutedEventArgs e) {
			_viewModel.LoadCertificatesFromStore();
		}

		private async void SignButton_OnClick(object sender, RoutedEventArgs e) {
			if (SelectedSignatureCert.SelectedItem == null) {
				MessageBox.Show(
					"Пожалуйста, выберите сертификат подписи!",
					"Не выбран сертификат подписи",
					MessageBoxButton.OK,
					MessageBoxImage.Exclamation
				);
				return;
			}
			if (_viewModel.SessionIsGo) {
				SignButton.IsEnabled = false;
				X509Certificate2 selectedCert = (X509Certificate2) SelectedSignatureCert.SelectedItem;
				#if !DEBUG
				string signedData = _viewModel.SignWithSelectedCert(selectedCert);
				if (string.IsNullOrEmpty(signedData)) {
					return;
				}
				#endif

				#if DEBUG
				string signedData = _viewModel.OriginalXmlDataToSign;
				#endif
				try {
					HttpResponseMessage serverResponse = await _viewModel.SendDataBackToServer(signedData);
					if(!serverResponse.IsSuccessStatusCode) {
						_viewModel.MessageIsError = true;
					}

					_viewModel.ServerHtmlMessage = await serverResponse.Content.ReadAsStringAsync();

					if(!_viewModel.MessageIsError) {
						MainUI.Title = $"Автоматическое закрытие через {closeAfter / 1000} секунд";
						_tmrClose.Start();
					}
				} catch (Exception ex) {
					_viewModel.SetErrorMessage(ex.Message);
				}
			} else {
				//means session is not success
				_viewModel.SetErrorMessage("Сеанс подписания не инициализирован.");
				/*
				MessageBox.Show(
					"Пожалуйста, выберите сертификат подписи!",
					"Не выбран сертификат подписи",
					MessageBoxButton.OK,
					MessageBoxImage.Exclamation
				);
				*/
			}
		}
		#endregion

		#region [MAIN MENU]
		private void SelectInteropCertificate_OnClick(object sender, RoutedEventArgs e) {
			_viewModel.SelectInteropCertificate();
			_viewModel.LoadConfig(); // because SelectInteropCertificate() doesn't call LoadConfig upon completion
		}
		private void LoadPrivateConfig_OnClick(object sender, RoutedEventArgs e) {

			_viewModel.LoadPrivateConfig();
			/*
			OpenFileDialog dlgOpenFile = new OpenFileDialog() {
				CheckFileExists = true,
				Multiselect = false,
				CheckPathExists = true,
				Filter = "Файлы конфигурации(*.CBIN;*.cbin)|*.CBIN;*.cbin"
			};
			dlgOpenFile.ShowDialog();
			_viewModel.SetPrivateConfig(dlgOpenFile.FileName);
			//_viewModel.LoadConfig();
			*/
		}

		private void LoadCertificate_OnClick(object sender, RoutedEventArgs e) {

			_viewModel.LoadServerCertificate();
			/*
			OpenFileDialog dlgOpenFile = new OpenFileDialog() {
				CheckFileExists = true,
				Multiselect = false,
				CheckPathExists = true,
				Filter = "Файлы сертификатов(*.CER;*.cer)|*.CER;*.cer"
			};
			dlgOpenFile.ShowDialog();
			_viewModel.SetCertificate(dlgOpenFile.FileName);
			//_viewModel.LoadConfig();
			*/
		}

		private void ReloadConfig_OnClick(object sender, RoutedEventArgs e) {
			_viewModel.LoadConfig();
		}

		private void ProgramExit_OnClick(object sender, RoutedEventArgs e) {
			Close();
		}
		#endregion

	}
}
