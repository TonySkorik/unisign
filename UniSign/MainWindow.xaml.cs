using System;
using System.Collections.Generic;
using System.ComponentModel;
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
			InitializeComponent();
			_viewModel = new MainViewModel();
			MainUI.Title = $"UniSign v{MainViewModel.ProgramVersion}";

			_tmrClose.Elapsed += (o, args) => {
				Dispatcher.Invoke(Close);
			};
		}
		
		private async void MainWindow_OnLoaded(object sender,RoutedEventArgs e) {
			
			MainUI.DataContext = _viewModel;
			
			if (!_viewModel.ConfigIsGo) {
				return;
			}

			string[] args = Environment.GetCommandLineArgs();
			//List<X509Certificate2> certs = CertificatesInSelectedStore.Items.Cast<X509Certificate2>().ToList();
			
			HttpResponseMessage serverSessionData = await _viewModel.GetServerSessionData(args[1]);

			if (serverSessionData.IsSuccessStatusCode) {
				_viewModel.MessageIsError = false;
				if (!_viewModel.InitSession(await serverSessionData.Content.ReadAsStringAsync(), args[1])) {
					//means session init ended with error
					_viewModel.SetErrorMessage($"Версия программы {MainViewModel.ProgramVersion} устарела");
				}
			} else {
				//means server returned not OK or connection timed out
				_viewModel.MessageIsError = true;
				_viewModel.ServerHtmlMessage = await serverSessionData.Content.ReadAsStringAsync();
			}
		}
		private void MainWindow_OnClosing(object sender, CancelEventArgs e) {
			_viewModel.RewriteConfig();
		}
		
		#region [CERT & SIGN]
		private void CertificateStoreSelect_OnClick(object sender, RoutedEventArgs e) {
			_viewModel.LoadCertificatesFromStore();
		}

		private async void SignButton_OnClick(object sender, RoutedEventArgs e) {
			if (SelectedSignatureCert.SelectedItem != null) {
				X509Certificate2 selectedCert = (X509Certificate2) SelectedSignatureCert.SelectedItem;
				HttpResponseMessage serverResponse = await _viewModel.SendDataBackToServer(_viewModel.SignWithSelectedCert(selectedCert));
				if (!serverResponse.IsSuccessStatusCode) {
					_viewModel.MessageIsError = true;
				}

				_viewModel.ServerHtmlMessage = await serverResponse.Content.ReadAsStringAsync();

				if (!_viewModel.MessageIsError) {
					MainUI.Title = $"Автоматическое закрытие через {closeAfter/1000} секунд";
					_tmrClose.Start();
				}
			} else {
				//means certificate not selected
				MessageBox.Show(
					"Пожалуйста, выберите сертификат подписи!",
					"Не выбран сертификат подписи",
					MessageBoxButton.OK,
					MessageBoxImage.Exclamation
				);
			}
		}
		#endregion

		#region [MAIN MENU]
		private void SelectInteropCertificate_OnClick(object sender, RoutedEventArgs e) {
			_viewModel.SelectInteropCertificate();
			_viewModel.LoadConfig(); // because SelectInteropCertificate() doesn't call LoadConfig upon completion
		}
		private void LoadPrivateConfig_OnClick(object sender, RoutedEventArgs e) {
			OpenFileDialog dlgOpenFile = new OpenFileDialog() {
				CheckFileExists = true,
				Multiselect = false,
				CheckPathExists = true,
				Filter = "Файлы конфигурации(*.CBIN;*.cbin)|*.CBIN;*.cbin"
			};
			dlgOpenFile.ShowDialog();
			_viewModel.SetPrivateConfig(dlgOpenFile.FileName);
			//_viewModel.LoadConfig();
		}

		private void LoadCertificate_OnClick(object sender, RoutedEventArgs e) {
			OpenFileDialog dlgOpenFile = new OpenFileDialog() {
				CheckFileExists = true,
				Multiselect = false,
				CheckPathExists = true,
				Filter = "Файлы сертификатов(*.CER;*.cer)|*.CER;*.cer"
			};
			dlgOpenFile.ShowDialog();
			_viewModel.SetCertificate(dlgOpenFile.FileName);
			//_viewModel.LoadConfig();
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
