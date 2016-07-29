using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
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

using Signer.ViewModel;
using Signer.DataModel;

namespace Signer {
	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow : Window {
		private MainViewModel _viewModel = new MainViewModel();
		
		public MainWindow() {
			InitializeComponent();
		}
		
		private async void MainWindow_OnLoaded(object sender,RoutedEventArgs e) {
			MainGrid.DataContext = _viewModel;

			string[] args = Environment.GetCommandLineArgs();
			
			HttpResponseMessage serverSessionData = await _viewModel.GetServerSessionData(args[1]);

			if (serverSessionData.IsSuccessStatusCode) {
				_viewModel.MessageIsError = false;
				_viewModel.InitSession(await serverSessionData.Content.ReadAsStringAsync());
			} else {
				//means server returned not OK or connection timed out
				_viewModel.MessageIsError = true;
				_viewModel.ServerHtmlMessage = await serverSessionData.Content.ReadAsStringAsync();
			}
		}
	}
}
