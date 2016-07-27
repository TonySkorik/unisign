using System;
using System.Collections.Generic;
using System.Linq;
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

using Signer.ViewModel;
using Signer.Model;

namespace Signer {
	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow : Window {
		private MainViewModel _viewModel = new MainViewModel();

		public MainWindow() {
			InitializeComponent();
		}

		private void MainWindow_OnLoaded(object sender, RoutedEventArgs e) {
			MainGrid.DataContext = _viewModel;

			string[] args = Environment.GetCommandLineArgs();
			if (!_viewModel.ParseUri(args[1])) {
				MessageBox.Show("Failed to load uri!");
			}
		}
	}
}
