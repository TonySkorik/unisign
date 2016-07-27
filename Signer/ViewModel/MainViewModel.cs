using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace Signer.ViewModel {
	class MainViewModel:INotifyPropertyChanged {

		public event PropertyChangedEventHandler PropertyChanged;
		private void NotifyPropertyChanged([CallerMemberName] string propertyName = "") {
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
		}

		private Uri _startupUri;
		public Uri StartupUri {
			get { return _startupUri; }
			set {
				_startupUri = value;
				NotifyPropertyChanged();
			}
		}

		public bool ParseUri(string uri) {
			Uri parsedUri;
			if (Uri.TryCreate(uri, UriKind.RelativeOrAbsolute, out parsedUri)) {
				StartupUri = parsedUri;
				return true;
			}
			return false;
		}
	}
}
