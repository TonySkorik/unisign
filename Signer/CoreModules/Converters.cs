using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Data;

namespace Signer.CoreModules {
	class CertificateToSubjectConverter : IValueConverter {
		public object Convert(object value, Type targetType, object parameter, CultureInfo culture) {
			X509Certificate2 cert = null;
			//cert = (X509Certificate2)value;

			try {
				cert = (X509Certificate2) value;
			} catch {
				//that's for control to not crash upon ObservableCollection.Clear() method
				return Binding.DoNothing;
			}
			
			if (cert == null) return "Сертификат поврежден";
			return cert.Subject;
		}
		public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) {
			throw new NotImplementedException();
		}
	}

	public class EnumToBooleanConverter : IValueConverter {
		public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture) {
			return value.Equals(parameter);
		}

		public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture) {
			return value.Equals(true) ? parameter : Binding.DoNothing;
		}
	}

}
