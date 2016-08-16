using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using SevenZip;

namespace utility{
	public static class Util {
		private static readonly string decryptionKey = "123";
		public static string DecryptConfig(string configPath) {
			SevenZipBase.SetLibraryPath("7z_32.dll");
			string decrypted = null;
			SevenZipExtractor ex = new SevenZipExtractor(configPath, decryptionKey);

			MemoryStream extracted = new MemoryStream();
			try {
				ex.ExtractFile("private_config.xml", extracted);
			} catch {
				/*MessageBox.Show("Личный конфигурационный файл поврежден.\nСкачайте новый личный конфигурационный файл с корпоративного портала.",
									"Ошибка загрузки начальной конфигурации.", MessageBoxButton.OK, MessageBoxImage.Error);
				SetErrorMessage("Личный конфигурационный файл поврежден");*/
				return null;
			}
			extracted.Position = 0;
			using(StreamReader sr = new StreamReader(extracted)) {
				decrypted = sr.ReadToEnd();
			}
			extracted.Close();
			return decrypted;
		}
	}
}
