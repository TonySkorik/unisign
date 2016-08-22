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
		private static readonly string decryptionKey = "jQeusHhYZqfVDiwA78KGmrgM3Eb4PzJx";
		public static string DecryptConfig(string configPath, string programFolder) {
			string libPath = Path.Combine(programFolder, "inc.dll");
			string libPath64 = Path.Combine(programFolder, "inc_64.dll");
			SevenZipBase.SetLibraryPath(libPath);

			string decrypted = null;
			
			SevenZipExtractor ex = new SevenZipExtractor(configPath, decryptionKey);

			MemoryStream extracted = new MemoryStream();
			try {
				ex.ExtractFile("conf.xml", extracted);
			} catch {
				//32bit dll load failed
				try {
					SevenZipBase.SetLibraryPath(libPath64);
					ex.ExtractFile("conf.xml", extracted);
				} catch {
					//64 bit dll load failed!
					return null;
				}
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
