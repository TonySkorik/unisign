using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows;

namespace UniSign {
	/// <summary>
	/// Interaction logic for App.xaml
	/// </summary>
	public partial class App : Application {
		protected override void OnStartup(StartupEventArgs e) {
			//AppDomain.CurrentDomain.AssemblyResolve += ResolveAssembly;
			base.OnStartup(e);
		}
		/*
		static Assembly ResolveAssembly(object sender, ResolveEventArgs args) {
			Assembly thisAssembly = Assembly.GetExecutingAssembly();
			var name = args.Name.Substring(0, args.Name.IndexOf(',')) + ".dll";
			var resourceName = thisAssembly.GetManifestResourceNames().First(s => s.EndsWith(name));

			using(Stream stream = thisAssembly.GetManifestResourceStream(resourceName)) {
				byte[] block = new byte[stream.Length];
				stream.Read(block, 0, block.Length);
				return Assembly.Load(block);
			}
		}*/
	}
}
