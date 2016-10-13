using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace UniSign.CoreModules {
	public static class BrowserBehavior {

		public static readonly DependencyProperty HtmlProperty = DependencyProperty.RegisterAttached(
			"Html",
			typeof(string),
			typeof(BrowserBehavior),
			new FrameworkPropertyMetadata(OnHtmlChanged)
		);

		[AttachedPropertyBrowsableForType(typeof(WebBrowser))]
		public static string GetHtml(WebBrowser d) {
			return (string)d.GetValue(HtmlProperty);
		}

		public static void SetHtml(WebBrowser d, string value) {
			d.SetValue(HtmlProperty, value);
		}

		static void OnHtmlChanged(DependencyObject d, DependencyPropertyChangedEventArgs e) {
			WebBrowser wb = d as WebBrowser;
			if (e.NewValue != null) {
				//wb?.NavigateToString(Encoding.GetEncoding("windows-1251").GetString(Encoding.UTF8.GetBytes(e.NewValue as string)));
				StringBuilder sb = new StringBuilder();
				sb.Append(
					@"<!DOCTYPE html ><html><meta http-equiv='Content-Type' content='text/html;charset=UTF-8'><head></head>");
				sb.Append(e.NewValue as string);
				sb.Append(@"</html>");
				
				wb?.NavigateToString(sb.ToString());
			}
		}
	}
}
