using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using UniSign.CoreModules;

namespace UniSign.DataModel {
	struct SignatureInfo {
		public SignatureProcessor.SignatureType SigType;
		//public int SmevMode;
		public string NodeId;

		public SignatureInfo(XElement node) {

			if (!SignatureProcessor.SignatureType.TryParse(node.Descendants("Type").First().Value, true, out SigType)) {
				SigType = SignatureProcessor.SignatureType.Smev2SidebysideDetached;
			}
			/*
			SmevMode = Int32.Parse(node.Descendants("SmevMode").DefaultIfEmpty(new XElement("SmevMode", 2)).First().Value);
			*/
			NodeId = node.Descendants("NodeId").DefaultIfEmpty(new XElement("NodeId",string.Empty)).First().Value;
			
		}

		/*
		<SignatureInfo>
			<Type>detached|side-by-side|enveloped</Type>
			<SmevMode*>2|3</SmevMode>
			<NodeId*>
				<!-- Textual node ID or blank or abscent if signature must be placed inside (or side-by-side with) the root -->
			</NodeId>
		</SignatureInfo>
		*/
	}
}
