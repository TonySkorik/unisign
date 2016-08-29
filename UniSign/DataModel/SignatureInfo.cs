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
		public string NodeId;

		public SignatureInfo(XElement node) {
			//SignatureType
			SignatureProcessor.SignatureType stype;
			if (
				!SignatureProcessor.SignatureType.TryParse(
					node.Descendants("Type").First().Value.Replace(".", "").Replace("_", ""), true, out stype)) {
				SigType = SignatureProcessor.SignatureType.Smev2SidebysideDetached;
			} else {
				SigType = stype;
			}

			//NodeId = node.Descendants("NodeId").DefaultIfEmpty(new XElement("NodeId",string.Empty)).First().Value;
			NodeId = node.Descendants("NodeId").DefaultIfEmpty(null).First().Value;
		}

		/*
		<SignatureInfo>
			<Type>smev2_base.detached|smev2_charge.enveloped|smev2_sidebyside.detached|smev3_base.detached|smev3_sidebyside.detached|sig.detached</Type>
			<NodeId*>
				<!-- Textual node ID or blank or abscent if signature must be placed inside (or side-by-side with) the root -->
			</NodeId>
		</SignatureInfo>
		*/
	}
}
