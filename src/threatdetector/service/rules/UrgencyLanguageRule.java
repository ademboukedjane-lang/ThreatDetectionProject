package threatdetector.service.rules;

import java.util.Locale;

import threatdetector.model.InputType;
import threatdetector.model.RuleHit;
import threatdetector.model.ScanItem;
import threatdetector.service.Rule;

public class UrgencyLanguageRule implements Rule {
	@Override
	public boolean appliesTo(InputType type) {
		return type == InputType.MESSAGE;
	}
	@Override
	public RuleHit evaluate(ScanItem item) {
		String content = item.getContent().toLowerCase(Locale.ROOT);
		String[] urgentWords =	{"urgent","immediately","urgently", "now","عاجل", "عاجلا", "فورا","فوراً",
				"حالا","حالاً","بسرعة","الآن", "الان"
	           
	        };
		for(String word : urgentWords) {
			if(content.contains(word)) {
				return new RuleHit(20 , "message contains urgencuy language");
			}
		}
		return RuleHit.none();
				}

}
