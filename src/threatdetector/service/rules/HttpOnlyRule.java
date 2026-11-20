 package threatdetector.service.rules;

import java.util.Locale;

import threatdetector.model.InputType;
import threatdetector.model.RuleHit;
import threatdetector.model.ScanItem;
import threatdetector.service.Rule;

public class HttpOnlyRule implements Rule {
	@Override
	public boolean appliesTo(InputType type) {
		return type == InputType.URL;
	}
	@Override
	public  RuleHit evaluate(ScanItem item) {
		String content = item.getContent().trim();
		if(content.toLowerCase(Locale.ROOT).startsWith("http://")) {
			return new RuleHit(20 , "URL uses HTTP instead of https");
		}
		return RuleHit.none();
	}

}
