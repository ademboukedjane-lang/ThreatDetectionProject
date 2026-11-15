package threatdetector.service;

import java.util.ArrayList;
import java.util.List;

import threatdetector.model.RuleHit;
import threatdetector.model.ScanItem;
import threatdetector.model.ScanResult;
import threatdetector.service.rules.CredentialRequestRule;
import threatdetector.service.rules.HttpOnlyRule;
import threatdetector.service.rules.IpHostRule;
import threatdetector.service.rules.MisleadingSubdomainRule;
import threatdetector.service.rules.UrgencyLanguageRule;

public class RuleBasedAnalyzer implements ThreatAnalyze {
	private final List<Rule> rules;
	public RuleBasedAnalyzer() {
		rules = new ArrayList<>();
		rules.add(new HttpOnlyRule());
		rules.add(new IpHostRule());
		rules.add(new MisleadingSubdomainRule());
		rules.add(new UrgencyLanguageRule());
		rules.add(new CredentialRequestRule());
	}
	@Override
	public ScanResult analyze(ScanItem item) {
		int totalScore = 0;
		List<String> reason = new ArrayList<>();
		for( Rule rule : rules) {
			if(rule.appliesTo(item.getType())) {
				RuleHit hit = rule.evaluate(item);
				if(hit != null && hit.isHit()) {
					totalScore+= hit.getPoints();
					reason.add(hit.getReason());
				}
				
			}
		}
		return ScanResult.done(item, totalScore, reason);
		
	}


}
