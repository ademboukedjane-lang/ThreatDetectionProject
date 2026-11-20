package threatdetector.service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import threatdetector.model.ScanItem;
import threatdetector.model.ScanResult;
import threatdetector.model.RuleHit;

import threatdetector.service.rules.HttpOnlyRule;
import threatdetector.service.rules.IpHostRule;
import threatdetector.service.rules.MisleadingSubdomainRule;
import threatdetector.service.rules.UrgencyLanguageRule;
import threatdetector.service.rules.CredentialRequestRule;

public class RuleBasedAnalyzer implements ThreatAnalyze {

    private final List<Rule> rules;

    public RuleBasedAnalyzer() {

        rules = Arrays.asList(
            new HttpOnlyRule(),
            new IpHostRule(),
            new MisleadingSubdomainRule(),
            new UrgencyLanguageRule(),
            new CredentialRequestRule()
        );
    }

    @Override
    public ScanResult analyze(ScanItem item) {

        if (item == null) {
            throw new IllegalArgumentException("Item cannot be null");
        }

        int score = 0;

        List<String> reasons = new ArrayList<>();

        try {

            for (Rule rule : rules) {

                if (rule.appliesTo(item.getType())) {

                    RuleHit hit = rule.evaluate(item);

                    if (hit != null && hit.isHit()) {

                        score += hit.getPoints();

                        reasons.add(hit.getReason());
                    }
                }
            }
            if (reasons.isEmpty()) {
                reasons.add("No suspicious indicators detected (Score: 0)");
            }

            return ScanResult.done(item, score, reasons);

        } catch (RuntimeException e) {

            return ScanResult.notVerified(
                item,
                "Analysis failed: " + e.getMessage()
            );
        }
    }
}