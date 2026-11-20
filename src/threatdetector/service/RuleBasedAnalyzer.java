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
import threatdetector.service.rules.SuspensionThreatRule;
import threatdetector.service.rules.UrgencyLanguageRule;
import threatdetector.service.rules.AccountNotificationRule;
import threatdetector.service.rules.AtSymbolRule;
import threatdetector.service.rules.CredentialRequestRule;
import threatdetector.service.rules.EmbeddedIpUrlRule;


public class RuleBasedAnalyzer implements ThreatAnalyze {

    private final List<Rule> rules;

    public RuleBasedAnalyzer() {

        rules = Arrays.asList(
            new HttpOnlyRule(),
            new IpHostRule(),
            new MisleadingSubdomainRule(),
            new UrgencyLanguageRule(),
            new CredentialRequestRule(),
            new AtSymbolRule(),
            new EmbeddedIpUrlRule(),
            new SuspensionThreatRule(),
            new AccountNotificationRule()
        );
    }

    @Override
    public ScanResult analyze(ScanItem item) {

        if (item == null) {
            throw new IllegalArgumentException("Item cannot be null");
        }
        if (item.getType() == null) {
            return ScanResult.notVerified(item, "Input type is missing");
        }

        if (item.getContent() == null || item.getContent().trim().isEmpty()) {
            return ScanResult.notVerified(item, "Input content is empty");
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

            return ScanResult.notVerified( item,"Analysis failed: " + e.getMessage());
        }
    }
}