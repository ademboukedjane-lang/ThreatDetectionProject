package threatdetector.service.rules;

import java.util.Locale;

import threatdetector.model.InputType;
import threatdetector.model.RuleHit;
import threatdetector.model.ScanItem;
import threatdetector.service.Rule;

public class SuspensionThreatRule implements Rule {

    @Override
    public boolean appliesTo(InputType type) {
        return type == InputType.MESSAGE;
    }

    @Override
    public RuleHit evaluate(ScanItem item) {

        String content = item.getContent().toLowerCase(Locale.ROOT);

        String[] threats = {
            "prevent suspension",
            "account suspension",
            "account suspended",
            "suspend your account",
            "account will be suspended",
            "تعليق الحساب",
            "إيقاف الحساب"
        };

        for (String word : threats) {
            if (content.contains(word)) {
                return new RuleHit(10,
                    "Message contains an account suspension threat");
            }
        }

        return RuleHit.none();
    }
}