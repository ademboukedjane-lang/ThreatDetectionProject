package threatdetector.service.rules;

import java.util.Locale;

import threatdetector.model.InputType;
import threatdetector.model.RuleHit;
import threatdetector.model.ScanItem;
import threatdetector.service.Rule;

public class AccountNotificationRule implements Rule {

    @Override
    public boolean appliesTo(InputType type) {
        return type == InputType.MESSAGE;
    }

    @Override
    public RuleHit evaluate(ScanItem item) {

        String content = item.getContent().toLowerCase(Locale.ROOT);

        if (content.contains("weekly account digest")
                || content.contains("notification settings")) {

            return new RuleHit(30,
                "Message contains account notification indicators");
        }

        return RuleHit.none();
    }
}