package threatdetector.service.rules;

import java.net.URI;

import threatdetector.model.InputType;
import threatdetector.model.RuleHit;
import threatdetector.model.ScanItem;
import threatdetector.service.Rule;

public class AtSymbolRule implements Rule {

    @Override
    public boolean appliesTo(InputType type) {
        return type == InputType.URL;
    }

    @Override
    public RuleHit evaluate(ScanItem item) {

        String content = item.getContent().trim();

        try {
            URI uri = URI.create(content);

            String userInfo = uri.getRawUserInfo();

            if (userInfo != null ) {
                return new RuleHit(
                    30,
                    "URL contains @ symbol, which may hide the real destination"
                );
            }

        } catch (IllegalArgumentException e) {
            return RuleHit.none();
        }

        return RuleHit.none();
    }
}