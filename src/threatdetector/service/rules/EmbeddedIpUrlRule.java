package threatdetector.service.rules;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import threatdetector.model.InputType;
import threatdetector.model.RuleHit;
import threatdetector.model.ScanItem;
import threatdetector.service.Rule;

public class EmbeddedIpUrlRule implements Rule {

    @Override
    public boolean appliesTo(InputType type) {
        return type == InputType.MESSAGE;
    }

    @Override
    public RuleHit evaluate(ScanItem item) {

        String content = item.getContent();

        Pattern pattern = Pattern.compile(
            "https?://(\\d{1,3}\\.){3}\\d{1,3}"
        );

        Matcher matcher = pattern.matcher(content);

        while (matcher.find()) {
            String ip = matcher.group()
                    .replaceFirst("^https?://", "");

            if (isIPv4(ip)) {
                return new RuleHit(30,
                    "Message contains a URL using an IP address");
            }
        }

        return RuleHit.none();
    }

    private boolean isIPv4(String host) {

        String[] parts = host.split("\\.");

        if (parts.length != 4) {
            return false;
        }

        for (String part : parts) {
            try {
                int number = Integer.parseInt(part);

                if (number < 0 || number > 255) {
                    return false;
                }

            } catch (NumberFormatException e) {
                return false;
            }
        }

        return true;
    }
}