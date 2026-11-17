package threatdetector.service;

import java.net.URI;
import java.net.URISyntaxException;
import threatdetector.exception.InvalidInputException;
import threatdetector.model.InputType;
import threatdetector.model.ScanItem;

public class InputValidator {

    public static void validate(ScanItem item) throws InvalidInputException {
        String text = item.getContent().trim();

        if (text.isEmpty()) {
            throw new InvalidInputException("Empty input");
        }

        if (item.getType() == InputType.URL) {
            if (!text.matches("(?i)^https?://\\S+$")) {
                throw new InvalidInputException("Malformed URL (scheme must be http or https)");
            }
            try {
                URI uri = new URI(text);
                if (uri.getHost() == null) {
                    throw new InvalidInputException("Malformed URL (invalid host)");
                }
            } catch (URISyntaxException e) {
                throw new InvalidInputException("Malformed URL");
            }
        }
    }
}