package threatdetector.service;

import java.net.URI;
import java.net.URISyntaxException;

import threatdetector.exception.InvalidInputException;
import threatdetector.model.InputType;
import threatdetector.model.ScanItem;

public class InputValidator {

    public static void validate(ScanItem item)
            throws InvalidInputException {

        // Check if item is null
        if (item == null) {
            throw new InvalidInputException("Input item is null");
        }

        // Check input type
        if (item.getType() == null) {
            throw new InvalidInputException("Input type is missing");
        }

        // Check content
        if (item.getContent() == null) {
            throw new InvalidInputException("Input content is null");
        }

        String text = item.getContent().trim();

        if (text.isEmpty()) {
            throw new InvalidInputException("Empty input");
        }

        // Validate URL
        if (item.getType() == InputType.URL) {

            if (!text.matches("(?i)^https?://\\S+$")) {
                throw new InvalidInputException(
                    "Malformed URL (scheme must be http or https)"
                );
            }

            try {
                URI uri = new URI(text);

                if (uri.getHost() == null) {
                    throw new InvalidInputException(
                        "Malformed URL (invalid host)"
                    );
                }

            } catch (URISyntaxException e) {

                throw new InvalidInputException("Malformed URL");
            }
        }
    }
}