package threatdetector.service;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import threatdetector.exception.CsvFormatException;
import threatdetector.model.InputType;
import threatdetector.model.ScanItem;

public class CsvParserService {

    public static class ParseReport {
        public List<ScanItem> items = new ArrayList<ScanItem>();
        public List<String> errors = new ArrayList<String>();
    }

    public ParseReport parse(File file) throws CsvFormatException {
      if (file == null || !file.exists()) {
            throw new CsvFormatException("File not found");
        }

        ParseReport report = new ParseReport();

        try {
            BufferedReader reader = new BufferedReader(new FileReader(file));

            String header = reader.readLine();

            if (header == null || header.trim().isEmpty()) {
                reader.close();
                throw new CsvFormatException("Empty file");
            }

            List<String> cols = splitLine(header.replace("\uFEFF", ""));

            int typeIndex = -1;
            int contentIndex = -1;

            for (int i = 0; i < cols.size(); i++) {

                String name = cols.get(i).trim().toLowerCase();

                if (name.equals("type") || name.equals("input_type")) {
                    typeIndex = i;
                }

                if (name.equals("content")) {
                    contentIndex = i;
                }
            }

            if (typeIndex == -1 || contentIndex == -1) {
                reader.close();
                throw new CsvFormatException(
                    "Header must contain 'type' and 'content'"
                );
            }

            String line;
            int lineNumber = 1;
            int id = 1;

            while ((line = reader.readLine()) != null) {

                lineNumber++;

                if (line.trim().isEmpty()) {
                    continue;
                }

                List<String> fields = splitLine(line);

                if (fields.size() <= Math.max(typeIndex, contentIndex)) {
                    report.errors.add("Line " + lineNumber + ": missing columns");
                    continue;
                }

                String typeText = fields.get(typeIndex).trim().toUpperCase();

                InputType type;

                if (typeText.equals("URL")) {

                    type = InputType.URL;

                } else if (typeText.equals("MESSAGE") ||
                           typeText.equals("SMS") ||
                           typeText.equals("EMAIL")) {

                    type = InputType.MESSAGE;

                } else {

                    report.errors.add("Line " + lineNumber + ": unknown type");
                    continue;
                }

                report.items.add(
                    new ScanItem(id, type, fields.get(contentIndex))
                );

                id++;
            }

            reader.close();

        } catch (IOException e) {

            throw new CsvFormatException("Cannot read file");
        }

        return report;
    }

    private List<String> splitLine(String line) {

        List<String> result = new ArrayList<String>();

        StringBuilder current = new StringBuilder();

        boolean inQuotes = false;

        for (int i = 0; i < line.length(); i++) {

            char c = line.charAt(i);

            if (c == '"') {

                inQuotes = !inQuotes;

            } else if (c == ',' && !inQuotes) {
                result.add(current.toString());
                current = new StringBuilder();

            } else {

                current.append(c);
            }
        }

        result.add(current.toString());

        return result;
    }
}