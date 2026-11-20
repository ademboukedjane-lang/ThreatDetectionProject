package threatdetector.service;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import threatdetector.exception.CsvFormatException;
import threatdetector.model.InputType;
import threatdetector.model.ScanItem;

/**
 * Tolerant CSV reader.
 *  - UTF-8 (with or without BOM), falls back to Windows-1252
 *  - delimiter auto-detected: comma, semicolon or tab
 *  - quoted fields, "" escapes, commas and line breaks inside quotes
 *  - header aliases (type/input_type/kind ..., content/text/url/message ...)
 *  - bad rows are skipped and reported with their line number
 */
public class CsvParserService {

    private static final long MAX_BYTES = 20L * 1024 * 1024;

    private static final List<String> TYPE_NAMES =
            Arrays.asList("type", "input_type", "inputtype", "kind", "category");
    private static final List<String> CONTENT_NAMES =
            Arrays.asList("content", "text", "value", "input", "url", "link", "message", "body");

    private static final class Rec {
        final int line;
        final List<String> fields;
        Rec(int line, List<String> fields) { this.line = line; this.fields = fields; }
    }

    public ParseReport parse(File file) throws CsvFormatException {
        if (file == null || !file.exists() || !file.isFile()) {
            throw new CsvFormatException("File not found");
        }
        if (file.length() > MAX_BYTES) {
            throw new CsvFormatException("File too large (max 20 MB)");
        }

        String text = readText(file);
        if (text.startsWith("\uFEFF")) {
            text = text.substring(1);
        }
        if (text.trim().isEmpty()) {
            throw new CsvFormatException("Empty file");
        }

        ParseReport report = new ParseReport();

        // Excel may add a first line "sep=;"
        if (text.regionMatches(true, 0, "sep=", 0, 4)) {
            int nl = text.indexOf('\n');
            text = nl < 0 ? "" : text.substring(nl + 1);
        }

        char delim = detectDelimiter(text);
        List<Rec> records = tokenize(text, delim, report);

        // first non-empty record is the header
        int h = 0;
        while (h < records.size() && isBlank(records.get(h).fields)) {
            h++;
        }
        if (h >= records.size()) {
            throw new CsvFormatException("Empty file");
        }

        List<String> header = records.get(h).fields;
        int typeIndex = -1, contentIndex = -1;
        for (int i = 0; i < header.size(); i++) {
            String name = header.get(i).trim().toLowerCase().replace(' ', '_');
            if (typeIndex == -1 && TYPE_NAMES.contains(name)) typeIndex = i;
            else if (contentIndex == -1 && CONTENT_NAMES.contains(name)) contentIndex = i;
        }
        if (typeIndex == -1 || contentIndex == -1) {
            throw new CsvFormatException("Header must contain 'type' and 'content'");
        }

        int id = 1;
        for (int r = h + 1; r < records.size(); r++) {
            Rec rec = records.get(r);
            if (isBlank(rec.fields)) continue;

            if (rec.fields.size() <= Math.max(typeIndex, contentIndex)) {
                report.errors.add("Line " + rec.line + ": missing columns");
                continue;
            }

            String typeText = rec.fields.get(typeIndex).trim().toUpperCase();
            InputType type = toType(typeText);
            if (type == null) {
                report.errors.add("Line " + rec.line + ": unknown type '" + typeText + "'");
                continue;
            }

            report.items.add(new ScanItem(id++, type, rec.fields.get(contentIndex).trim()));
        }
        return report;
    }

    private static InputType toType(String t) {
        switch (t) {
            case "URL": case "LINK": case "WEB": case "WEBSITE":
                return InputType.URL;
            case "MESSAGE": case "MSG": case "SMS": case "EMAIL": case "MAIL": case "TEXT":
                return InputType.MESSAGE;
            default:
                return null;
        }
    }

    private static boolean isBlank(List<String> f) {
        for (String s : f) {
            if (!s.trim().isEmpty()) return false;
        }
        return true;
    }

    private static String readText(File file) throws CsvFormatException {
        try {
            byte[] bytes = Files.readAllBytes(file.toPath());
            try {
                return StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(bytes)).toString();
            } catch (CharacterCodingException e) {
                return new String(bytes, Charset.forName("windows-1252"));
            }
        } catch (IOException e) {
            throw new CsvFormatException("Cannot read file");
        }
    }

    /** Looks at the first line (outside quotes) and picks the most frequent delimiter. */
    private static char detectDelimiter(String text) {
        int comma = 0, semi = 0, tab = 0;
        boolean q = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '"') q = !q;
            else if (!q && (c == '\n' || c == '\r')) {
                if (comma + semi + tab > 0) break;
            } else if (!q) {
                if (c == ',') comma++;
                else if (c == ';') semi++;
                else if (c == '\t') tab++;
            }
        }
        if (semi > comma && semi >= tab) return ';';
        if (tab > comma && tab > semi) return '\t';
        return ',';
    }

    /** RFC-4180 style tokenizer: returns one Rec per logical row, with its starting line number. */
    private static List<Rec> tokenize(String text, char delim, ParseReport report) {
        List<Rec> out = new ArrayList<>();
        List<String> fields = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inQuotes = false;
        int line = 1, startLine = 1;

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);

            if (inQuotes) {
                if (c == '"') {
                    if (i + 1 < text.length() && text.charAt(i + 1) == '"') {
                        cur.append('"');
                        i++;
                    } else {
                        inQuotes = false;
                    }
                } else {
                    if (c == '\n') line++;
                    cur.append(c);
                }
            } else if (c == '"') {
                inQuotes = true;
            } else if (c == delim) {
                fields.add(cur.toString());
                cur.setLength(0);
            } else if (c == '\n' || c == '\r') {
                if (c == '\r' && i + 1 < text.length() && text.charAt(i + 1) == '\n') i++;
                fields.add(cur.toString());
                cur.setLength(0);
                out.add(new Rec(startLine, fields));
                fields = new ArrayList<>();
                line++;
                startLine = line;
            } else {
                cur.append(c);
            }
        }

        if (inQuotes) {
            report.errors.add("Line " + startLine + ": quote was never closed");
        }
        else if (cur.length() > 0 || !fields.isEmpty()) {
            fields.add(cur.toString());
            out.add(new Rec(startLine, fields));
        }
        return out;
    }
}
