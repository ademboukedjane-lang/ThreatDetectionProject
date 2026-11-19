package threatdetector.ui;

import threatdetector.exception.InvalidInputException;
import threatdetector.model.InputType;
import threatdetector.model.ScanItem;
import threatdetector.model.ScanResult;
import threatdetector.service.InputValidator;
import threatdetector.service.ScanCoordinator;
import threatdetector.service.ScanListener;

import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Whole screen + glue to the team's ScanCoordinator.
 * No detection logic here: it validates the input (InputValidator), hands the items to the
 * coordinator on a background thread, and displays what the listener reports.
 */
public class MainPanel extends JPanel {

    private final ScanCoordinator coordinator;
    private final int workerCount;
    private final AtomicInteger nextId = new AtomicInteger();

    private final InputPanel input = new InputPanel();
    private final ResultsTable results = new ResultsTable();
    private final ActivityLogPanel log = new ActivityLogPanel();
    private final SummaryPanel summary = new SummaryPanel();

    private List<ScanItem> loadedCsv;   // valid rows of the chosen CSV, waiting for Scan
    private int batchTotal;             // only touched on the Swing thread
    private int batchDone;

    /** @param workerCount number shown in the header badge (threads used by the coordinator). */
    public MainPanel(ScanCoordinator coordinator, int workerCount) {
        super(new BorderLayout());
        this.coordinator = coordinator;
        this.workerCount = workerCount;
        setBackground(Theme.BG);

        add(new SidebarPanel(this::onNavigate), BorderLayout.WEST);

        JPanel content = new JPanel(new BorderLayout(0, 12));
        content.setOpaque(false);
        content.setBorder(Theme.pad(14, 16, 16, 16));
        content.add(buildHeader(), BorderLayout.NORTH);

        JPanel center = new JPanel(new BorderLayout(0, 12));
        center.setOpaque(false);
        center.add(input, BorderLayout.NORTH);
        center.add(results, BorderLayout.CENTER);
        center.add(buildBottom(), BorderLayout.SOUTH);
        content.add(center, BorderLayout.CENTER);
        add(content, BorderLayout.CENTER);

        input.onScan(this::onScan);
        input.onBrowse(this::onBrowse);
        input.onModeChange(mode -> {
            if (mode != InputPanel.Mode.CSV) loadedCsv = null;
        });
        log.log("Ready. " + workerCount + " worker thread(s).");
    }

    // ---- layout pieces --------------------------------------------------------

    private JPanel buildHeader() {
        JLabel title = new JLabel("<html><span style='color:#FFFFFF'>Multi-Threaded </span>"
                + "<span style='color:#22D3EE'>Threat Detector</span></html>");
        title.setFont(Theme.font(Font.BOLD, 32));
        JLabel sub = new JLabel("Scan suspicious URLs and messages for phishing risk, in parallel !");
        sub.setFont(Theme.font(Font.ITALIC, 16));
        sub.setForeground(new Color(225, 235, 255));

        JPanel text = new JPanel(new BorderLayout(0, 2));
        text.setOpaque(false);
        text.add(title, BorderLayout.CENTER);
        text.add(sub, BorderLayout.SOUTH);

        RoundedPanel pill = new RoundedPanel(new BorderLayout(), Theme.PANEL, Theme.BORDER, 30);
        pill.setBorder(Theme.pad(8, 18, 8, 18));
        JLabel workers = new JLabel(workerCount + " Worker Threads", new Icons.Dot(Theme.OK), JLabel.LEFT);
        workers.setHorizontalTextPosition(JLabel.LEFT);
        workers.setIconTextGap(10);
        workers.setFont(Theme.font(Font.PLAIN, 15));
        workers.setForeground(Theme.TEXT);
        pill.add(workers, BorderLayout.CENTER);
        JPanel pillWrap = new JPanel(new GridBagLayout());
        pillWrap.setOpaque(false);
        pillWrap.add(pill);

        JPanel header = new JPanel(new BorderLayout());
        header.setOpaque(false);
        header.add(text, BorderLayout.WEST);
        header.add(pillWrap, BorderLayout.EAST);
        return header;
    }

    private JPanel buildBottom() {
        JPanel bottom = new JPanel(new GridBagLayout());
        bottom.setOpaque(false);
        bottom.setPreferredSize(new Dimension(0, 190));
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.BOTH;
        c.weighty = 1;
        c.gridy = 0;
        c.gridx = 0;
        c.weightx = 0.62;
        c.insets = new Insets(0, 0, 0, 7);
        bottom.add(log, c);
        c.gridx = 1;
        c.weightx = 0.38;
        c.insets = new Insets(0, 7, 0, 0);
        bottom.add(summary, c);
        return bottom;
    }

    // ---- actions --------------------------------------------------------------

    private void onNavigate(Icons.Nav nav) {
        switch (nav) {
            case ABOUT:
                JOptionPane.showMessageDialog(this,
                        "Multi-Threaded Threat Detector\nConcurrency Programming mini-project\n"
                                + "Scans URLs and messages in parallel and reports a risk level.",
                        "About", JOptionPane.INFORMATION_MESSAGE);
                break;
            case HISTORY:
            case SETTINGS:
                JOptionPane.showMessageDialog(this, "This page will be added in a later sprint.",
                        nav == Icons.Nav.HISTORY ? "History" : "Settings", JOptionPane.INFORMATION_MESSAGE);
                break;
            default:
                break;
        }
    }

    private void onBrowse() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Choose a CSV file");
        chooser.setFileFilter(new FileNameExtensionFilter("CSV files (*.csv)", "csv"));
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        loadCsv(chooser.getSelectedFile());
    }

    /**
     * Reads "type,content" lines (type = URL or MESSAGE; a header line is allowed).
     * Every row goes through InputValidator; bad rows are reported, good rows are kept.
     * TODO: if CsvParserService is ready, call it here instead of this small reader.
     */
    public void loadCsv(File file) {
        List<String> lines;
        try {
            lines = Files.readAllLines(file.toPath(), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            loadedCsv = null;
            input.setError("Cannot read file: " + ex.getMessage(), false);
            log.log("CSV error: " + ex);
            return;
        }

        List<ScanItem> items = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        boolean sawContent = false;
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.isEmpty()) continue;
            if (!sawContent) {
                sawContent = true;
                if (line.toLowerCase(Locale.ROOT).startsWith("type")) continue; // header row
            }
            int comma = line.indexOf(',');
            if (comma < 0) {
                errors.add("Line " + (i + 1) + ": missing columns");
                continue;
            }
            String typeText = line.substring(0, comma).trim().toUpperCase(Locale.ROOT);
            String content = line.substring(comma + 1).trim();
            if (content.length() >= 2 && content.startsWith("\"") && content.endsWith("\"")) {
                content = content.substring(1, content.length() - 1);
            }
            InputType type;
            try {
                type = InputType.valueOf(typeText);
            } catch (IllegalArgumentException e) {
                errors.add("Line " + (i + 1) + ": unknown type '" + typeText + "'");
                continue;
            }
            try {
                InputValidator.validate(new ScanItem(0, type, content));   // throwaway item, id 0
                items.add(new ScanItem(nextId.incrementAndGet(), type, content));
            } catch (InvalidInputException e) {
                errors.add("Line " + (i + 1) + ": " + e.getMessage());
            }
        }

        input.setMode(InputPanel.Mode.CSV);
        if (!sawContent) {
            loadedCsv = null;
            input.setError("The CSV file is empty.", false);
            log.log("CSV error: " + file.getName() + " is empty.");
            return;
        }
        loadedCsv = items;
        input.showCsvFile(file.getName() + "  (" + items.size() + " valid rows)");
        log.log("Loaded CSV " + file.getName() + ": " + items.size() + " valid, " + errors.size() + " invalid.");
        for (String e : errors) log.log("CSV: " + e);
        if (!errors.isEmpty()) {
            input.setError(errors.size() + " invalid row(s) skipped. First: " + errors.get(0), true);
        } else if (items.isEmpty()) {
            input.setError("No valid rows found in this file.", false);
        }
    }

    private void onScan() {
        input.setError(null, false);
        try {
            List<ScanItem> items;
            InputPanel.Mode mode = input.getMode();
            if (mode == InputPanel.Mode.CSV) {
                if (loadedCsv == null || loadedCsv.isEmpty()) {
                    throw new InvalidInputException("Choose a CSV file first (Browse CSV).");
                }
                items = loadedCsv;
                loadedCsv = null;
                input.clearField();
            } else {
                InputType type = mode == InputPanel.Mode.URL ? InputType.URL : InputType.MESSAGE;
                String text = input.getText().trim();
                InputValidator.validate(new ScanItem(0, type, text));       // throws if empty / malformed
                items = List.of(new ScanItem(nextId.incrementAndGet(), type, text));
                input.clearField();
            }
            startScan(items);
        } catch (InvalidInputException ex) {
            input.setError(ex.getMessage(), false);
            log.log("Rejected input: " + ex.getMessage());
        } catch (RuntimeException ex) {
            input.setError("Unexpected error: " + ex.getMessage(), false);
            log.log("Unexpected error: " + ex);
        }
    }

    private void startScan(List<ScanItem> items) {
        batchTotal = items.size();
        batchDone = 0;
        for (ScanItem item : items) results.addItem(item);
        results.setBatchProgress(0, batchTotal);
        input.setScanning(true);
        log.log("Scan started... (" + batchTotal + (batchTotal == 1 ? " item)" : " items)"));

        // The coordinator calls these from its own thread(s): always hop to the Swing thread.
        ScanListener listener = new ScanListener() {
            @Override public void onStarted(ScanItem item) {
                SwingUtilities.invokeLater(() -> {
                    results.markRunning(item);
                    log.log("Analyzing: " + shorten(item.getContent()));
                });
            }

            @Override public void onProgress(int done, int total) {
                // The table's progress bar is driven by handleFinished (exact, on the Swing thread).
            }

            @Override public void onFinished(ScanResult result) {
                SwingUtilities.invokeLater(() -> handleFinished(result));
            }
        };

        // submitAll may block until the batch is done (sequential coordinator) -> never on the Swing thread.
        Thread t = new Thread(() -> {
            try {
                coordinator.submitAll(items, listener);
            } catch (RuntimeException ex) {
                SwingUtilities.invokeLater(() -> {
                    log.log("Scan failed: " + ex);
                    input.setError("Scan failed: " + ex.getMessage(), false);
                    input.setScanning(false);
                });
            }
        }, "scan-batch");
        t.setDaemon(true);
        t.start();
    }

    private void handleFinished(ScanResult r) {
        results.updateResult(r);
        batchDone++;
        results.setBatchProgress(batchDone, batchTotal);
        summary.update(results.counts());
        log.log("Item #" + r.getItem().getId() + " completed: " + r.getLevel() + " risk");
        if (batchDone >= batchTotal) {
            input.setScanning(false);
            log.log("Scan finished: " + batchTotal + (batchTotal == 1 ? " item." : " items."));
        }
    }

    private static String shorten(String s) {
        return s.length() <= 48 ? s : s.substring(0, 45) + "...";
    }
}
