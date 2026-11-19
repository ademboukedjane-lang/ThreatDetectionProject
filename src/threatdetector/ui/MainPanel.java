package threatdetector.ui;

import threatdetector.exception.InvalidInputException;
import threatdetector.exception.CsvFormatException;

import threatdetector.model.InputType;
import threatdetector.model.ScanItem;
import threatdetector.model.ScanResult;

import threatdetector.service.InputValidator;
import threatdetector.service.CsvParserService;
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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class MainPanel extends JPanel {

    private final ScanCoordinator coordinator;
    private final int workerCount;

    private final AtomicInteger nextId = new AtomicInteger(0);


    private final InputPanel input = new InputPanel();
    private final ResultsTable results = new ResultsTable();
    private final ActivityLogPanel log = new ActivityLogPanel();
    private final SummaryPanel summary = new SummaryPanel();

    private List<ScanItem> loadedCsv;

    private int batchTotal;
    private int batchDone;

    // ================= CONSTRUCTOR =================

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
            if (mode != InputPanel.Mode.CSV) {
                loadedCsv = null;
            }
        });

        log.log("Ready. " + workerCount + " worker thread(s).");
    }

    // ================= HEADER =================

    private JPanel buildHeader() {

        JLabel title = new JLabel(
                "<html><span style='color:#FFFFFF'>Multi-Threaded </span>"
                + "<span style='color:#22D3EE'>Threat Detector</span></html>");

        title.setFont(Theme.font(Font.BOLD, 32));

        JLabel sub = new JLabel(
                "Scan suspicious URLs and messages for phishing risk, in parallel !");

        sub.setFont(Theme.font(Font.ITALIC, 16));
        sub.setForeground(new Color(225, 235, 255));

        JPanel text = new JPanel(new BorderLayout(0, 2));
        text.setOpaque(false);

        text.add(title, BorderLayout.CENTER);
        text.add(sub, BorderLayout.SOUTH);

        RoundedPanel pill = new RoundedPanel(
                new BorderLayout(),
                Theme.PANEL,
                Theme.BORDER,
                30
        );

        pill.setBorder(Theme.pad(8, 18, 8, 18));

        JLabel workers = new JLabel(
                workerCount + " Worker Threads",
                new Icons.Dot(Theme.OK),
                JLabel.LEFT
        );

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

    // ================= BOTTOM =================

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

    // ================= NAVIGATION =================

    private void onNavigate(Icons.Nav nav) {

        switch (nav) {

            case ABOUT:

                JOptionPane.showMessageDialog(
                        this,
                        "Multi-Threaded Threat Detector\n"
                        + "Concurrency Programming mini-project\n"
                        + "Scans URLs and messages and reports a risk level.",
                        "About",
                        JOptionPane.INFORMATION_MESSAGE
                );

                break;

            case HISTORY:

                JOptionPane.showMessageDialog(
                        this,
                        "History page will be added later.",
                        "History",
                        JOptionPane.INFORMATION_MESSAGE
                );

                break;

            case SETTINGS:

                JOptionPane.showMessageDialog(
                        this,
                        "Settings page will be added later.",
                        "Settings",
                        JOptionPane.INFORMATION_MESSAGE
                );

                break;

            default:
                break;
        }
    }

    // ================= CSV BROWSE =================

    private void onBrowse() {

        JFileChooser chooser = new JFileChooser();

        chooser.setDialogTitle("Choose a CSV file");

        chooser.setFileFilter(
                new FileNameExtensionFilter("CSV files (*.csv)", "csv")
        );

        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        loadCsv(chooser.getSelectedFile());
    }

    // ================= CSV LOADING =================

    public void loadCsv(File file) {

        loadedCsv = null;
        input.setError(null, false);

        CsvParserService parser = new CsvParserService();

        try {

            CsvParserService.ParseReport report = parser.parse(file);

            List<ScanItem> items = new ArrayList<>();
            List<String> errors = new ArrayList<>();

            errors.addAll(report.errors);

            // Validate every parsed item
            for (ScanItem parsedItem : report.items) {

                try {

                    InputValidator.validate(
                            new ScanItem(
                                    0,
                                    parsedItem.getType(),
                                    parsedItem.getContent()
                            )
                    );

                    ScanItem item = new ScanItem(
                            nextId.incrementAndGet(),
                            parsedItem.getType(),
                            parsedItem.getContent()
                    );

                    items.add(item);

                } catch (InvalidInputException ex) {

                    errors.add(ex.getMessage());
                }
            }

            input.setMode(InputPanel.Mode.CSV);

            if (items.isEmpty()) {

                loadedCsv = null;
                input.setError(
                        "No valid rows found in CSV file.",
                        false
                );

                log.log("CSV loaded but no valid rows found.");

                for (String error : errors) {
                    log.log("CSV error: " + error);
                }

                return;
            }

            loadedCsv = items;

            input.showCsvFile(
                    file.getName()
                    + "  ("
                    + items.size()
                    + " valid rows)"
            );

            log.log(
                    "CSV loaded: "
                    + file.getName()
                    + " | Valid: "
                    + items.size()
                    + " | Invalid: "
                    + errors.size()
            );

            for (String error : errors) {
                log.log("CSV error: " + error);
            }

            if (!errors.isEmpty()) {

                input.setError(
                        errors.size()
                        + " invalid row(s) skipped. First: "
                        + errors.get(0),
                        true
                );
            }

        } catch (CsvFormatException ex) {

            loadedCsv = null;

            input.setError(
                    "CSV format error: " + ex.getMessage(),
                    false
            );

            log.log("CSV format error: " + ex.getMessage());

        } catch (RuntimeException ex) {

            loadedCsv = null;

            input.setError(
                    "Cannot load CSV: " + ex.getMessage(),
                    false
            );

            log.log("CSV loading failed: " + ex);
        }
    }

    // ================= SCAN BUTTON =================

    private void onScan() {

        input.setError(null, false);

        try {

            List<ScanItem> items;

            InputPanel.Mode mode = input.getMode();

            // -------- CSV MODE --------

            if (mode == InputPanel.Mode.CSV) {

                if (loadedCsv == null || loadedCsv.isEmpty()) {

                    throw new InvalidInputException(
                            "Choose a valid CSV file first."
                    );
                }

                items = new ArrayList<>(loadedCsv);

                loadedCsv = null;

                input.clearField();
            }

            // -------- URL / MESSAGE MODE --------

            else {

                InputType type;

                if (mode == InputPanel.Mode.URL) {
                    type = InputType.URL;
                } else {
                    type = InputType.MESSAGE;
                }

                String text = input.getText().trim();

                ScanItem temporaryItem = new ScanItem(
                        0,
                        type,
                        text
                );

                InputValidator.validate(temporaryItem);

                ScanItem item = new ScanItem(
                        nextId.incrementAndGet(),
                        type,
                        text
                );

                items = new ArrayList<>();
                items.add(item);

                input.clearField();
            }

            if (items.isEmpty()) {

                throw new InvalidInputException(
                        "There is nothing to scan."
                );
            }

            startScan(items);

        } catch (InvalidInputException ex) {

            input.setError(ex.getMessage(), false);

            log.log("Rejected input: " + ex.getMessage());

        } catch (RuntimeException ex) {

            input.setError(
                    "Unexpected error: " + ex.getMessage(),
                    false
            );

            log.log("Unexpected error: " + ex);
        }
    }

    // ================= START SCAN =================

    private void startScan(List<ScanItem> items) {

        batchTotal = items.size();
        batchDone = 0;
        for (ScanItem item : items) {
            results.addItem(item);
        }

        results.setBatchProgress(0, batchTotal);

        input.setScanning(true);

        log.log(
                "Scan started... ("
                + batchTotal
                + (batchTotal == 1 ? " item)" : " items)")
        );

        ScanListener listener = new ScanListener() {

            @Override
            public void onStarted(ScanItem item) {

                SwingUtilities.invokeLater(() -> {

                    results.markRunning(item);

                    log.log(
                            "Analyzing: "
                            + shorten(item.getContent())
                    );
                });
            }

            @Override
            public void onProgress(int done, int total) {

                // Progress is updated when each item finishes.
            }

            @Override
            public void onFinished(ScanResult result) {

                SwingUtilities.invokeLater(() -> handleFinished(result));
            }
        };

        // Run the coordinator outside the Swing thread.
        Thread scanThread = new Thread(() -> {

            try {

                coordinator.submitAll(items, listener);

            } catch (Exception ex) {

                SwingUtilities.invokeLater(() -> {

                    log.log("Scan failed: " + ex);

                    input.setError(
                            "Scan failed: " + ex.getMessage(),
                            false
                    );

                    input.setScanning(false);
                });
            }

        }, "scan-batch");

        scanThread.setDaemon(true);
        scanThread.start();
    }

    // ================= FINISHED ITEM =================

    private void handleFinished(ScanResult result) {

        results.updateResult(result);

        batchDone++;

        results.setBatchProgress(
                batchDone,
                batchTotal
        );

        summary.update(results.counts());

        log.log(
                "Item #"
                + result.getItem().getId()
                + " completed: "
                + result.getLevel()
                + " risk"
        );

        if (batchDone >= batchTotal) {

            input.setScanning(false);

            log.log(
                    "Scan finished: "
                    + batchTotal
                    + (batchTotal == 1 ? " item." : " items.")
            );
        }
    }

    // ================= SHORT TEXT =================

    private static String shorten(String text) {

        if (text == null) {
            return "";
        }

        if (text.length() <= 48) {
            return text;
        }

        return text.substring(0, 45) + "...";
    }
}