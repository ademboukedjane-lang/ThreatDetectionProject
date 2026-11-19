package threatdetector.ui;

import threatdetector.exception.CsvFormatException;
import threatdetector.exception.InvalidInputException;
import threatdetector.model.InputType;
import threatdetector.model.ScanItem;
import threatdetector.model.ScanResult;
import threatdetector.service.ParseReport;
import threatdetector.service.ScanListener;
import threatdetector.service.ScanService;

import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Dimension;
import java.io.File;
import java.util.List;

/**
 * All the screen content + the glue between widgets and the ScanService.
 * It contains NO detection logic: it only calls the service and displays what comes back.
 */
public class MainPanel extends JPanel {

    private final ScanService service;
    private final InputPanel input = new InputPanel();
    private final ResultsTable results = new ResultsTable();
    private final ActivityLogPanel log = new ActivityLogPanel();
    private final SummaryPanel summary = new SummaryPanel();

    private List<ScanItem> loadedCsv;   // items parsed from the chosen CSV, waiting for Scan
    private int batchTotal;
    private int batchDone;

    public MainPanel(ScanService service) {
        super(new BorderLayout());
        this.service = service;
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
        log.log("Ready. " + service.getWorkerCount() + " worker threads available.");
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
        JLabel workers = new JLabel(service.getWorkerCount() + " Worker Threads", new Icons.Dot(Theme.OK), JLabel.LEFT);
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
        c.insets = new java.awt.Insets(0, 0, 0, 7);
        bottom.add(log, c);
        c.gridx = 1;
        c.weightx = 0.38;
        c.insets = new java.awt.Insets(0, 7, 0, 0);
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

    /** Public so it can be tested / reused (e.g. drag & drop later). */
    public void loadCsv(File file) {
        try {
            ParseReport report = service.loadCsv(file);
            input.setMode(InputPanel.Mode.CSV);
            loadedCsv = report.getItems();
            input.showCsvFile(file.getName() + "  (" + loadedCsv.size() + " valid rows)");
            log.log("Loaded CSV " + file.getName() + ": " + loadedCsv.size() + " valid, "
                    + report.getErrors().size() + " invalid.");
            if (!report.getErrors().isEmpty()) {
                input.setError(report.getErrors().size() + " invalid row(s) skipped. First: "
                        + report.getErrors().get(0), true);
                for (String e : report.getErrors()) log.log("CSV: " + e);
            } else if (loadedCsv.isEmpty()) {
                input.setError("No valid rows found in this file.", false);
            }
        } catch (CsvFormatException ex) {
            loadedCsv = null;
            input.setError(ex.getMessage(), false);
            log.log("CSV error: " + ex.getMessage());
        } catch (RuntimeException ex) {
            loadedCsv = null;
            input.setError("Unexpected error while reading the file.", false);
            log.log("CSV error: " + ex);
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
                items = List.of(service.createItem(type, input.getText()));
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

        // Callbacks arrive on worker threads: always hop to the Swing thread.
        service.submitAll(items, new ScanListener() {
            @Override public void onStarted(ScanItem item) {
                SwingUtilities.invokeLater(() -> {
                    results.markRunning(item);
                    log.log("Analyzing: " + shorten(item.getContent()));
                });
            }

            @Override public void onProgress(ScanItem item, int percent) {
                SwingUtilities.invokeLater(() -> results.updateProgress(item, percent));
            }

            @Override public void onFinished(ScanResult result) {
                SwingUtilities.invokeLater(() -> handleFinished(result));
            }
        });
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
