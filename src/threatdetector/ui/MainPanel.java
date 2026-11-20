package threatdetector.ui;

import threatdetector.exception.InvalidInputException;
import threatdetector.exception.CsvFormatException;

import threatdetector.model.InputType;
import threatdetector.model.ScanItem;
import threatdetector.model.ScanResult;

import threatdetector.service.CsvParserService;
import threatdetector.service.ParseReport;
import threatdetector.service.ScanCoordinator;
import threatdetector.service.ScanListener;

import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
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

    private final AnimatedBackground background = new AnimatedBackground(this);

    private int active;   // items queued or running (Swing thread only)

    private int batchTotal;
    private int batchDone;

    // ================= CONSTRUCTOR =================

    public MainPanel(ScanCoordinator coordinator, int workerCount) {

        super(new BorderLayout());

        this.coordinator = coordinator;
        this.workerCount = workerCount;

        setBackground(Theme.BG);

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
        input.onAdd(this::onAdd);
        results.onRowScan(this::onRowScan);
        results.onClear(() -> summary.update(new int[4]));


        log.log("Ready. " + workerCount + " VEYTRIX(s).");
    }

    // ================= HEADER =================

    private JPanel buildHeader() {

        JLabel title = new JLabel(
                "<html><span style='color:#FFFFFF'>ThreatGuard- </span>"
                + "<span style='color:#22D3EE'>SMART THREAT DETECTION</span></html>");

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
                workerCount + " VEYTRIX",
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

        JLabel logo = new JLabel(new Icons.Shield(52, 62, true));
        logo.setBorder(Theme.pad(0, 0, 0, 14));

        JPanel left = new JPanel(new BorderLayout());
        left.setOpaque(false);
        left.add(logo, BorderLayout.WEST);
        left.add(text, BorderLayout.CENTER);

        header.add(left, BorderLayout.WEST);
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

    // ================= CSV BROWSE =================

    private static File lastDir = null;

    private void onBrowse() {

        JFileChooser chooser = new JFileChooser(lastDir);

        chooser.setDialogTitle("Choose one or more CSV files");
        chooser.setMultiSelectionEnabled(true);
        chooser.setFileFilter(
                new FileNameExtensionFilter("CSV / text files (*.csv, *.txt)", "csv", "txt")
        );

        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File[] files = chooser.getSelectedFiles();

        if (files.length > 0) {
            lastDir = files[0].getParentFile();
        }

        for (File f : files) {
            loadCsv(f);
        }
    }

    // ================= CSV LOADING =================

    /** Adds every usable row of the file to the table (as Pending). Nothing is scanned yet. */
    public void loadCsv(File file) {

        input.setError(null, false);

        try {

            ParseReport report = new CsvParserService().parse(file);

            input.setMode(InputPanel.Mode.CSV);

            for (String error : report.errors) {
                log.log("CSV skipped: " + error);
            }

            if (report.items.isEmpty()) {

                input.setError("No usable rows in " + file.getName(), false);
                log.log("CSV loaded but no usable rows: " + file.getName());
                return;
            }

            for (ScanItem parsed : report.items) {
                results.addItem(new ScanItem(
                        nextId.incrementAndGet(),
                        parsed.getType(),
                        parsed.getContent()));
            }

            input.showCsvFile(file.getName() + "  (" + report.items.size() + " rows added)");

            log.log("CSV loaded: " + file.getName()
                    + " | Rows: " + report.items.size()
                    + " | Skipped: " + report.errors.size());

            if (!report.errors.isEmpty()) {
                input.setError(
                        report.errors.size() + " row(s) skipped. First: " + report.errors.get(0),
                        true);
            }

        } catch (CsvFormatException ex) {

            input.setError("CSV format error: " + ex.getMessage(), false);
            log.log("CSV format error (" + file.getName() + "): " + ex.getMessage());

        } catch (RuntimeException ex) {

            input.setError("Cannot load CSV: " + ex.getMessage(), false);
            log.log("CSV loading failed: " + ex);
        }
    }

    // ================= ADD (one item) =================

    private ScanItem readTypedItem() throws InvalidInputException {

        InputPanel.Mode mode = input.getMode();

        if (mode == InputPanel.Mode.CSV) {
            throw new InvalidInputException("Use Browse CSV to load a file.");
        }

        String text = input.getText().trim();

        if (text.isEmpty()) {
            throw new InvalidInputException("Empty input: type a URL or a message first.");
        }

        InputType type = mode == InputPanel.Mode.URL ? InputType.URL : InputType.MESSAGE;

        return new ScanItem(nextId.incrementAndGet(), type, text);
    }

    private void onAdd() {

        input.setError(null, false);

        try {

            ScanItem item = readTypedItem();

            results.addItem(item);
            input.clearField();

            log.log("Added #" + item.getId() + " (" + item.getType() + "): " + shorten(item.getContent()));

        } catch (InvalidInputException ex) {

            input.setError(ex.getMessage(), false);
            log.log("Rejected input: " + ex.getMessage());
        }
    }

    // ================= SCAN ALL =================

    /** Scans every row that is still Pending (typed text, if any, is added first). */
    private void onScan() {

        input.setError(null, false);

        try {

            if (input.getMode() != InputPanel.Mode.CSV && !input.getText().trim().isEmpty()) {
                ScanItem typed = readTypedItem();
                results.addItem(typed);
                input.clearField();
            }

            List<ScanItem> pending = results.pendingItems();

            if (pending.isEmpty()) {
                throw new InvalidInputException(
                        "Empty input: add a URL / message or load a CSV first.");
            }

            startScan(pending);

        } catch (InvalidInputException ex) {

            input.setError(ex.getMessage(), false);
            log.log("Rejected input: " + ex.getMessage());

        } catch (RuntimeException ex) {

            input.setError("Unexpected error: " + ex.getMessage(), false);
            log.log("Unexpected error: " + ex);
        }
    }

    // ================= SCAN ONE ROW =================

    private void onRowScan(ScanItem item) {

        results.resetRow(item);
        summary.update(results.counts());

        startScan(Collections.singletonList(item));
    }

    // ================= START SCAN =================

    private void startScan(List<ScanItem> items) {

        if (active == 0) {
            batchTotal = 0;
            batchDone = 0;
        }

        batchTotal += items.size();
        active += items.size();

        for (ScanItem item : items) {
            results.markQueued(item);
        }

        results.setBatchProgress(batchDone, batchTotal);

        input.setScanning(true);
        results.setClearEnabled(false);

        log.log("Scan started... (" + items.size() + (items.size() == 1 ? " item)" : " items)"));

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
                    active = 0;

                    input.setError(
                            "Scan failed: " + ex.getMessage(),
                            false
                    );

                    input.setScanning(false);
            results.setClearEnabled(true);
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
        active--;

        results.setBatchProgress(batchDone, batchTotal);
        summary.update(results.counts());

        log.log("Item #" + result.getItem().getId()
                + " completed: " + result.getLevel() + " risk");

        if (active <= 0) {

            active = 0;

            input.setScanning(false);
            results.setClearEnabled(true);

            log.log("Scan finished: " + batchDone + (batchDone == 1 ? " item." : " items."));
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

    // ================= ANIMATED BACKGROUND =================

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        Graphics2D g2 = Theme.aa(g);
        background.paint(g2, getWidth(), getHeight());
        g2.dispose();
    }

    @Override
    public void addNotify() {
        super.addNotify();
        background.start();
    }

    @Override
    public void removeNotify() {
        background.stop();
        super.removeNotify();
    }
}
