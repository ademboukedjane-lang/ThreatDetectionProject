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

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

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
import javax.swing.AbstractAction;
import javax.swing.BoxLayout;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;

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

        File[] files = FileBrowser.choose(this, lastDir);

        if (files == null || files.length == 0) {
            return;   // cancelled
        }

        lastDir = files[0].getParentFile();

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

    // ================= FILE BROWSER (Windows 11 style) =================

    /**
     * File picker in the same dark style as the app, laid out like the Windows 11 Explorer:
     * back / up buttons, address bar, quick-access list, and a file list with date and size.
     * Only folders and .csv / .txt files are shown.
     */
    private static final class FileBrowser extends JDialog {

        private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("dd/MM/yyyy  HH:mm");
        private static final Icon FOLDER = new FolderIcon();
        private static final Icon SHEET = new SheetIcon();

        private final Model model = new Model();
        private final JTable table = new JTable(model);
        private final JTextField pathField = new JTextField();
        private final JLabel status = new JLabel(" ");
        private final GlowButton back = new GlowButton("\u2190", false);
        private final GlowButton up = new GlowButton("\u2191", false);
        private final GlowButton open = new GlowButton("Open", false);
        private final GlowButton cancel = new GlowButton("Cancel", false);
        private final Deque<File> history = new ArrayDeque<>();

        private File current;
        private File[] result;

        /** Shows the dialog and returns the chosen files, or null if cancelled. */
        public static File[] choose(Component parent, File startDir) {
            java.awt.Window owner = parent == null ? null : SwingUtilities.getWindowAncestor(parent);
            FileBrowser d = new FileBrowser(owner, startDir);
            d.setVisible(true);
            return d.result;
        }

        private FileBrowser(java.awt.Window owner, File startDir) {
            super(owner, "Open CSV file", Dialog.ModalityType.APPLICATION_MODAL);

            JPanel root = new JPanel(new BorderLayout(12, 12));
            root.setBackground(Theme.BG);
            root.setBorder(Theme.pad(14, 14, 14, 14));
            setContentPane(root);

            root.add(buildToolbar(), BorderLayout.NORTH);
            root.add(buildNav(), BorderLayout.WEST);
            root.add(buildList(), BorderLayout.CENTER);
            root.add(buildBottom(), BorderLayout.SOUTH);

            getRootPane().registerKeyboardAction(e -> dispose(),
                    KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_IN_FOCUSED_WINDOW);

            setSize(920, 580);
            setMinimumSize(new Dimension(700, 440));
            setLocationRelativeTo(owner);

            File start = startDir != null && startDir.isDirectory()
                    ? startDir
                    : firstExisting(new File(home(), "Downloads"), new File(home()));
            go(start, false);
        }

        // ---------------------------------------------------------------- layout

        private JPanel buildToolbar() {
            back.setPreferredSize(new Dimension(46, 40));
            up.setPreferredSize(new Dimension(46, 40));
            back.addActionListener(e -> {
                if (!history.isEmpty()) go(history.pop(), false);
            });
            up.addActionListener(e -> {
                if (current != null && current.getParentFile() != null) go(current.getParentFile(), true);
            });

            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            buttons.setOpaque(false);
            buttons.add(back);
            buttons.add(up);

            pathField.setOpaque(false);
            pathField.setBorder(null);
            pathField.setForeground(Color.WHITE);
            pathField.setCaretColor(Color.WHITE);
            pathField.setSelectionColor(Theme.ACCENT);
            pathField.setFont(Theme.font(Font.PLAIN, 15));
            pathField.addActionListener(e -> openTypedPath());

            RoundedPanel box = new RoundedPanel(new BorderLayout(), Theme.FIELD, Theme.BORDER, 14);
            box.setBorder(Theme.pad(0, 14, 0, 14));
            box.setPreferredSize(new Dimension(100, 40));
            box.add(pathField, BorderLayout.CENTER);

            JPanel bar = new JPanel(new BorderLayout(12, 0));
            bar.setOpaque(false);
            bar.add(buttons, BorderLayout.WEST);
            bar.add(box, BorderLayout.CENTER);
            return bar;
        }

        private RoundedPanel buildNav() {
            RoundedPanel nav = new RoundedPanel(new BorderLayout(), Theme.PANEL_DARK, Theme.BORDER, 14);
            nav.setPreferredSize(new Dimension(200, 0));
            nav.setBorder(Theme.pad(10, 8, 10, 8));

            JPanel list = new JPanel();
            list.setOpaque(false);
            list.setLayout(new BoxLayout(list, BoxLayout.Y_AXIS));

            list.add(heading("Quick access"));
            String home = home();
            addLink(list, "Home", new File(home));
            addLink(list, "Desktop", firstExisting(new File(home, "Desktop"), new File(home, "OneDrive/Desktop")));
            addLink(list, "Documents", firstExisting(new File(home, "Documents"), new File(home, "OneDrive/Documents")));
            addLink(list, "Downloads", new File(home, "Downloads"));

            list.add(heading("This PC"));
            File[] roots = File.listRoots();
            if (roots != null) {
                for (File r : roots) {
                    addLink(list, r.toString(), r);
                }
            }

            nav.add(list, BorderLayout.NORTH);
            return nav;
        }

        private JComponent buildList() {
            table.setBackground(Theme.PANEL_DARK);
            table.setForeground(Color.WHITE);
            table.setSelectionBackground(Theme.ROW_SEL);
            table.setSelectionForeground(Color.WHITE);
            table.setShowGrid(false);
            table.setIntercellSpacing(new Dimension(0, 0));
            table.setRowHeight(36);
            table.setFillsViewportHeight(true);
            table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
            table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
            table.setDefaultRenderer(Object.class, new CellRenderer());

            table.getColumnModel().getColumn(0).setPreferredWidth(420);
            table.getColumnModel().getColumn(1).setPreferredWidth(170);
            table.getColumnModel().getColumn(2).setPreferredWidth(90);

            JTableHeader header = table.getTableHeader();
            header.setReorderingAllowed(false);
            header.setPreferredSize(new Dimension(0, 36));
            header.setDefaultRenderer(new DefaultTableCellRenderer() {
                @Override
                public Component getTableCellRendererComponent(JTable t, Object v, boolean sel,
                                                               boolean focus, int row, int col) {
                    super.getTableCellRendererComponent(t, v, false, false, row, col);
                    setOpaque(true);
                    setBackground(Theme.PANEL);
                    setForeground(Theme.MUTED);
                    setFont(Theme.font(Font.BOLD, 13));
                    setBorder(Theme.pad(0, 10, 0, 10));
                    return this;
                }
            });

            table.getSelectionModel().addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) updateButtons();
            });
            table.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2 && table.rowAtPoint(e.getPoint()) >= 0) accept();
                }
            });
            table.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "accept");
            table.getActionMap().put("accept", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    FileBrowser.this.accept();
                }
            });

            JScrollPane scroll = new JScrollPane(table);
            Theme.styleScroll(scroll);
            scroll.setBorder(javax.swing.BorderFactory.createLineBorder(Theme.BORDER));
            return scroll;
        }

        private JPanel buildBottom() {
            status.setFont(Theme.font(Font.PLAIN, 13));
            status.setForeground(Theme.MUTED);

            open.setPreferredSize(new Dimension(120, 40));
            cancel.setPreferredSize(new Dimension(120, 40));
            open.setEnabled(false);
            open.addActionListener(e -> accept());
            cancel.addActionListener(e -> dispose());

            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
            buttons.setOpaque(false);
            buttons.add(open);
            buttons.add(cancel);

            JPanel bottom = new JPanel(new BorderLayout());
            bottom.setOpaque(false);
            bottom.add(status, BorderLayout.WEST);
            bottom.add(buttons, BorderLayout.EAST);
            return bottom;
        }

        private static JLabel heading(String text) {
            JLabel l = new JLabel(text);
            l.setFont(Theme.font(Font.BOLD, 12));
            l.setForeground(Theme.MUTED);
            l.setBorder(Theme.pad(8, 10, 4, 0));
            l.setAlignmentX(Component.LEFT_ALIGNMENT);
            return l;
        }

        private void addLink(JPanel list, String text, File target) {
            if (target == null || !target.isDirectory()) return;

            JButton b = new JButton(text, FOLDER);
            b.setContentAreaFilled(false);
            b.setBorderPainted(false);
            b.setFocusPainted(false);
            b.setHorizontalAlignment(SwingConstants.LEFT);
            b.setFont(Theme.font(Font.PLAIN, 15));
            b.setForeground(Color.WHITE);
            b.setIconTextGap(10);
            b.setBorder(Theme.pad(6, 10, 6, 10));
            b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            b.setAlignmentX(Component.LEFT_ALIGNMENT);
            b.setMaximumSize(new Dimension(Integer.MAX_VALUE, 36));
            b.addMouseListener(new MouseAdapter() {
                @Override public void mouseEntered(MouseEvent e) { b.setForeground(Theme.CYAN); }
                @Override public void mouseExited(MouseEvent e) { b.setForeground(Color.WHITE); }
            });
            b.addActionListener(e -> go(target, true));
            list.add(b);
        }

        // ---------------------------------------------------------------- logic

        private void go(File dir, boolean remember) {
            if (dir == null) return;

            if (!dir.isDirectory()) {
                showError("Folder not found");
                return;
            }

            File[] list = dir.listFiles(f -> !f.isHidden() && (f.isDirectory() || isCsv(f)));
            if (list == null) {
                showError("Access denied: " + dir.getAbsolutePath());
                return;
            }

            if (remember && current != null) history.push(current);
            current = dir;

            Arrays.sort(list, (a, b) -> {
                if (a.isDirectory() != b.isDirectory()) return a.isDirectory() ? -1 : 1;
                return a.getName().compareToIgnoreCase(b.getName());
            });

            model.set(Arrays.asList(list));
            pathField.setText(dir.getAbsolutePath());
            back.setEnabled(!history.isEmpty());
            up.setEnabled(dir.getParentFile() != null);
            updateButtons();
        }

        private void showError(String message) {
            status.setForeground(Theme.DANGER);
            status.setText(message);
        }

        private void updateButtons() {
            int[] rows = table.getSelectedRows();
            int files = 0;
            for (int r : rows) {
                if (!model.entries.get(r).isDirectory()) files++;
            }

            open.setEnabled(rows.length > 0);
            status.setForeground(Theme.MUTED);

            if (files > 0) {
                status.setText(files + (files == 1 ? " file selected" : " files selected"));
            } else {
                int n = model.getRowCount();
                status.setText(n + (n == 1 ? " item" : " items"));
            }
        }

        private void accept() {
            List<File> files = new ArrayList<>();
            File folder = null;

            for (int r : table.getSelectedRows()) {
                File f = model.entries.get(r);
                if (f.isDirectory()) folder = f;
                else files.add(f);
            }

            if (!files.isEmpty()) {
                result = files.toArray(new File[0]);
                dispose();
            } else if (folder != null) {
                go(folder, true);
            }
        }

        private void openTypedPath() {
            File f = new File(pathField.getText().trim());

            if (f.isDirectory()) {
                go(f, true);
            } else if (f.isFile()) {
                result = new File[] {f};
                dispose();
            } else {
                showError("Path not found");
            }
        }

        private static boolean isCsv(File f) {
            String n = f.getName().toLowerCase();
            return n.endsWith(".csv") || n.endsWith(".txt");
        }

        private static String home() {
            return System.getProperty("user.home", ".");
        }

        private static File firstExisting(File... candidates) {
            for (File f : candidates) {
                if (f != null && f.isDirectory()) return f;
            }
            return new File(home());
        }

        private static String size(File f) {
            if (f.isDirectory()) return "";
            long n = f.length();
            if (n < 1024) return n + " B";
            if (n < 1024 * 1024) return (n / 1024) + " KB";
            return String.format("%.1f MB", n / (1024.0 * 1024.0));
        }

        // ---------------------------------------------------------------- table

        private static final class Model extends AbstractTableModel {
            private final String[] cols = {"Name", "Date modified", "Size"};
            private List<File> entries = new ArrayList<>();

            void set(List<File> list) {
                entries = new ArrayList<>(list);
                fireTableDataChanged();
            }

            @Override public int getRowCount() { return entries.size(); }
            @Override public int getColumnCount() { return cols.length; }
            @Override public String getColumnName(int c) { return cols[c]; }

            @Override
            public Object getValueAt(int r, int c) {
                File f = entries.get(r);
                switch (c) {
                    case 0: return f.getName();
                    case 1: return DATE.format(Instant.ofEpochMilli(f.lastModified()).atZone(ZoneId.systemDefault()));
                    default: return size(f);
                }
            }
        }

        private final class CellRenderer extends DefaultTableCellRenderer {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object v, boolean sel,
                                                           boolean focus, int row, int col) {
                super.getTableCellRendererComponent(t, v, sel, false, row, col);
                File f = model.entries.get(row);

                setOpaque(true);
                setBorder(Theme.pad(0, 10, 0, 10));
                setFont(Theme.font(Font.PLAIN, 15));
                setForeground(col == 0 ? Color.WHITE : Theme.MUTED);
                setBackground(sel ? Theme.ROW_SEL : (row % 2 == 0 ? Theme.ROW_A : Theme.ROW_B));
                setIconTextGap(10);
                setIcon(col == 0 ? (f.isDirectory() ? FOLDER : SHEET) : null);
                return this;
            }
        }

        // ---------------------------------------------------------------- icons

        private static final class FolderIcon implements Icon {
            @Override public int getIconWidth() { return 24; }
            @Override public int getIconHeight() { return 20; }

            @Override
            public void paintIcon(Component c, Graphics g, int x, int y) {
                Graphics2D g2 = Theme.aa(g);
                g2.translate(x, y);
                g2.setColor(new Color(235, 175, 40));
                g2.fillRoundRect(0, 1, 10, 7, 3, 3);
                g2.setColor(new Color(255, 205, 70));
                g2.fillRoundRect(0, 4, 24, 15, 4, 4);
                g2.dispose();
            }
        }

        private static final class SheetIcon implements Icon {
            @Override public int getIconWidth() { return 24; }
            @Override public int getIconHeight() { return 20; }

            @Override
            public void paintIcon(Component c, Graphics g, int x, int y) {
                Graphics2D g2 = Theme.aa(g);
                g2.translate(x, y);
                g2.setColor(new Color(34, 160, 100));
                g2.fillRoundRect(4, 0, 16, 20, 4, 4);
                g2.setColor(Color.WHITE);
                g2.fillRect(8, 5, 8, 2);
                g2.fillRect(8, 9, 8, 2);
                g2.fillRect(8, 13, 8, 2);
                g2.dispose();
            }
        }
    }
}
