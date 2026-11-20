package threatdetector.ui;

import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import javax.swing.ButtonGroup;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JToggleButton;
import javax.swing.RowFilter;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import threatdetector.model.InputType;
import threatdetector.model.RiskLevel;
import threatdetector.model.ScanItem;
import threatdetector.model.ScanResult;
import threatdetector.model.ScanStatus;

public class ResultsTable extends RoundedPanel {

    private static final String[] COLUMNS = {
        "#", "Input", "Type", "Risk Level", "Status", "Reasons", "Action"
    };

    private static final int ACTION_COL = 6;

    private final Model model = new Model();
    private final JTable table;
    private final JLabel counter = new JLabel("0 / 0");
    private final GlobalBar globalBar = new GlobalBar();
    private final GlowButton clearButton = new GlowButton("Clear", false);

    private TableRowSorter<Model> sorter;
    private RiskLevel filterLevel = null;   // null = show all
    private Chip[] chips;
    private Runnable clearListener = () -> {};
    private Consumer<ScanItem> rowScanListener = i -> {};

    public ResultsTable() {
        super(new BorderLayout(0, 8), Theme.PANEL, Theme.BORDER, 18);

        setBorder(Theme.pad(10, 12, 12, 12));

        JLabel title = new JLabel("Scan Results");
        title.setFont(Theme.font(Font.BOLD, 20));
        title.setForeground(Theme.TEXT);

        counter.setFont(Theme.font(Font.PLAIN, 14));
        counter.setForeground(Theme.MUTED);

        clearButton.setFont(Theme.font(Font.BOLD, 13));
        clearButton.setPreferredSize(new Dimension(80, 30));
        clearButton.addActionListener(e -> clear());

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        right.setOpaque(false);
        right.add(counter);
        right.add(globalBar);
        right.add(clearButton);

        JPanel head = new JPanel(new BorderLayout());
        head.setOpaque(false);
        head.add(title, BorderLayout.WEST);
        head.add(right, BorderLayout.EAST);
        JPanel top = new JPanel(new BorderLayout(0, 8));
        top.setOpaque(false);
        top.add(head, BorderLayout.NORTH);
        top.add(buildFilters(), BorderLayout.CENTER);
        add(top, BorderLayout.NORTH);

        table = new JTable(model) {
            @Override
            public String getToolTipText(MouseEvent e) {
                int r = rowAtPoint(e.getPoint());
                int c = columnAtPoint(e.getPoint());

                if (r < 0 || (c != 1 && c != 5)) {
                    return null;
                }

                Row row = model.rows.get(convertRowIndexToModel(r));

                String text = c == 1
                        ? row.item.getContent()
                        : reasonText(row);

                return "<html><body style='width:320px'>"
                        + escape(text)
                        + "</body></html>";
            }
        };

        table.setRowHeight(42);
        table.setShowGrid(false);
        table.setIntercellSpacing(new Dimension(0, 0));
        table.setFillsViewportHeight(true);
        table.setBackground(Theme.PANEL_DARK);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFocusable(false);

        sorter = new TableRowSorter<>(model);
        for (int i = 0; i < COLUMNS.length; i++) {
            sorter.setSortable(i, false);   // filtering only, no sorting
        }
        sorter.setSortsOnUpdates(true);     // re-filter when a result arrives
        table.setRowSorter(sorter);

        // click on the "Scan" button of a row
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int vr = table.rowAtPoint(e.getPoint());
                int vc = table.columnAtPoint(e.getPoint());
                if (vr < 0 || vc != ACTION_COL) return;

                Row r = model.rows.get(table.convertRowIndexToModel(vr));
                if (r.queued || r.status == ScanStatus.RUNNING) return;

                rowScanListener.accept(r.item);
            }
        });
        table.addMouseMotionListener(new MouseAdapter() {
            @Override
            public void mouseMoved(MouseEvent e) {
                int vc = table.columnAtPoint(e.getPoint());
                table.setCursor(Cursor.getPredefinedCursor(
                        vc == ACTION_COL ? Cursor.HAND_CURSOR : Cursor.DEFAULT_CURSOR));
            }
        });

        table.setDefaultRenderer(Object.class, new CellRenderer());
        table.getTableHeader().setDefaultRenderer(new HeaderRenderer());
        table.getTableHeader().setReorderingAllowed(false);
        table.getTableHeader().setPreferredSize(new Dimension(0, 38));

        int[] widths = {44, 250, 90, 165, 140, 300, 96};

        for (int i = 0; i < widths.length; i++) {
            TableColumn col = table.getColumnModel().getColumn(i);
            col.setPreferredWidth(widths[i]);
        }

        table.getColumnModel().getColumn(0).setMaxWidth(60);
        JScrollPane scroll = new JScrollPane(
                table,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
        );

        scroll.setColumnHeaderView(table.getTableHeader());
        Theme.styleScroll(scroll);
        scroll.setBorder(javax.swing.BorderFactory.createLineBorder(Theme.BORDER));

        add(scroll, BorderLayout.CENTER);

        updateChipCounts();
    }

    // ================= API =================

    public void addItem(ScanItem item) {
        if (item == null) return;

        Row row = new Row(item);

        model.index.put(item.getId(), model.rows.size());
        model.rows.add(row);

        int last = model.rows.size() - 1;
        model.fireTableRowsInserted(last, last);

        int viewRow = table.convertRowIndexToView(last);
        if (viewRow >= 0) {
            table.scrollRectToVisible(table.getCellRect(viewRow, 0, true));
        }
        updateChipCounts();
    }

    public void markRunning(ScanItem item) {
        Row r = find(item);
        if (r == null) return;

        r.status = ScanStatus.RUNNING;
        refresh(item);
    }

    public void updateProgress(ScanItem item, int percent) {
        Row r = find(item);
        if (r == null) return;

        r.status = ScanStatus.RUNNING;
        r.progress = Math.max(0, Math.min(100, percent));

        refresh(item);
    }

    public void updateResult(ScanResult result) {
        if (result == null || result.getItem() == null) return;

        Row r = find(result.getItem());
        if (r == null) return;

        r.result = result;
        r.queued = false;
        r.status = result.getStatus();
        r.progress = 100;

        refresh(result.getItem());
        updateChipCounts();
    }

    public void onRowScan(Consumer<ScanItem> c) {
        rowScanListener = c == null ? i -> {} : c;
    }

    /** Rows that were added but never scanned. */
    public List<ScanItem> pendingItems() {
        List<ScanItem> list = new ArrayList<>();
        for (Row r : model.rows) {
            if (r.result == null && !r.queued && r.status == ScanStatus.PENDING) {
                list.add(r.item);
            }
        }
        return list;
    }

    public void markQueued(ScanItem item) {
        Row r = find(item);
        if (r == null) return;

        r.queued = true;
        refresh(item);
    }

    /** Puts a finished row back to "Pending" so it can be scanned again. */
    public void resetRow(ScanItem item) {
        Row r = find(item);
        if (r == null) return;

        r.result = null;
        r.status = ScanStatus.PENDING;
        r.progress = 0;
        r.queued = false;

        refresh(item);
        updateChipCounts();
    }

    public void clear() {
        model.rows.clear();
        model.index.clear();

        model.fireTableDataChanged();
        setBatchProgress(0, 0);

        filterLevel = null;
        applyFilter();
        if (chips != null) {
            chips[0].setSelected(true);
        }
        updateChipCounts();
        clearListener.run();
    }

    public void onClear(Runnable r) {
        clearListener = r == null ? () -> {} : r;
    }

    public void setClearEnabled(boolean enabled) {
        clearButton.setEnabled(enabled);
    }

    public int[] counts() {
        int[] c = new int[4];

        for (Row r : model.rows) {
            if (r.result == null) continue;

            switch (r.result.getLevel()) {
                case LOW:
                    c[0]++;
                    break;

                case MEDIUM:
                    c[1]++;
                    break;

                case HIGH:
                    c[2]++;
                    break;

                default:
                    c[3]++;
                    break;
            }
        }

        return c;
    }

    public int rowCount() {
        return model.rows.size();
    }

    public void setBatchProgress(int done, int total) {
        counter.setText(done + " / " + total);

        int value = total <= 0
                ? 0
                : Math.max(0, Math.min(100, done * 100 / total));

        globalBar.setValue(value);
    }

    // ================= FILTER =================

    private JPanel buildFilters() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        p.setOpaque(false);

        JLabel label = new JLabel("Filter:");
        label.setFont(Theme.font(Font.PLAIN, 14));
        label.setForeground(Theme.MUTED);
        p.add(label);

        chips = new Chip[] {
            new Chip("All", Theme.ACCENT, null),
            new Chip("Low", Theme.OK, RiskLevel.LOW),
            new Chip("Medium", Theme.WARN, RiskLevel.MEDIUM),
            new Chip("High", Theme.DANGER, RiskLevel.HIGH),
            new Chip("Not Verified", Theme.UNKNOWN, RiskLevel.NOT_VERIFIED)
        };

        ButtonGroup group = new ButtonGroup();
        for (Chip c : chips) {
            group.add(c);
            p.add(c);
        }
        chips[0].setSelected(true);

        return p;
    }

    private void applyFilter() {
        if (sorter == null) return;

        if (filterLevel == null) {
            sorter.setRowFilter(null);
            return;
        }

        final RiskLevel wanted = filterLevel;

        sorter.setRowFilter(new RowFilter<Model, Integer>() {
            @Override
            public boolean include(Entry<? extends Model, ? extends Integer> entry) {
                Row r = (Row) entry.getValue(0);
                return r.result != null && r.result.getLevel() == wanted;
            }
        });
    }

    private void updateChipCounts() {
        if (chips == null) return;

        int[] c = counts();

        chips[0].setCount(model.rows.size());
        chips[1].setCount(c[0]);
        chips[2].setCount(c[1]);
        chips[3].setCount(c[2]);
        chips[4].setCount(c[3]);
    }

    private final class Chip extends JToggleButton {

        private final String name;
        private final Color color;

        Chip(String name, Color color, RiskLevel level) {
            super(name);
            this.name = name;
            this.color = color;

            setContentAreaFilled(false);
            setBorderPainted(false);
            setFocusPainted(false);
            setFont(Theme.font(Font.BOLD, 13));
            setForeground(Color.WHITE);
            setBorder(Theme.pad(5, 14, 5, 14));
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

            addActionListener(e -> {
                filterLevel = level;
                applyFilter();
            });
        }

        void setCount(int n) {
            setText(name + "  " + n);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = Theme.aa(g);
            int w = getWidth() - 1, h = getHeight() - 1;

            if (isSelected()) {
                g2.setColor(new Color(color.getRed(), color.getGreen(), color.getBlue(), 90));
            } else {
                g2.setColor(new Color(10, 36, 90));
            }
            g2.fillRoundRect(0, 0, w, h, h, h);

            g2.setColor(isSelected() ? color : Theme.BORDER);
            g2.drawRoundRect(0, 0, w, h, h, h);

            g2.dispose();
            super.paintComponent(g);
        }
    }

    // ================= INTERNALS =================

    private Row find(ScanItem item) {
        if (item == null) return null;

        Integer i = model.index.get(item.getId());

        return i == null ? null : model.rows.get(i);
    }

    private void refresh(ScanItem item) {
        Integer i = model.index.get(item.getId());

        if (i != null) {
            model.fireTableRowsUpdated(i, i);
        }
    }

    private static String reasonText(Row r) {
        if (r.result != null && r.result.getReasons() != null) {
            return String.join(" ", r.result.getReasons());
        }

        return r.status == ScanStatus.RUNNING
                ? "Analyzing..."
                : "Waiting...";
    }

    private static String escape(String s) {
        if (s == null) return "";

        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    // ================= ROW =================

    private static final class Row {
        final ScanItem item;

        ScanResult result;
        ScanStatus status = ScanStatus.PENDING;
        boolean queued;
        int progress;

        Row(ScanItem item) {
            this.item = item;
        }
    }

    // ================= TABLE MODEL =================

    private static final class Model extends AbstractTableModel {
    	final List<Row> rows = new ArrayList<>();
        final Map<Integer, Integer> index = new HashMap<>();

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int c) {
            return COLUMNS[c];
        }

        @Override
        public Object getValueAt(int r, int c) {
            return rows.get(r);
        }

        @Override
        public boolean isCellEditable(int r, int c) {
            return false;
        }
    }

    // ================= HEADER RENDERER =================

    private static final class HeaderRenderer
            extends DefaultTableCellRenderer {

        HeaderRenderer() {
            setHorizontalAlignment(SwingConstants.CENTER);
            setOpaque(true);
        }

        @Override
        public Component getTableCellRendererComponent(
                JTable t, Object v,
                boolean s, boolean f, int r, int c) {

            super.getTableCellRendererComponent(
                    t, v, s, f, r, c
            );

            setBackground(new Color(12, 40, 100));
            setForeground(Color.WHITE);
            setFont(Theme.font(Font.BOLD, 15));

            setHorizontalAlignment(
                    c == 1 || c == 5
                    ? SwingConstants.LEFT
                    : SwingConstants.CENTER
            );

            setBorder(
                    javax.swing.BorderFactory.createCompoundBorder(
                            javax.swing.BorderFactory.createMatteBorder(
                                    0, 0, 1, 1, Theme.BORDER
                            ),
                            Theme.pad(0, 10, 0, 6)
                    )
            );

            return this;
        }
    }

    // ================= CELL RENDERER =================

    private static final class CellRenderer
            implements TableCellRenderer {

        private final DefaultTableCellRenderer text =
                new DefaultTableCellRenderer();

        private final PillCell pill = new PillCell();
        private final StatusCell status = new StatusCell();
        private final ActionCell action = new ActionCell();

        @Override
        public Component getTableCellRendererComponent(
                JTable t, Object v,
                boolean sel, boolean focus,
                int row, int col) {

            Row r = (Row) v;

            Color bg = sel
                    ? Theme.ROW_SEL
                    : (row % 2 == 0 ? Theme.ROW_A : Theme.ROW_B);

            // Risk column
            if (col == 3) {
                RiskLevel level =
                        r.result == null
                        ? null
                        : r.result.getLevel();

                pill.set(bg, level);
                return pill;
            }

            // Action column
            if (col == ACTION_COL) {
                action.set(bg, r);
                return action;
            }

            // Status column
            if (col == 4) {
                status.set(bg, r.status, r.progress);
                return status;
            }

            String s;
            Color fg = Theme.TEXT;
            int align = SwingConstants.LEFT;

            switch (col) {
                case 0:
                    s = String.valueOf(r.item.getId());
                    align = SwingConstants.CENTER;
                    break;

                case 1:
                    s = r.item.getContent();
                    break;

                case 2:
                    s = r.item.getType() == InputType.URL
                            ? "URL"
                            : "MESSAGE";

                    fg = new Color(120, 190, 255);
                    align = SwingConstants.CENTER;
                    break;

                default:
                    s = reasonText(r);

                    if (r.result == null) {
                        fg = Theme.MUTED;
                    }
                    break;
            }
            text.setText(s);
            text.setOpaque(true);
            text.setBackground(bg);
            text.setForeground(fg);
            text.setFont(Theme.font(Font.PLAIN, 15));
            text.setHorizontalAlignment(align);
            text.setBorder(Theme.pad(0, 10, 0, 6));

            return text;
        }
    }

    // ================= CELL BASE =================

    private abstract static class CellBase extends JComponent {

        Color bg = Theme.ROW_A;

        @Override
        protected void paintComponent(Graphics g) {
            g.setColor(bg);
            g.fillRect(0, 0, getWidth(), getHeight());

            Graphics2D g2 = Theme.aa(g);

            paintCell(g2);

            g2.dispose();
        }

        abstract void paintCell(Graphics2D g2);
    }

    // ================= RISK CELL =================

    private static final class PillCell extends CellBase {

        private RiskLevel level;

        void set(Color bg, RiskLevel level) {
            this.bg = bg;
            this.level = level;
        }

        @Override
        void paintCell(Graphics2D g2) {
            if (level == null) {
                g2.setColor(Theme.MUTED);
                g2.setFont(Theme.font(Font.PLAIN, 15));

                FontMetrics fm = g2.getFontMetrics();

                g2.drawString(
                        "-",
                        (getWidth() - fm.stringWidth("-")) / 2,
                        (getHeight() + fm.getAscent()) / 2 - 2
                );

                return;
            }

            Color c = Theme.riskColor(level);

            g2.setFont(Theme.font(Font.BOLD, 14));

            FontMetrics fm = g2.getFontMetrics();

            String label = level.name().replace('_', ' ');

            int w = fm.stringWidth(label) + 32;
            int h = 28;

            int x = (getWidth() - w) / 2;
            int y = (getHeight() - h) / 2;

            g2.setColor(
                    new Color(
                            c.getRed(),
                            c.getGreen(),
                            c.getBlue(),
                            55
                    )
            );

            g2.fillRoundRect(x, y, w, h, h, h);

            g2.setColor(c);
            g2.setStroke(new BasicStroke(1.5f));

            g2.drawRoundRect(x, y, w, h, h, h);

            g2.setColor(Color.WHITE);

            g2.drawString(
                    label,
                    x + (w - fm.stringWidth(label)) / 2,
                    y + (h + fm.getAscent()) / 2 - 2
            );
        }
    }

    // ================= STATUS CELL =================

    private static final class StatusCell extends CellBase {

        private ScanStatus status = ScanStatus.PENDING;
        private int progress;

        void set(Color bg, ScanStatus status, int progress) {
            this.bg = bg;
            this.status = status;
            this.progress = Math.max(0, Math.min(100, progress));
        }

        @Override
        void paintCell(Graphics2D g2) {
            int w = getWidth();
            int h = getHeight();

            g2.setFont(Theme.font(Font.BOLD, 15));
            FontMetrics fm = g2.getFontMetrics();

            switch (status) {

                case RUNNING: {
                    int barW = Math.max(10, w - 70);

                    Theme.paintBar(
                            g2,
                            14,
                            (h - 10) / 2,
                            barW,
                            10,
                            progress
                    );

                    g2.setColor(Theme.MUTED);
                    g2.setFont(Theme.font(Font.PLAIN, 13));

                    g2.drawString(
                            progress + "%",
                            14 + barW + 8,
                            (h + g2.getFontMetrics().getAscent()) / 2 - 2
                    );

                    break;
                }

                case DONE:
                case FAILED: {
                    boolean ok = status == ScanStatus.DONE;
                    Color c = ok ? Theme.OK : Theme.DANGER;
                    String label = ok ? "Done" : "Failed";

                    int d = 20;

                    int x = (w - (d + 8 + fm.stringWidth(label))) / 2;
                    int y = (h - d) / 2;

                    g2.setColor(c);
                    g2.fillOval(x, y, d, d);

                    g2.setColor(new Color(4, 20, 40));

                    g2.setStroke(
                            new BasicStroke(
                                    2.2f,
                                    BasicStroke.CAP_ROUND,
                                    BasicStroke.JOIN_ROUND
                            )
                    );

                    if (ok) {
                        g2.drawLine(x + 5, y + 10, x + 9, y + 14);
                        g2.drawLine(x + 9, y + 14, x + 15, y + 6);
                    } else {
                        g2.drawLine(x + 6, y + 6, x + 14, y + 14);
                        g2.drawLine(x + 14, y + 6, x + 6, y + 14);
                    }

                    g2.setColor(c);

                    g2.drawString(
                            label,
                            x + d + 8,
                            (h + fm.getAscent()) / 2 - 2
                    );

                    break;
                }

                default: {
                    g2.setColor(Theme.MUTED);
                    g2.setFont(Theme.font(Font.PLAIN, 15));

                    fm = g2.getFontMetrics();

                    String label = "Pending";

                    g2.drawString(
                            label,
                            (w - fm.stringWidth(label)) / 2,
                            (h + fm.getAscent()) / 2 - 2
                    );
                }
            }
        }
    }

    // ================= ACTION CELL =================

    private static final class ActionCell extends CellBase {

        private String label = "Scan";
        private boolean enabled = true;

        void set(Color bg, Row r) {
            this.bg = bg;

            boolean busy = r.queued || r.status == ScanStatus.RUNNING;
            enabled = !busy;
            label = busy ? "..." : (r.result == null ? "Scan" : "Re-scan");
        }

        @Override
        void paintCell(Graphics2D g2) {
            int w = 78, h = 28;
            int x = (getWidth() - w) / 2;
            int y = (getHeight() - h) / 2;

            g2.setColor(enabled ? new Color(20, 110, 230) : new Color(30, 55, 100));
            g2.fillRoundRect(x, y, w, h, 14, 14);

            g2.setColor(enabled ? new Color(120, 190, 255) : Theme.BORDER);
            g2.drawRoundRect(x, y, w, h, 14, 14);

            g2.setFont(Theme.font(Font.BOLD, 13));
            FontMetrics fm = g2.getFontMetrics();

            g2.setColor(enabled ? Color.WHITE : Theme.MUTED);
            g2.drawString(label,
                    x + (w - fm.stringWidth(label)) / 2,
                    y + (h + fm.getAscent()) / 2 - 2);
        }
    }

    // ================= GLOBAL PROGRESS =================

    private static final class GlobalBar extends JComponent {

        private int value;

        GlobalBar() {
            setPreferredSize(new Dimension(170, 14));
        }

        void setValue(int v) {
            value = Math.max(0, Math.min(100, v));
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = Theme.aa(g);

            Theme.paintBar(
                    g2,
                    0,
                    2,
                    getWidth(),
                    10,
                    value
            );

            g2.dispose();
        }
    }
}
    