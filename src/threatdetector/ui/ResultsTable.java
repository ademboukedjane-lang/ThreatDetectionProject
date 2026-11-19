package threatdetector.ui;

import threatdetector.model.InputType;
import threatdetector.model.RiskLevel;
import threatdetector.model.ScanItem;
import threatdetector.model.ScanResult;
import threatdetector.model.ScanStatus;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * "Scan Results" card. Columns: # | Input | Type | Risk Level | Status | Reasons.
 * The Status column shows a progress bar while an item is being analysed.
 * All methods must be called on the Swing thread.
 */
public class ResultsTable extends RoundedPanel {

    private static final String[] COLUMNS = {"#", "Input", "Type", "Risk Level", "Status", "Reasons"};

    private final Model model = new Model();
    private final JTable table;
    private final JLabel counter = new JLabel("0 / 0");
    private final GlobalBar globalBar = new GlobalBar();
    private final GlowButton clearButton = new GlowButton("Clear", false);

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
        add(head, BorderLayout.NORTH);

        table = new JTable(model) {
            @Override
            public String getToolTipText(MouseEvent e) {
                int r = rowAtPoint(e.getPoint());
                int c = columnAtPoint(e.getPoint());
                if (r < 0 || (c != 1 && c != 5)) return null;
                String text = c == 1 ? model.rows.get(r).item.getContent() : reasonText(model.rows.get(r));
                return "<html><body style='width:320px'>" + escape(text) + "</body></html>";
            }
        };
        table.setRowHeight(42);
        table.setShowGrid(false);
        table.setIntercellSpacing(new Dimension(0, 0));
        table.setFillsViewportHeight(true);
        table.setBackground(Theme.PANEL_DARK);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFocusable(false);
        table.setDefaultRenderer(Object.class, new CellRenderer());
        table.getTableHeader().setDefaultRenderer(new HeaderRenderer());
        table.getTableHeader().setReorderingAllowed(false);
        table.getTableHeader().setPreferredSize(new Dimension(0, 38));
        int[] widths = {44, 270, 100, 140, 150, 380};
        for (int i = 0; i < widths.length; i++) {
            TableColumn col = table.getColumnModel().getColumn(i);
            col.setPreferredWidth(widths[i]);
        }
        table.getColumnModel().getColumn(0).setMaxWidth(60);

        JScrollPane scroll = new JScrollPane(table,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setColumnHeaderView(table.getTableHeader());
        Theme.styleScroll(scroll);
        scroll.setBorder(javax.swing.BorderFactory.createLineBorder(Theme.BORDER));
        add(scroll, BorderLayout.CENTER);
    }

    // ---- API used by MainPanel ------------------------------------------------

    public void addItem(ScanItem item) {
        Row row = new Row(item);
        model.index.put(item.getId(), model.rows.size());
        model.rows.add(row);
        int last = model.rows.size() - 1;
        model.fireTableRowsInserted(last, last);
        table.scrollRectToVisible(table.getCellRect(last, 0, true));
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
        r.progress = percent;
        refresh(item);
    }

    public void updateResult(ScanResult result) {
        Row r = find(result.getItem());
        if (r == null) return;
        r.result = result;
        r.status = result.getStatus();
        r.progress = 100;
        refresh(result.getItem());
    }

    public void clear() {
        model.rows.clear();
        model.index.clear();
        model.fireTableDataChanged();
        setBatchProgress(0, 0);
    }

    /** counts = {low, medium, high, notVerified} among finished rows. */
    public int[] counts() {
        int[] c = new int[4];
        for (Row r : model.rows) {
            if (r.result == null) continue;
            switch (r.result.getLevel()) {
                case LOW: c[0]++; break;
                case MEDIUM: c[1]++; break;
                case HIGH: c[2]++; break;
                default: c[3]++; break;
            }
        }
        return c;
    }

    public int rowCount() { return model.rows.size(); }

    public void setBatchProgress(int done, int total) {
        counter.setText(done + " / " + total);
        globalBar.setValue(total == 0 ? 0 : done * 100 / total);
    }

    // ---- internals ------------------------------------------------------------

    private Row find(ScanItem item) {
        Integer i = model.index.get(item.getId());
        return i == null ? null : model.rows.get(i);
    }

    private void refresh(ScanItem item) {
        Integer i = model.index.get(item.getId());
        if (i != null) model.fireTableRowsUpdated(i, i);
    }

    private static String reasonText(Row r) {
        if (r.result != null) return String.join(" ", r.result.getReasons());
        return r.status == ScanStatus.RUNNING ? "Analyzing..." : "Waiting...";
    }

    private static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static final class Row {
        final ScanItem item;
        ScanResult result;
        ScanStatus status = ScanStatus.PENDING;
        int progress;

        Row(ScanItem item) { this.item = item; }
    }

    private static final class Model extends AbstractTableModel {
        final List<Row> rows = new ArrayList<>();
        final Map<Integer, Integer> index = new HashMap<>();

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int c) { return COLUMNS[c]; }
        @Override public Object getValueAt(int r, int c) { return rows.get(r); }
    }

    // ---- rendering ------------------------------------------------------------

    private static final class HeaderRenderer extends DefaultTableCellRenderer {
        HeaderRenderer() {
            setHorizontalAlignment(SwingConstants.CENTER);
            setOpaque(true);
        }

        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
            super.getTableCellRendererComponent(t, v, s, f, r, c);
            setBackground(new Color(12, 40, 100));
            setForeground(Color.WHITE);
            setFont(Theme.font(Font.BOLD, 15));
            setHorizontalAlignment(c == 1 || c == 5 ? SwingConstants.LEFT : SwingConstants.CENTER);
            setBorder(javax.swing.BorderFactory.createCompoundBorder(
                    javax.swing.BorderFactory.createMatteBorder(0, 0, 1, 1, Theme.BORDER), Theme.pad(0, 10, 0, 6)));
            return this;
        }
    }

    private static final class CellRenderer implements TableCellRenderer {
        private final DefaultTableCellRenderer text = new DefaultTableCellRenderer();
        private final PillCell pill = new PillCell();
        private final StatusCell status = new StatusCell();

        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int row, int col) {
            Row r = (Row) v;
            Color bg = sel ? Theme.ROW_SEL : (row % 2 == 0 ? Theme.ROW_A : Theme.ROW_B);
            if (col == 3) {
                RiskLevel level = r.result == null ? null : r.result.getLevel();
                pill.set(bg, level);
                return pill;
            }
            if (col == 4) {
                status.set(bg, r.status, r.progress);
                return status;
            }
            String s;
            Color fg = Theme.TEXT;
            int align = SwingConstants.LEFT;
            switch (col) {
                case 0: s = String.valueOf(r.item.getId()); align = SwingConstants.CENTER; break;
                case 1: s = r.item.getContent(); break;
                case 2:
                    s = r.item.getType() == InputType.URL ? "URL" : "MESSAGE";
                    fg = new Color(120, 190, 255);
                    align = SwingConstants.CENTER;
                    break;
                default:
                    s = reasonText(r);
                    if (r.result == null) fg = Theme.MUTED;
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

    /** Base for cells we paint ourselves. */
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

    /** Colored rounded badge: LOW / MEDIUM / HIGH / NOT_VERIFIED. */
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
                g2.drawString("-", (getWidth() - fm.stringWidth("-")) / 2, (getHeight() + fm.getAscent()) / 2 - 2);
                return;
            }
            Color c = Theme.riskColor(level);
            g2.setFont(Theme.font(Font.BOLD, 14));
            FontMetrics fm = g2.getFontMetrics();
            String label = level.name();
            int w = fm.stringWidth(label) + 32, h = 28;
            int x = (getWidth() - w) / 2, y = (getHeight() - h) / 2;
            g2.setColor(new Color(c.getRed(), c.getGreen(), c.getBlue(), 55));
            g2.fillRoundRect(x, y, w, h, h, h);
            g2.setColor(c);
            g2.setStroke(new BasicStroke(1.5f));
            g2.drawRoundRect(x, y, w, h, h, h);
            g2.setColor(Color.WHITE);
            g2.drawString(label, x + (w - fm.stringWidth(label)) / 2, y + (h + fm.getAscent()) / 2 - 2);
        }
    }

    /** Pending text, running progress bar, or Done / Failed marker. */
    private static final class StatusCell extends CellBase {
        private ScanStatus status = ScanStatus.PENDING;
        private int progress;

        void set(Color bg, ScanStatus status, int progress) {
            this.bg = bg;
            this.status = status;
            this.progress = progress;
        }

        @Override
        void paintCell(Graphics2D g2) {
            int w = getWidth(), h = getHeight();
            g2.setFont(Theme.font(Font.BOLD, 15));
            FontMetrics fm = g2.getFontMetrics();
            switch (status) {
                case RUNNING: {
                    int barW = w - 70;
                    Theme.paintBar(g2, 14, (h - 10) / 2, barW, 10, progress);
                    g2.setColor(Theme.MUTED);
                    g2.setFont(Theme.font(Font.PLAIN, 13));
                    g2.drawString(progress + "%", 14 + barW + 8, (h + g2.getFontMetrics().getAscent()) / 2 - 2);
                    break;
                }
                case DONE:
                case FAILED: {
                    boolean ok = status == ScanStatus.DONE;
                    Color c = ok ? Theme.OK : Theme.DANGER;
                    String label = ok ? "Done" : "Failed";
                    int d = 20;
                    int x = (w - (d + 8 + fm.stringWidth(label))) / 2, y = (h - d) / 2;
                    g2.setColor(c);
                    g2.fillOval(x, y, d, d);
                    g2.setColor(new Color(4, 20, 40));
                    g2.setStroke(new BasicStroke(2.2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                    if (ok) {
                        g2.drawLine(x + 5, y + 10, x + 9, y + 14);
                        g2.drawLine(x + 9, y + 14, x + 15, y + 6);
                    } else {
                        g2.drawLine(x + 6, y + 6, x + 14, y + 14);
                        g2.drawLine(x + 14, y + 6, x + 6, y + 14);
                    }
                    g2.setColor(c);
                    g2.drawString(label, x + d + 8, (h + fm.getAscent()) / 2 - 2);
                    break;
                }
                default: {
                    g2.setColor(Theme.MUTED);
                    g2.setFont(Theme.font(Font.PLAIN, 15));
                    fm = g2.getFontMetrics();
                    String label = "Pending";
                    g2.drawString(label, (w - fm.stringWidth(label)) / 2, (h + fm.getAscent()) / 2 - 2);
                }
            }
        }
    }

    /** Thin overall progress bar in the card header. */
    private static final class GlobalBar extends JComponent {
        private int value;

        GlobalBar() { setPreferredSize(new Dimension(170, 14)); }

        void setValue(int v) {
            value = v;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = Theme.aa(g);
            Theme.paintBar(g2, 0, 2, getWidth(), 10, value);
            g2.dispose();
        }
    }
}
