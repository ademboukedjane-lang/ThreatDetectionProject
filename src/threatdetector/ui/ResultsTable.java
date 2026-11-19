package threatdetector.ui;

import java.awt.*;
import java.util.*;
import javax.swing.*;
import javax.swing.table.*;
import threatdetector.model.*;

public class ResultsTable extends JScrollPane {
    private static final int COL_RISK = 2, COL_STATUS = 3, COL_PROGRESS = 4, COL_REASONS = 5;

    private final DefaultTableModel model = new DefaultTableModel(
            new String[]{"Input", "Type", "Risk", "Status", "Progress", "Reasons"}, 0) {
        @Override
        public boolean isCellEditable(int r, int c) { return false; }
    };
    private final JTable table = new JTable(model);
    private final Map<Integer, Integer> rowById = new HashMap<>();

    public ResultsTable() {
        setViewportView(table);
        table.setRowHeight(26);
        table.getColumnModel().getColumn(COL_RISK).setCellRenderer(new RiskRenderer());
        table.getColumnModel().getColumn(COL_PROGRESS).setCellRenderer(new ProgressRenderer());
        table.getColumnModel().getColumn(0).setPreferredWidth(280);
    }

    public void addItem(ScanItem item) {
        rowById.put(item.getId(), model.getRowCount());
        model.addRow(new Object[]{
                item.getContent(), item.getType(), "-", ScanStatus.PENDING, 0, ""});
    }

    public void markRunning(int id) {
        Integer row = rowById.get(id);
        if (row == null) return;
        model.setValueAt(ScanStatus.RUNNING, row, COL_STATUS);
        model.setValueAt(50, row, COL_PROGRESS);
    }

    public void updateResult(ScanResult r) {
        Integer row = rowById.get(r.getItem().getId());
        if (row == null) return;
        model.setValueAt(r.getLevel(), row, COL_RISK);
        model.setValueAt(r.getStatus(), row, COL_STATUS);
        model.setValueAt(100, row, COL_PROGRESS);
        model.setValueAt(String.join("; ", r.getReasons()), row, COL_REASONS);
    }

    public void clear() {
        model.setRowCount(0);
        rowById.clear();
    }

    private static class RiskRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object v,
                boolean sel, boolean foc, int r, int c) {
            super.getTableCellRendererComponent(t, v, sel, foc, r, c);
            setHorizontalAlignment(CENTER);
            setOpaque(true);
            Color bg = Color.WHITE;
            Color fg = Color.BLACK;
            switch (String.valueOf(v)) {
                case "LOW":          bg = new Color(46, 160, 67);   fg = Color.WHITE; break;
                case "MEDIUM":       bg = new Color(240, 140, 0);   fg = Color.WHITE; break;
                case "HIGH":         bg = new Color(200, 40, 40);   fg = Color.WHITE; break;
                case "NOT_VERIFIED": bg = new Color(130, 130, 130); fg = Color.WHITE; break;
                default: break;
            }
            setBackground(bg);
            setForeground(fg);
            return this;
        }
    }

    private static class ProgressRenderer extends JProgressBar implements TableCellRenderer {
        ProgressRenderer() {
            super(0, 100);
            setStringPainted(true);
        }

        @Override
        public Component getTableCellRendererComponent(JTable t, Object v,
                boolean sel, boolean foc, int r, int c) {
            int val = (v instanceof Integer) ? (Integer) v : 0;
            setValue(val);
            setString(val == 0 ? "Pending" : (val < 100 ? "Running..." : "Done"));
            return this;
        }
    }
}