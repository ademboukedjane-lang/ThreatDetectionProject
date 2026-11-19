package threatdetector.ui;

import threatdetector.model.RiskLevel;

import javax.swing.JButton;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.border.Border;
import javax.swing.plaf.basic.BasicScrollBarUI;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.Rectangle;

/** Colors, fonts and small painting helpers shared by all UI classes. */
public final class Theme {
    private Theme() {}

    public static final Color BG = new Color(4, 12, 36);
    public static final Color PANEL = new Color(9, 27, 70);
    public static final Color PANEL_DARK = new Color(6, 19, 54);
    public static final Color FIELD = new Color(5, 16, 48);
    public static final Color ROW_A = new Color(7, 22, 60);
    public static final Color ROW_B = new Color(10, 30, 78);
    public static final Color ROW_SEL = new Color(22, 62, 140);
    public static final Color BORDER = new Color(28, 86, 196);
    public static final Color ACCENT = new Color(30, 144, 255);
    public static final Color CYAN = new Color(34, 211, 238);
    public static final Color TEXT = Color.WHITE;
    public static final Color MUTED = new Color(150, 172, 215);
    public static final Color OK = new Color(34, 197, 94);
    public static final Color WARN = new Color(245, 158, 11);
    public static final Color DANGER = new Color(239, 68, 68);
    public static final Color UNKNOWN = new Color(148, 163, 184);

    public static Color riskColor(RiskLevel level) {
        switch (level) {
            case LOW: return OK;
            case MEDIUM: return WARN;
            case HIGH: return DANGER;
            default: return UNKNOWN;
        }
    }

    public static Font font(int style, int size) {
        return new Font("Segoe UI", style, size);
    }

    public static Graphics2D aa(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
        return g2;
    }

    /** Horizontal progress bar drawn by hand (used by the table and the global bar). */
    public static void paintBar(Graphics2D g, int x, int y, int w, int h, int percent) {
        g.setColor(new Color(20, 45, 100));
        g.fillRoundRect(x, y, w, h, h, h);
        int fill = Math.max(0, Math.min(100, percent)) * w / 100;
        if (fill > 0) {
            g.setColor(ACCENT);
            g.fillRoundRect(x, y, Math.max(fill, h), h, h, h);
        }
    }

    public static void styleScroll(JScrollPane sp) {
        sp.setBorder(null);
        sp.getViewport().setBackground(PANEL_DARK);
        sp.setBackground(PANEL_DARK);
        sp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        sp.getVerticalScrollBar().setPreferredSize(new Dimension(10, 0));
        sp.getHorizontalScrollBar().setUI(new DarkScrollBarUI());
        sp.getHorizontalScrollBar().setPreferredSize(new Dimension(0, 10));
    }

    private static final class DarkScrollBarUI extends BasicScrollBarUI {
        @Override
        protected void configureScrollBarColors() {
            super.configureScrollBarColors();
            thumbColor = new Color(40, 90, 190);
            trackColor = PANEL_DARK;
        }

        @Override
        protected JButton createDecreaseButton(int orientation) { return zeroButton(); }

        @Override
        protected JButton createIncreaseButton(int orientation) { return zeroButton(); }

        private JButton zeroButton() {
            JButton b = new JButton();
            b.setPreferredSize(new Dimension(0, 0));
            return b;
        }

        @Override
        protected void paintTrack(Graphics g, javax.swing.JComponent c, Rectangle r) {
            g.setColor(trackColor);
            g.fillRect(r.x, r.y, r.width, r.height);
        }

        @Override
        protected void paintThumb(Graphics g, javax.swing.JComponent c, Rectangle r) {
            Graphics2D g2 = aa(g);
            g2.setColor(thumbColor);
            g2.fillRoundRect(r.x + 1, r.y + 1, r.width - 2, r.height - 2, 8, 8);
            g2.dispose();
        }
    }

    public static Border pad(int t, int l, int b, int r) {
        return javax.swing.BorderFactory.createEmptyBorder(t, l, b, r);
    }
}

