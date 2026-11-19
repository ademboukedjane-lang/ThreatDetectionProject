package threatdetector.ui;

import javax.swing.Icon;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Component;
import java.awt.GradientPaint;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.geom.Arc2D;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Path2D;
import java.awt.geom.RoundRectangle2D;

/** All icons are painted with Java2D so no image files are needed. */
public final class Icons {
    private Icons() {}

    /** Shield with a padlock or a check mark inside. */
    public static final class Shield implements Icon {
        private final int w, h;
        private final boolean lock;

        public Shield(int w, int h, boolean lock) {
            this.w = w;
            this.h = h;
            this.lock = lock;
        }

        @Override public int getIconWidth() { return w; }
        @Override public int getIconHeight() { return h; }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = Theme.aa(g);
            g2.translate(x, y);
            Path2D p = new Path2D.Double();
            p.moveTo(w / 2.0, 1);
            p.lineTo(w - 2, h * 0.14);
            p.lineTo(w - 2, h * 0.52);
            p.quadTo(w - 3, h * 0.84, w / 2.0, h - 1);
            p.quadTo(3, h * 0.84, 2, h * 0.52);
            p.lineTo(2, h * 0.14);
            p.closePath();
            g2.setPaint(new GradientPaint(0, 0, new Color(10, 60, 150), 0, h, new Color(5, 25, 80)));
            g2.fill(p);
            g2.setColor(Theme.ACCENT);
            g2.setStroke(new BasicStroke(Math.max(2f, w / 18f), BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.draw(p);
            g2.setColor(new Color(60, 170, 255));
            if (lock) {
                double bw = w * 0.38, bh = h * 0.26;
                double bx = (w - bw) / 2, by = h * 0.42;
                g2.fill(new RoundRectangle2D.Double(bx, by, bw, bh, 6, 6));
                g2.setStroke(new BasicStroke(w / 14f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                g2.draw(new Arc2D.Double(bx + bw * 0.15, by - bh * 0.7, bw * 0.7, bh * 1.1, 0, 180, Arc2D.OPEN));
                g2.setColor(new Color(5, 25, 80));
                g2.fill(new Ellipse2D.Double(w / 2.0 - 3, by + bh * 0.3, 6, 6));
            } else {
                g2.setStroke(new BasicStroke(w / 8f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                g2.draw(new java.awt.geom.Line2D.Double(w * 0.30, h * 0.46, w * 0.45, h * 0.60));
                g2.draw(new java.awt.geom.Line2D.Double(w * 0.45, h * 0.60, w * 0.72, h * 0.32));
            }
            g2.dispose();
        }
    }

    public enum Nav { HOME, HISTORY, SETTINGS, ABOUT }

    /** Small white icons for the sidebar buttons. */
    public static final class NavIcon implements Icon {
        private final Nav kind;

        public NavIcon(Nav kind) { this.kind = kind; }

        @Override public int getIconWidth() { return 26; }
        @Override public int getIconHeight() { return 26; }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = Theme.aa(g);
            g2.translate(x, y);
            g2.setColor(Color.WHITE);
            g2.setStroke(new BasicStroke(2.2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            switch (kind) {
                case HOME: {
                    Path2D roof = new Path2D.Double();
                    roof.moveTo(2, 13); roof.lineTo(13, 3); roof.lineTo(24, 13);
                    g2.draw(roof);
                    g2.fillRect(6, 13, 14, 10);
                    break;
                }
                case HISTORY:
                    g2.draw(new Ellipse2D.Double(3, 3, 20, 20));
                    g2.draw(new java.awt.geom.Line2D.Double(13, 7, 13, 13));
                    g2.draw(new java.awt.geom.Line2D.Double(13, 13, 18, 16));
                    break;
                case SETTINGS:
                    g2.draw(new Ellipse2D.Double(8, 8, 10, 10));
                    for (int i = 0; i < 8; i++) {
                        double a = Math.PI * i / 4;
                        g2.draw(new java.awt.geom.Line2D.Double(13 + Math.cos(a) * 8, 13 + Math.sin(a) * 8,
                                13 + Math.cos(a) * 11.5, 13 + Math.sin(a) * 11.5));
                    }
                    break;
                default:
                    g2.fill(new Ellipse2D.Double(2, 2, 22, 22));
                    g2.setColor(Theme.PANEL);
                    g2.fillOval(11, 6, 4, 4);
                    g2.fillRect(11, 11, 4, 8);
                    break;
            }
            g2.dispose();
        }
    }

    public static final class Magnifier implements Icon {
        @Override public int getIconWidth() { return 28; }
        @Override public int getIconHeight() { return 28; }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = Theme.aa(g);
            g2.translate(x, y);
            g2.setColor(Color.WHITE);
            g2.setStroke(new BasicStroke(3f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.draw(new Ellipse2D.Double(3, 3, 16, 16));
            g2.draw(new java.awt.geom.Line2D.Double(17, 17, 25, 25));
            g2.dispose();
        }
    }

    /** Round radio indicator that follows the button's selected state. */
    public static final class Radio implements Icon {
        @Override public int getIconWidth() { return 24; }
        @Override public int getIconHeight() { return 24; }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = Theme.aa(g);
            g2.translate(x, y);
            boolean sel = c instanceof javax.swing.AbstractButton && ((javax.swing.AbstractButton) c).isSelected();
            g2.setColor(Theme.ACCENT);
            g2.setStroke(new BasicStroke(2.2f));
            g2.draw(new Ellipse2D.Double(2, 2, 20, 20));
            if (sel) {
                g2.fill(new Ellipse2D.Double(7, 7, 10, 10));
            }
            g2.dispose();
        }
    }

    public static final class Dot implements Icon {
        private final Color color;

        public Dot(Color color) { this.color = color; }

        @Override public int getIconWidth() { return 14; }
        @Override public int getIconHeight() { return 14; }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = Theme.aa(g);
            g2.setColor(color);
            g2.fill(new Ellipse2D.Double(x + 1, y + 1, 12, 12));
            g2.dispose();
        }
    }
}

