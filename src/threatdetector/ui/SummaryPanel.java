package threatdetector.ui;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridLayout;
import java.awt.geom.Arc2D;

/** "Scan Summary" card: donut chart + legend with counts. */
public class SummaryPanel extends RoundedPanel {
    private static final String[] NAMES = {"Low", "Medium", "High", "Not Verified"};
    private static final Color[] COLORS = {Theme.OK, Theme.WARN, Theme.DANGER, Theme.UNKNOWN};

    private final int[] counts = new int[4];
    private final JLabel[] countLabels = new JLabel[4];
    private final Donut donut = new Donut();

    public SummaryPanel() {
        super(new BorderLayout(0, 6), Theme.PANEL, Theme.BORDER, 18);
        setBorder(Theme.pad(10, 12, 12, 12));

        JLabel title = new JLabel("Scan Summary");
        title.setFont(Theme.font(Font.BOLD, 18));
        title.setForeground(Theme.TEXT);
        add(title, BorderLayout.NORTH);

        JPanel legend = new JPanel(new GridLayout(4, 1, 0, 4));
        legend.setOpaque(false);
        legend.setBorder(Theme.pad(0, 10, 0, 10));
        for (int i = 0; i < 4; i++) {
            JPanel line = new JPanel(new BorderLayout(10, 0));
            line.setOpaque(false);
            JLabel name = new JLabel(NAMES[i], new Icons.Dot(COLORS[i]), JLabel.LEFT);
            name.setIconTextGap(10);
            name.setFont(Theme.font(Font.PLAIN, 16));
            name.setForeground(Theme.TEXT);
            countLabels[i] = new JLabel("0");
            countLabels[i].setFont(Theme.font(Font.PLAIN, 16));
            countLabels[i].setForeground(Theme.TEXT);
            line.add(name, BorderLayout.CENTER);
            line.add(countLabels[i], BorderLayout.EAST);
            legend.add(line);
        }

        JPanel body = new JPanel(new BorderLayout(10, 0));
        body.setOpaque(false);
        body.add(donut, BorderLayout.WEST);
        body.add(legend, BorderLayout.CENTER);
        add(body, BorderLayout.CENTER);
    }

    /** counts = {low, medium, high, notVerified}. */
    public void update(int[] c) {
        System.arraycopy(c, 0, counts, 0, 4);
        for (int i = 0; i < 4; i++) countLabels[i].setText(String.valueOf(counts[i]));
        donut.repaint();
    }

    private final class Donut extends JComponent {
        Donut() { setPreferredSize(new Dimension(150, 150)); }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = Theme.aa(g);
            int size = Math.min(getWidth(), getHeight()) - 16;
            int x = (getWidth() - size) / 2, y = (getHeight() - size) / 2;
            float thick = size * 0.17f;
            int total = counts[0] + counts[1] + counts[2] + counts[3];
            g2.setStroke(new BasicStroke(thick, BasicStroke.CAP_BUTT, BasicStroke.JOIN_ROUND));
            double inset = thick / 2;
            double d = size - thick;
            if (total == 0) {
                g2.setColor(new Color(30, 55, 110));
                g2.draw(new Arc2D.Double(x + inset, y + inset, d, d, 0, 360, Arc2D.OPEN));
            } else {
                double start = 90;
                for (int i = 0; i < 4; i++) {
                    if (counts[i] == 0) continue;
                    double extent = -360.0 * counts[i] / total;
                    g2.setColor(COLORS[i]);
                    g2.draw(new Arc2D.Double(x + inset, y + inset, d, d, start, extent, Arc2D.OPEN));
                    start += extent;
                }
            }
            g2.setColor(Color.WHITE);
            g2.setFont(Theme.font(Font.BOLD, 34));
            FontMetrics fm = g2.getFontMetrics();
            String n = String.valueOf(total);
            g2.drawString(n, (getWidth() - fm.stringWidth(n)) / 2, getHeight() / 2 + 6);
            g2.setFont(Theme.font(Font.PLAIN, 15));
            fm = g2.getFontMetrics();
            g2.drawString("Items", (getWidth() - fm.stringWidth("Items")) / 2, getHeight() / 2 + 26);
            g2.dispose();
        }
    }
}

