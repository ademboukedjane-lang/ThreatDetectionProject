package threatdetector.ui;

import javax.swing.JPanel;
import java.awt.Color;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.LayoutManager;

/** Panel with rounded corners, a fill color and a border color. */
public class RoundedPanel extends JPanel {
    private final Color fill;
    private final Color border;
    private final int arc;

    public RoundedPanel(LayoutManager layout, Color fill, Color border, int arc) {
        super(layout);
        this.fill = fill;
        this.border = border;
        this.arc = arc;
        setOpaque(false);
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = Theme.aa(g);
        g2.setColor(fill);
        g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, arc, arc);
        g2.setColor(border);
        g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, arc, arc);
        g2.dispose();
        super.paintComponent(g);
    }
}

