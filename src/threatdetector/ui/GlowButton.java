package threatdetector.ui;

import javax.swing.JButton;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Font;
import java.awt.GradientPaint;
import java.awt.Graphics;
import java.awt.Graphics2D;

/** Rounded button. primary = bright blue gradient (Scan), otherwise a dark outlined button. */
public class GlowButton extends JButton {
    private final boolean primary;

    public GlowButton(String text, boolean primary) {
        super(text);
        this.primary = primary;
        setContentAreaFilled(false);
        setBorderPainted(false);
        setFocusPainted(false);
        setRolloverEnabled(true);
        setForeground(Color.WHITE);
        setFont(Theme.font(Font.BOLD, primary ? 22 : 15));
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = Theme.aa(g);
        boolean on = isEnabled();
        boolean hover = getModel().isRollover() && on;
        boolean down = getModel().isPressed() && on;
        int w = getWidth() - 1, h = getHeight() - 1;
        if (primary) {
            Color top = on ? new Color(40, 150, 255) : new Color(40, 70, 120);
            Color bottom = on ? new Color(10, 90, 220) : new Color(25, 45, 90);
            if (hover) { top = top.brighter(); bottom = bottom.brighter(); }
            if (down) { top = top.darker(); bottom = bottom.darker(); }
            g2.setPaint(new GradientPaint(0, 0, top, 0, h, bottom));
            g2.fillRoundRect(0, 0, w, h, 18, 18);
            g2.setColor(new Color(120, 190, 255));
            g2.drawRoundRect(0, 0, w, h, 18, 18);
        } else {
            g2.setColor(down ? new Color(12, 40, 100) : hover ? new Color(16, 52, 120) : new Color(10, 36, 90));
            g2.fillRoundRect(0, 0, w, h, 14, 14);
            g2.setColor(on ? Theme.BORDER : new Color(40, 60, 100));
            g2.drawRoundRect(0, 0, w, h, 14, 14);
        }
        g2.dispose();
        setForeground(on ? Color.WHITE : new Color(160, 175, 200));
        super.paintComponent(g);
    }
}
