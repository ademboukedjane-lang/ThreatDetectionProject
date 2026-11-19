package threatdetector.ui;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GradientPaint;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.util.function.Consumer;

/** Left navigation bar: logo, Home / History / Settings / About, "Stay Safe Online". */
public class SidebarPanel extends JPanel {

    public SidebarPanel(Consumer<Icons.Nav> onNavigate) {
        super(new BorderLayout());
        setOpaque(false);
        setPreferredSize(new Dimension(200, 0));

        JLabel logo = new JLabel(new Icons.Shield(110, 130, true), SwingConstants.CENTER);
        logo.setBorder(Theme.pad(18, 0, 22, 0));
        add(logo, BorderLayout.NORTH);

        JPanel nav = new JPanel();
        nav.setOpaque(false);
        nav.setLayout(new BoxLayout(nav, BoxLayout.Y_AXIS));
        nav.setBorder(Theme.pad(0, 10, 0, 10));
        addNav(nav, "Home", Icons.Nav.HOME, true, onNavigate);
        addNav(nav, "History", Icons.Nav.HISTORY, false, onNavigate);
        addNav(nav, "Settings", Icons.Nav.SETTINGS, false, onNavigate);
        addNav(nav, "About", Icons.Nav.ABOUT, false, onNavigate);
        add(nav, BorderLayout.CENTER);

        JPanel bottom = new JPanel(new BorderLayout());
        bottom.setOpaque(false);
        bottom.setBorder(Theme.pad(0, 0, 24, 0));
        bottom.add(new JLabel(new Icons.Shield(90, 106, false), SwingConstants.CENTER), BorderLayout.CENTER);
        JLabel stay = new JLabel("<html><div style='text-align:center'>Stay Safe<br>Online</div></html>",
                SwingConstants.CENTER);
        stay.setFont(Theme.font(Font.BOLD, 20));
        stay.setForeground(Theme.ACCENT);
        stay.setBorder(Theme.pad(8, 0, 0, 0));
        bottom.add(stay, BorderLayout.SOUTH);
        add(bottom, BorderLayout.SOUTH);
    }

    private void addNav(JPanel nav, String text, Icons.Nav kind, boolean selected, Consumer<Icons.Nav> cb) {
        NavButton b = new NavButton(text, new Icons.NavIcon(kind), selected);
        b.addActionListener(e -> cb.accept(kind));
        nav.add(b);
        nav.add(Box.createRigidArea(new Dimension(0, 14)));
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = Theme.aa(g);
        g2.setPaint(new GradientPaint(0, 0, new Color(8, 30, 84), 0, getHeight(), new Color(3, 12, 40)));
        g2.fillRect(0, 0, getWidth(), getHeight());
        g2.setColor(new Color(20, 60, 140));
        g2.drawLine(getWidth() - 1, 0, getWidth() - 1, getHeight());
        g2.dispose();
        super.paintComponent(g);
    }

    private static final class NavButton extends JButton {
        private final boolean selected;

        NavButton(String text, Icon icon, boolean selected) {
            super(text, icon);
            this.selected = selected;
            setContentAreaFilled(false);
            setBorderPainted(false);
            setFocusPainted(false);
            setRolloverEnabled(true);
            setHorizontalAlignment(SwingConstants.LEFT);
            setIconTextGap(14);
            setBorder(Theme.pad(0, 16, 0, 8));
            setForeground(Color.WHITE);
            setFont(Theme.font(Font.PLAIN, 17));
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            Dimension d = new Dimension(180, 50);
            setPreferredSize(d);
            setMaximumSize(d);
            setMinimumSize(d);
            setAlignmentX(LEFT_ALIGNMENT);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = Theme.aa(g);
            int w = getWidth() - 1, h = getHeight() - 1;
            if (selected) {
                g2.setPaint(new GradientPaint(0, 0, new Color(30, 130, 255), 0, h, new Color(10, 70, 190)));
                g2.fillRoundRect(0, 0, w, h, 16, 16);
                g2.setColor(new Color(110, 190, 255));
                g2.drawRoundRect(0, 0, w, h, 16, 16);
            } else if (getModel().isRollover()) {
                g2.setColor(new Color(20, 55, 130, 160));
                g2.fillRoundRect(0, 0, w, h, 16, 16);
            }
            g2.dispose();
            super.paintComponent(g);
        }
    }
}

