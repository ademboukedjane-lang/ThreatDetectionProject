package threatdetector.ui;

import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

/** "Activity Log" card: timestamped lines. Call log() on the Swing thread. */
public class ActivityLogPanel extends RoundedPanel {
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss");
    private final JTextArea area = new JTextArea();

    public ActivityLogPanel() {
        super(new BorderLayout(0, 6), Theme.PANEL, Theme.BORDER, 18);
        setBorder(Theme.pad(10, 12, 12, 12));

        JLabel title = new JLabel("Activity Log");
        title.setFont(Theme.font(Font.BOLD, 18));
        title.setForeground(Theme.TEXT);
        add(title, BorderLayout.NORTH);

        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setFocusable(false);
        area.setBackground(Theme.PANEL_DARK);
        area.setForeground(new Color(215, 228, 250));
        area.setFont(Theme.font(Font.PLAIN, 14));
        area.setBorder(Theme.pad(6, 10, 6, 10));
        JScrollPane scroll = new JScrollPane(area);
        Theme.styleScroll(scroll);
        add(scroll, BorderLayout.CENTER);
    }

    public void log(String message) {
        area.append("[" + TIME.format(LocalTime.now()) + "]  " + message + "\n");
        area.setCaretPosition(area.getDocument().getLength());
    }
}
