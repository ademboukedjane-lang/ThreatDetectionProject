package threatdetector.ui;

import javax.swing.ButtonGroup;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridBagLayout;
import java.util.function.Consumer;

/** "Input Source" card: URL / Message / CSV radios, text field, Browse CSV and Scan buttons. */
public class InputPanel extends RoundedPanel {

    public enum Mode { URL, MESSAGE, CSV }

    private final JRadioButton rUrl = radio("URL");
    private final JRadioButton rMsg = radio("Message");
    private final JRadioButton rCsv = radio("CSV File");
    private final HintTextField field = new HintTextField();
    private final GlowButton browse = new GlowButton("Browse CSV", false);
    private final GlowButton scan = new GlowButton("Scan", true);
    private final JLabel error = new JLabel(" ");
    private Consumer<Mode> modeListener = m -> { };

    public InputPanel() {
        super(new BorderLayout(16, 0), Theme.PANEL, Theme.BORDER, 18);
        setBorder(Theme.pad(12, 14, 12, 14));

        ButtonGroup group = new ButtonGroup();
        group.add(rUrl);
        group.add(rMsg);
        group.add(rCsv);
        rUrl.setSelected(true);

        JLabel title = new JLabel("Input Source");
        title.setFont(Theme.font(Font.BOLD, 20));
        title.setForeground(Theme.TEXT);

        JPanel radios = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        radios.setOpaque(false);
        radios.add(rUrl);
        radios.add(javax.swing.Box.createHorizontalStrut(40));
        radios.add(rMsg);
        radios.add(javax.swing.Box.createHorizontalStrut(40));
        radios.add(rCsv);

        RoundedPanel fieldBox = new RoundedPanel(new BorderLayout(), Theme.FIELD, Theme.BORDER, 14);
        fieldBox.setBorder(Theme.pad(0, 16, 0, 16));
        fieldBox.setPreferredSize(new Dimension(100, 46));
        fieldBox.add(field, BorderLayout.CENTER);

        browse.setPreferredSize(new Dimension(170, 46));
        JPanel fieldRow = new JPanel(new BorderLayout(14, 0));
        fieldRow.setOpaque(false);
        fieldRow.add(fieldBox, BorderLayout.CENTER);
        fieldRow.add(browse, BorderLayout.EAST);

        error.setFont(Theme.font(Font.PLAIN, 13));
        error.setForeground(Theme.DANGER);

        RoundedPanel box = new RoundedPanel(new BorderLayout(0, 10), Theme.PANEL_DARK, Theme.BORDER, 14);
        box.setBorder(Theme.pad(12, 14, 8, 14));
        box.add(radios, BorderLayout.NORTH);
        box.add(fieldRow, BorderLayout.CENTER);
        box.add(error, BorderLayout.SOUTH);

        JPanel left = new JPanel(new BorderLayout(0, 8));
        left.setOpaque(false);
        left.add(title, BorderLayout.NORTH);
        left.add(box, BorderLayout.CENTER);
        add(left, BorderLayout.CENTER);

        scan.setIcon(new Icons.Magnifier());
        scan.setIconTextGap(12);
        scan.setPreferredSize(new Dimension(230, 80));
        JPanel scanWrap = new JPanel(new GridBagLayout());
        scanWrap.setOpaque(false);
        scanWrap.add(scan);
        add(scanWrap, BorderLayout.EAST);

        rUrl.addActionListener(e -> applyMode());
        rMsg.addActionListener(e -> applyMode());
        rCsv.addActionListener(e -> applyMode());
        field.addActionListener(e -> scan.doClick());
        applyMode();
    }

    private static JRadioButton radio(String text) {
        JRadioButton r = new JRadioButton(text);
        r.setOpaque(false);
        r.setFocusPainted(false);
        r.setForeground(Theme.TEXT);
        r.setFont(Theme.font(Font.PLAIN, 17));
        Icons.Radio icon = new Icons.Radio();
        r.setIcon(icon);
        r.setSelectedIcon(icon);
        r.setIconTextGap(10);
        r.setBorder(Theme.pad(0, 0, 0, 0));
        return r;
    }

    private void applyMode() {
        Mode m = getMode();
        field.setText("");
        field.setEditable(m != Mode.CSV);
        field.setHint(m == Mode.URL ? "Enter a URL, e.g. http://example.com/login"
                : m == Mode.MESSAGE ? "Paste a message (email / SMS)..."
                : "Click Browse CSV to choose a file...");
        setError(null, false);
        modeListener.accept(m);
    }

    public Mode getMode() {
        return rCsv.isSelected() ? Mode.CSV : rMsg.isSelected() ? Mode.MESSAGE : Mode.URL;
    }

    /** Switches mode from code (also clears the field). */
    public void setMode(Mode m) {
        (m == Mode.CSV ? rCsv : m == Mode.MESSAGE ? rMsg : rUrl).setSelected(true);
        applyMode();
    }

    public String getText() { return field.getText(); }

    /** Shows the chosen CSV file name inside the (read-only) field. */
    public void showCsvFile(String label) { field.setText(label); }

    public void clearField() { field.setText(""); }

    public void setError(String message, boolean warning) {
        error.setForeground(warning ? Theme.WARN : Theme.DANGER);
        error.setText(message == null || message.isEmpty() ? " " : message);
    }

    public void setScanning(boolean scanning) {
        scan.setEnabled(!scanning);
        browse.setEnabled(!scanning);
        scan.setText(scanning ? "Scanning..." : "Scan");
    }

    public void onScan(Runnable r) { scan.addActionListener(e -> r.run()); }
    public void onBrowse(Runnable r) { browse.addActionListener(e -> r.run()); }
    public void onModeChange(Consumer<Mode> c) { modeListener = c; }

    /** Text field that shows a gray hint while empty. */
    private static final class HintTextField extends JTextField {
        private String hint = "";

        HintTextField() {
            setOpaque(false);
            setBorder(null);
            setForeground(Color.WHITE);
            setCaretColor(Color.WHITE);
            setSelectionColor(Theme.ACCENT);
            setFont(Theme.font(Font.PLAIN, 16));
        }

        void setHint(String hint) {
            this.hint = hint;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            if (getText().isEmpty()) {
                Graphics2D g2 = Theme.aa(g);
                g2.setColor(Theme.MUTED);
                g2.setFont(getFont());
                int y = (getHeight() + g2.getFontMetrics().getAscent() - g2.getFontMetrics().getDescent()) / 2;
                g2.drawString(hint, getInsets().left, y);
                g2.dispose();
            }
        }
    }
}

