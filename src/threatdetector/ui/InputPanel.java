package threatdetector.ui;

import java.awt.*;
import java.awt.event.ActionListener;
import javax.swing.*;
import threatdetector.model.InputType;

public class InputPanel extends JPanel {

    private final JComboBox<InputType> typeBox = new JComboBox<>(InputType.values());
    private final JTextField inputField = new JTextField();
    private final JButton addBtn = new JButton("Add");
    private final JButton csvBtn = new JButton("Load CSV...");

    public InputPanel() {
        super(new BorderLayout(6, 6));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 4, 8));

        JPanel right = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        right.add(addBtn);
        right.add(csvBtn);

        add(typeBox, BorderLayout.WEST);
        add(inputField, BorderLayout.CENTER);
        add(right, BorderLayout.EAST);
    }

    public InputType getSelectedType() {
        return (InputType) typeBox.getSelectedItem();
    }

    public String getText() {
        return inputField.getText();
    }

    public void clearText() {
        inputField.setText("");
    }

    public void onAdd(ActionListener l) {
        addBtn.addActionListener(l);
        inputField.addActionListener(l); // Enter key
    }

    public void onLoadCsv(ActionListener l) {
        csvBtn.addActionListener(l);
    }

    public void setInputEnabled(boolean enabled) {
        typeBox.setEnabled(enabled);
        inputField.setEnabled(enabled);
        addBtn.setEnabled(enabled);
        csvBtn.setEnabled(enabled);
    }
}
