package threatdetector.ui;

import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.swing.*;
import threatdetector.exception.*;
import threatdetector.model.*;
import threatdetector.service.*;

public class MainWindow extends JFrame {

    private final InputPanel inputPanel = new InputPanel();
    private final JButton scanBtn = new JButton("Scan");
    private final JButton clearBtn = new JButton("Clear");
    private final ResultsTable table = new ResultsTable();
    private final JProgressBar globalBar = new JProgressBar(0, 100);
    private final JLabel errorLabel = new JLabel(" ");

    // If the real constructor needs an analyzer: new ScanCoordinator(new RuleBasedAnalyzer())
    private final ScanCoordinator coordinator = new ScanCoordinator();
    private final CsvParserService csvParser = new CsvParserService();
    private final List<ScanItem> pending = new ArrayList<>();
    private final AtomicInteger idGen = new AtomicInteger(1);
    private int total = 0, done = 0; // used only on the UI thread

    public MainWindow() {
        super("Threat Detector");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(950, 520);
        setLocationRelativeTo(null);
        buildLayout();
        wireActions();
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                coordinator.shutdown();
            }
        });
    }

    private void buildLayout() {
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttons.add(scanBtn);
        buttons.add(clearBtn);
        globalBar.setStringPainted(true);
        globalBar.setString("0/0");
        errorLabel.setForeground(new Color(200, 40, 40));

        JPanel bottom = new JPanel(new GridLayout(3, 1, 0, 4));
        bottom.setBorder(BorderFactory.createEmptyBorder(4, 8, 8, 8));
        bottom.add(buttons);
        bottom.add(globalBar);
        bottom.add(errorLabel);

        add(inputPanel, BorderLayout.NORTH);
        add(table, BorderLayout.CENTER);
        add(bottom, BorderLayout.SOUTH);
    }

    private void wireActions() {
        inputPanel.onAdd(e -> onAdd());
        inputPanel.onLoadCsv(e -> onLoadCsv());
        scanBtn.addActionListener(e -> onScan());
        clearBtn.addActionListener(e -> onClear());
    }

    private void onAdd() {
        InputType type = inputPanel.getSelectedType();
        String text = inputPanel.getText();
        try {
            InputValidator.validate(type, text);   // adapt if the name differs
            addItem(type, text.trim());
            inputPanel.clearText();
            showError(" ");
        } catch (InvalidInputException ex) {
            showError(ex.getMessage());
        }
    }

    private void onLoadCsv() {
        JFileChooser fc = new JFileChooser();
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try {
            ParseReport rep = csvParser.parse(fc.getSelectedFile()); // adapt if needed
            for (ScanItem it : rep.getItems()) {
                addItem(it.getType(), it.getContent());
            }
            if (rep.getErrors().isEmpty()) {
                showError(" ");
            } else {
                showError(rep.getErrors().size() + " row(s) skipped. First: "
                        + rep.getErrors().get(0));
            }
        } catch (Exception ex) {
            showError("Cannot load CSV: " + ex.getMessage());
        }
    }

    private void addItem(InputType type, String content) {
        ScanItem item = new ScanItem(idGen.getAndIncrement(), type, content);
        pending.add(item);
        table.addItem(item);
    }

    private void onScan() {
    	if (pending.isEmpty()) {
            showError("Nothing to scan. Add an input or load a CSV first.");
            return;
        }
        showError(" ");
        List<ScanItem> batch = new ArrayList<>(pending);
        pending.clear();
        total = batch.size();
        done = 0;
        globalBar.setMaximum(total);
        globalBar.setValue(0);
        globalBar.setString("0/" + total);
        setBusy(true);

        // The ONLY place that talks to ScanCoordinator. Adapt here if its API differs.
        coordinator.submitAll(batch, new ScanListener() {
            @Override
            public void onStarted(ScanItem item) {
                SwingUtilities.invokeLater(() -> table.markRunning(item.getId()));
            }

            @Override
            public void onFinished(ScanResult r) {
                SwingUtilities.invokeLater(() -> {
                    table.updateResult(r);
                    done++;
                    globalBar.setValue(done);
                    globalBar.setString(done + "/" + total);
                    if (done == total) setBusy(false);
                });
            }
        });
    }

    private void onClear() {
        pending.clear();
        table.clear();
        total = 0;
        done = 0;
        globalBar.setValue(0);
        globalBar.setString("0/0");
        showError(" ");
    }

    private void setBusy(boolean busy) {
        scanBtn.setEnabled(!busy);
        clearBtn.setEnabled(!busy);
        inputPanel.setInputEnabled(!busy);
    }

    private void showError(String msg) {
        errorLabel.setText(msg);
    }
}
    