package com.ecapture.burp.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

/**
 * Dialog for selecting which columns to include in exports.
 */
public class ColumnSelectorDialog extends JDialog {

    private final List<String> selected = new ArrayList<>();
    private final java.util.List<JCheckBox> boxes = new ArrayList<>();

    public ColumnSelectorDialog(Window owner, List<String> currentSelection, String[] allColumns) {
        super(owner, "Choose Export Columns", ModalityType.APPLICATION_MODAL);
        setLayout(new BorderLayout(8, 8));

        JPanel center = new JPanel(new GridLayout(0, 1));
        for (String col : allColumns) {
            if ("Sel".equals(col)) continue; // don't expose selection column
            JCheckBox cb = new JCheckBox(col, currentSelection.contains(col));
            boxes.add(cb);
            center.add(cb);
        }
        add(new JScrollPane(center), BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton ok = new JButton("OK");
        JButton cancel = new JButton("Cancel");
        JButton selectAll = new JButton("Select All");
        JButton deselectAll = new JButton("Deselect All");

        ok.addActionListener(e -> {
            selected.clear();
            for (JCheckBox cb : boxes) {
                if (cb.isSelected()) selected.add(cb.getText());
            }
            setVisible(false);
            dispose();
        });
        cancel.addActionListener(e -> {
            selected.clear();
            setVisible(false);
            dispose();
        });
        selectAll.addActionListener(e -> boxes.forEach(b -> b.setSelected(true)));
        deselectAll.addActionListener(e -> boxes.forEach(b -> b.setSelected(false)));

        buttons.add(selectAll);
        buttons.add(deselectAll);
        buttons.add(cancel);
        buttons.add(ok);

        add(buttons, BorderLayout.SOUTH);
        setSize(320, 360);
        setLocationRelativeTo(owner);
    }

    public List<String> getSelectedColumns() {
        return new ArrayList<>(selected);
    }
}

