package com.ecapture.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.ecapture.burp.ECaptureBurpExtension;
import com.ecapture.burp.event.CapturedEvent;
import com.ecapture.burp.event.EventManager;
import com.ecapture.burp.event.MatchedHttpPair;
import com.ecapture.burp.websocket.ECaptureWebSocketClient;
import com.ecapture.burp.export.ExportManager;
import com.ecapture.burp.ui.ColumnSelectorDialog;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;

/**
 * Main UI tab for the eCapture Burp extension.
 */
public class ECaptureTab {
    
    private final MontoyaApi api;
    private final Logging logging;
    private final ECaptureWebSocketClient wsClient;
    private final EventManager eventManager;
    
    private JPanel mainPanel;
    private JTextField urlField;
    private JButton connectButton;
    private JButton disconnectButton;
    private JLabel statusLabel;
    private JLabel heartbeatLabel;
    private JLabel statsLabel;
    
    private JTable eventTable;
    private DefaultTableModel tableModel;
    private TableRowSorter<DefaultTableModel> tableSorter;
    private JTextField searchField;
    
    // Burp native HTTP message editors (like Proxy History)
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    
    private ECaptureContextMenuProvider contextMenuProvider;
    private final com.ecapture.burp.export.ExportManager exportManager = new com.ecapture.burp.export.ExportManager();
    private java.util.List<String> exportColumns = new java.util.ArrayList<>();

    // Table columns (add Protocol column)
    private static final String[] COLUMN_NAMES = {
            "#", "Time", "Proto", "Method", "Host", "URL", "Status", "Req Len", "Resp Len", "Process", "Complete"
    };
    
    // Map pair ID to table row index for updates
    private final java.util.Map<String, Integer> pairToRowMap = new java.util.concurrent.ConcurrentHashMap<>();
    
    public ECaptureTab(MontoyaApi api, ECaptureWebSocketClient wsClient, EventManager eventManager) {
        this.api = api;
        this.logging = api.logging();
        this.wsClient = wsClient;
        this.eventManager = eventManager;
        exportColumns.addAll(java.util.Arrays.asList(COLUMN_NAMES));

        initializeUI();
        setupListeners();
        
        this.contextMenuProvider = new ECaptureContextMenuProvider(api, this);
    }
    
    private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout(5, 5));
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // Top panel - Configuration and Status
        JPanel topPanel = createTopPanel();
        mainPanel.add(topPanel, BorderLayout.NORTH);
        
        // Center - Split pane with table and details
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplit.setResizeWeight(0.5);
        
        // Event table with search
        JPanel tablePanel = createTablePanel();
        mainSplit.setTopComponent(tablePanel);
        
        // Bottom - Request/Response split view using Burp's native editors
        JSplitPane detailSplit = createDetailSplitPane();
        mainSplit.setBottomComponent(detailSplit);
        
        mainPanel.add(mainSplit, BorderLayout.CENTER);
    }
    
    private JPanel createTopPanel() {
        JPanel topPanel = new JPanel(new BorderLayout(10, 5));
        
        // Connection panel
        JPanel connectionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        connectionPanel.setBorder(new TitledBorder("Connection"));
        
        connectionPanel.add(new JLabel("WebSocket URL:"));
        urlField = new JTextField(ECaptureBurpExtension.DEFAULT_WS_URL, 30);
        connectionPanel.add(urlField);
        
        connectButton = new JButton("Connect");
        connectButton.setBackground(new Color(76, 175, 80));
        connectButton.setForeground(Color.WHITE);
        connectionPanel.add(connectButton);
        
        disconnectButton = new JButton("Disconnect");
        disconnectButton.setEnabled(false);
        connectionPanel.add(disconnectButton);
        
        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> clearAll());
        connectionPanel.add(clearButton);
        
        topPanel.add(connectionPanel, BorderLayout.WEST);
        
        // Status panel
        JPanel statusPanel = new JPanel(new GridLayout(3, 1, 5, 2));
        statusPanel.setBorder(new TitledBorder("Status"));
        
        statusLabel = new JLabel("● Disconnected");
        statusLabel.setForeground(Color.GRAY);
        statusPanel.add(statusLabel);
        
        heartbeatLabel = new JLabel("Heartbeat: -");
        statusPanel.add(heartbeatLabel);
        
        statsLabel = new JLabel("Events: 0 | Pairs: 0 | Pending: 0");
        statusPanel.add(statsLabel);
        
        topPanel.add(statusPanel, BorderLayout.EAST);
        
        return topPanel;
    }
    
    private JPanel createTablePanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(new TitledBorder("Captured HTTP Traffic (GET/POST only)"));
        
        // Search panel
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        searchPanel.add(new JLabel("Search:"));
        searchField = new JTextField(30);
        searchField.setToolTipText("Filter by host, URL, method, or process name");
        searchPanel.add(searchField);
        
        JButton searchButton = new JButton("Filter");
        searchButton.addActionListener(e -> applyFilter());
        searchPanel.add(searchButton);
        
        JButton clearFilterButton = new JButton("Clear Filter");
        clearFilterButton.addActionListener(e -> {
            searchField.setText("");
            applyFilter();
        });
        searchPanel.add(clearFilterButton);
        
        // Add export controls to search panel
        JButton columnSelectButton = new JButton("Choose Columns");
        columnSelectButton.addActionListener(e -> {
            ColumnSelectorDialog dlg = new ColumnSelectorDialog(SwingUtilities.getWindowAncestor(mainPanel), exportColumns, COLUMN_NAMES);
            dlg.setVisible(true);
            java.util.List<String> selected = dlg.getSelectedColumns();
            if (selected != null && !selected.isEmpty()) {
                exportColumns = new java.util.ArrayList<>(selected);
            }
        });
        searchPanel.add(columnSelectButton);

        JButton exportHarButton = new JButton("Export HAR");
        exportHarButton.addActionListener(e -> onExportHarClicked());
        searchPanel.add(exportHarButton);

        JButton exportCsvButton = new JButton("Export CSV");
        exportCsvButton.addActionListener(e -> onExportCsvClicked());
        searchPanel.add(exportCsvButton);

        panel.add(searchPanel, BorderLayout.NORTH);
        
        // Table
        tableModel = new DefaultTableModel(COLUMN_NAMES, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        eventTable = new JTable(tableModel);
        // Allow multiple selection so user can select multiple rows to export
        eventTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        eventTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        
        // Set column widths
        eventTable.getColumnModel().getColumn(0).setPreferredWidth(40);  // #
        eventTable.getColumnModel().getColumn(1).setPreferredWidth(120); // Time
        eventTable.getColumnModel().getColumn(2).setPreferredWidth(60);  // Proto
        eventTable.getColumnModel().getColumn(3).setPreferredWidth(60);  // Method
        eventTable.getColumnModel().getColumn(4).setPreferredWidth(150); // Host
        eventTable.getColumnModel().getColumn(5).setPreferredWidth(250); // URL
        eventTable.getColumnModel().getColumn(6).setPreferredWidth(50);  // Status
        eventTable.getColumnModel().getColumn(7).setPreferredWidth(60);  // Req Len
        eventTable.getColumnModel().getColumn(8).setPreferredWidth(60);  // Resp Len
        eventTable.getColumnModel().getColumn(9).setPreferredWidth(120); // Process
        eventTable.getColumnModel().getColumn(10).setPreferredWidth(60);  // Complete

        // Row sorter for filtering
        tableSorter = new TableRowSorter<>(tableModel);
        eventTable.setRowSorter(tableSorter);
        
        // Selection listener - show request and response when row is selected
        eventTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelectedPairDetails();
            }
        });
        
        JScrollPane scrollPane = new JScrollPane(eventTable);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * Create split pane for Request/Response using Burp's native HTTP editors.
     */
    private JSplitPane createDetailSplitPane() {
        // Create Burp's native HTTP request editor (read-only)
        requestEditor = api.userInterface().createHttpRequestEditor(READ_ONLY);
        
        // Create Burp's native HTTP response editor (read-only)
        responseEditor = api.userInterface().createHttpResponseEditor(READ_ONLY);
        
        // Request panel
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(new TitledBorder("Request"));
        requestPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);
        
        // Response panel
        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(new TitledBorder("Response"));
        responsePanel.add(responseEditor.uiComponent(), BorderLayout.CENTER);
        
        // Split pane - horizontal split (request on left, response on right)
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestPanel, responsePanel);
        splitPane.setResizeWeight(0.5);
        splitPane.setDividerLocation(0.5);
        
        return splitPane;
    }
    
    private void setupListeners() {
        // Connect button
        connectButton.addActionListener(e -> {
            String url = urlField.getText().trim();
            if (url.isEmpty()) {
                JOptionPane.showMessageDialog(mainPanel, "Please enter WebSocket URL",
                        "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            wsClient.connect(url);
        });
        
        // Disconnect button
        disconnectButton.addActionListener(e -> wsClient.disconnect());
        
        // WebSocket state listener
        wsClient.setStateListener(state -> SwingUtilities.invokeLater(() -> {
            switch (state) {
                case CONNECTED:
                    statusLabel.setText("● Connected");
                    statusLabel.setForeground(new Color(76, 175, 80));
                    connectButton.setEnabled(false);
                    disconnectButton.setEnabled(true);
                    urlField.setEnabled(false);
                    break;
                    
                case CONNECTING:
                    statusLabel.setText("● Connecting...");
                    statusLabel.setForeground(new Color(255, 193, 7));
                    connectButton.setEnabled(false);
                    disconnectButton.setEnabled(true);
                    break;
                    
                case RECONNECTING:
                    statusLabel.setText("● Reconnecting...");
                    statusLabel.setForeground(new Color(255, 152, 0));
                    break;
                    
                case DISCONNECTED:
                    statusLabel.setText("● Disconnected");
                    statusLabel.setForeground(Color.GRAY);
                    connectButton.setEnabled(true);
                    disconnectButton.setEnabled(false);
                    urlField.setEnabled(true);
                    break;
                    
                case ERROR:
                    statusLabel.setText("● Error");
                    statusLabel.setForeground(Color.RED);
                    break;
            }
        }));
        
        // Event manager listeners
        eventManager.addPairListener(pair -> {
            javax.swing.SwingUtilities.invokeLater(() -> {
                try {
                    updateTableSafe(pair);
                    updateStats();
                } catch (Exception e) {
                    logging.logToError("Error in pair listener: " + e.getMessage());
                    e.printStackTrace();
                }
            });
        });
        
        // eCapture logs go to Burp Output
        eventManager.addLogListener(log -> {
            logging.logToOutput("[eCapture] " + log.trim());
        });
        
        // Search field - filter on Enter
        searchField.addActionListener(e -> applyFilter());
        
        // Timer to update heartbeat and stats
        Timer statsTimer = new Timer(1000, e -> updateHeartbeatAndStats());
        statsTimer.start();
    }
    
    /**
     * Safely add or update a row in the table for the given pair.
     */
    private void updateTableSafe(MatchedHttpPair pair) {
        try {
            String pairId = pair.getUuid();
            
            // Check if this pair already has a row
            Integer existingRow = pairToRowMap.get(pairId);
            
            if (existingRow != null && existingRow < tableModel.getRowCount()) {
                // Update existing row (response arrived)
                tableModel.setValueAt(pair.getStatusCode(), existingRow, 6);
                tableModel.setValueAt(pair.getResponseLength(), existingRow, 8);
                tableModel.setValueAt(pair.isComplete() ? "✓" : "...", existingRow, 10);

            } else {
                // Add new row
                int rowNum = tableModel.getRowCount();
                
                java.util.Vector<Object> rowData = new java.util.Vector<>();
                rowData.add(rowNum + 1);
                rowData.add(pair.getTimestamp());
                rowData.add(pair.getProtocol());
                rowData.add(pair.getMethod());
                rowData.add(pair.getHost());
                rowData.add(pair.getUrl());
                rowData.add(pair.getStatusCode());
                rowData.add(pair.getRequestLength());
                rowData.add(pair.getResponseLength());
                rowData.add(pair.getProcessInfo());
                rowData.add(pair.isComplete() ? "✓" : "...");
                
                tableModel.addRow(rowData);
                pairToRowMap.put(pairId, rowNum);
                
            }
            
        } catch (Exception e) {
            logging.logToError("Error in updateTableSafe: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private void updateStats() {
        statsLabel.setText(String.format("Events: %d | Pairs: %d | Pending: %d",
                eventManager.getTotalEventsReceived(),
                eventManager.getTotalPairsMatched(),
                eventManager.getPendingPairsCount()));
    }
    
    private void updateHeartbeatAndStats() {
        long lastHeartbeat = eventManager.getLastHeartbeatTime();
        if (lastHeartbeat > 0) {
            long elapsed = (System.currentTimeMillis() - lastHeartbeat) / 1000;
            heartbeatLabel.setText(String.format("Heartbeat: %ds ago (count: %d)",
                    elapsed, eventManager.getHeartbeatCount()));
            
            // Change color based on heartbeat freshness
            if (elapsed < 10) {
                heartbeatLabel.setForeground(new Color(76, 175, 80));
            } else if (elapsed < 30) {
                heartbeatLabel.setForeground(new Color(255, 152, 0));
            } else {
                heartbeatLabel.setForeground(Color.RED);
            }
        }
        
        updateStats();
    }
    
    /**
     * Show selected pair's request and response in Burp's native editors.
     */
    private void showSelectedPairDetails() {
        int selectedRow = eventTable.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }
        
        // Convert view index to model index (for filtering)
        int modelRow = eventTable.convertRowIndexToModel(selectedRow);
        
        List<MatchedHttpPair> pairs = eventManager.getMatchedPairs();
        if (modelRow >= pairs.size()) {
            return;
        }
        
        MatchedHttpPair pair = pairs.get(modelRow);
        
        try {
            // Build HttpRequest for the editor
            HttpRequest httpRequest = null;
            if (pair.getRequest() != null && pair.getRequest().getPayload() != null) {
                String rawRequest = new String(pair.getRequest().getPayload());
                httpRequest = HttpRequest.httpRequest(rawRequest);
            }
            
            // Build HttpResponse for the editor
            HttpResponse httpResponse = null;
            if (pair.getResponse() != null && pair.getResponse().getPayload() != null) {
                String rawResponse = new String(pair.getResponse().getPayload());
                httpResponse = HttpResponse.httpResponse(rawResponse);
            }
            
            // Set request in editor
            if (httpRequest != null) {
                requestEditor.setRequest(httpRequest);
            } else {
                // Clear the editor if no request
                requestEditor.setRequest(HttpRequest.httpRequest(""));
            }
            
            // Set response in editor
            if (httpResponse != null) {
                responseEditor.setResponse(httpResponse);
            } else {
                // Clear the editor if no response
                responseEditor.setResponse(HttpResponse.httpResponse(""));
            }
            
        } catch (Exception e) {
            logging.logToError("Error showing details: " + e.getMessage());
        }
    }
    
    private void applyFilter() {
        String filterText = searchField.getText().trim();
        
        if (filterText.isEmpty()) {
            tableSorter.setRowFilter(null);
        } else {
            try {
                // Case-insensitive filter across multiple columns (Host, URL, Method, Process)
                tableSorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(filterText)));
            } catch (Exception e) {
                logging.logToError("Invalid filter pattern: " + e.getMessage());
            }
        }
    }
    
    private void clearAll() {
        eventManager.clear();
        tableModel.setRowCount(0);
        pairToRowMap.clear();
        
        // Clear editors
        try {
            requestEditor.setRequest(HttpRequest.httpRequest(""));
            responseEditor.setResponse(HttpResponse.httpResponse(""));
        } catch (Exception e) {
            // Ignore
        }
        
        updateStats();
    }
    
    /**
     * Get the selected HTTP pair (for context menu).
     */
    public MatchedHttpPair getSelectedPair() {
        int selectedRow = eventTable.getSelectedRow();
        if (selectedRow < 0) {
            return null;
        }
        
        int modelRow = eventTable.convertRowIndexToModel(selectedRow);
        List<MatchedHttpPair> pairs = eventManager.getMatchedPairs();
        
        if (modelRow < pairs.size()) {
            return pairs.get(modelRow);
        }
        return null;
    }
    
    /**
     * Get the event table component (for context menu).
     */
    public JTable getEventTable() {
        return eventTable;
    }
    
    /**
     * Get the main UI component.
     */
    public Component getComponent() {
        return mainPanel;
    }
    
    /**
     * Get context menu provider.
     */
    public ContextMenuItemsProvider getContextMenuProvider() {
        return contextMenuProvider;
    }

    /**
     * Get selected pairs based on table selection (multiple rows supported). If none selected, returns empty list.
     */
    public java.util.List<MatchedHttpPair> getSelectedPairsForExport() {
        int[] selectedRows = eventTable.getSelectedRows();
        java.util.List<MatchedHttpPair> result = new java.util.ArrayList<>();
        if (selectedRows == null || selectedRows.length == 0) return result;
        java.util.List<MatchedHttpPair> pairs = eventManager.getMatchedPairs();
        for (int viewRow : selectedRows) {
            int modelRow = eventTable.convertRowIndexToModel(viewRow);
            if (modelRow >= 0 && modelRow < pairs.size()) {
                result.add(pairs.get(modelRow));
            }
        }
        return result;
    }

    private void onExportHarClicked() {
        java.util.List<MatchedHttpPair> selected = getSelectedPairsForExport();
        java.util.List<MatchedHttpPair> toExport = selected;
        if (selected.isEmpty()) {
            int sel = JOptionPane.showConfirmDialog(mainPanel, "No rows selected. Export all captured pairs?", "Export", JOptionPane.YES_NO_OPTION);
            if (sel != JOptionPane.YES_OPTION) return;
            toExport = eventManager.getMatchedPairs();
        }
        String defaultName = buildDefaultFilename(".har");
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(defaultName));
        int res = chooser.showSaveDialog(mainPanel);
        if (res != JFileChooser.APPROVE_OPTION) return;
        File out = chooser.getSelectedFile();
        try {
            exportManager.exportAsHar(out, toExport, exportColumns);
            JOptionPane.showMessageDialog(mainPanel, "Exported HAR: " + out.getAbsolutePath());
        } catch (Exception ex) {
            logging.logToError("Export HAR failed: " + ex.getMessage());
            JOptionPane.showMessageDialog(mainPanel, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onExportCsvClicked() {
        java.util.List<MatchedHttpPair> selected = getSelectedPairsForExport();
        java.util.List<MatchedHttpPair> toExport = selected;
        if (selected.isEmpty()) {
            int sel = JOptionPane.showConfirmDialog(mainPanel, "No rows selected. Export all captured pairs?", "Export", JOptionPane.YES_NO_OPTION);
            if (sel != JOptionPane.YES_OPTION) return;
            toExport = eventManager.getMatchedPairs();
        }
        String defaultName = buildDefaultFilename(".csv");
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(defaultName));
        int res = chooser.showSaveDialog(mainPanel);
        if (res != JFileChooser.APPROVE_OPTION) return;
        File out = chooser.getSelectedFile();
        try {
            exportManager.exportAsExcel(out, toExport, exportColumns);
            JOptionPane.showMessageDialog(mainPanel, "Exported CSV: " + out.getAbsolutePath());
        } catch (Exception ex) {
            logging.logToError("Export CSV failed: " + ex.getMessage());
            JOptionPane.showMessageDialog(mainPanel, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private String buildDefaultFilename(String ext) {
        String url = urlField.getText().trim();
        if (url.isEmpty()) url = "ecapture";
        String safe = url.replaceAll("[^a-zA-Z0-9._-]", "_");
        String ts = new java.text.SimpleDateFormat("yyyyMMdd_HHmmss").format(new java.util.Date());
        return safe + "_" + ts + ext;
    }
}
