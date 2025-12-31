package com.ecapture.burp.export;

import com.ecapture.burp.event.MatchedHttpPair;

import java.io.File;
import java.io.FileOutputStream;
import java.util.List;

/**
 * High level export manager that delegates to HAR and CSV exporters.
 */
public class ExportManager {

    public ExportManager() {
    }

    public void exportAsHar(File outFile, List<MatchedHttpPair> pairs, List<String> columns) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(outFile)) {
            HarSerializer.writeHar(fos, pairs, columns);
        }
    }

    public void exportAsExcel(File outFile, List<MatchedHttpPair> pairs, List<String> columns) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(outFile)) {
            // ExcelExporter writes CSV text for compatibility; if user selected .xlsx extension, file will contain CSV
            ExcelExporter.writeXlsx(fos, pairs, columns);
        }
    }
}

