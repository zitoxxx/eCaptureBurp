package com.ecapture.burp.export;

import com.ecapture.burp.event.MatchedHttpPair;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Simple CSV exporter to avoid Apache POI dependency. Writes a UTF-8 CSV with quoted fields.
 */
public class ExcelExporter {

    public static void writeXlsx(OutputStream out, List<MatchedHttpPair> pairs, List<String> columns) throws Exception {
        // We'll write CSV text and let user open it with Excel. File extension may be .csv even if caller passes .xlsx
        StringBuilder sb = new StringBuilder();

        // header
        for (int i = 0; i < columns.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append('"').append(escape(columns.get(i))).append('"');
        }
        sb.append('\n');

        for (MatchedHttpPair pair : pairs) {
            for (int i = 0; i < columns.size(); i++) {
                if (i > 0) sb.append(',');
                String col = columns.get(i);
                String value = "";
                switch (col) {
                    case "#": value = pair.getUuid(); break;
                    case "Time": value = pair.getTimestamp(); break;
                    case "Proto": value = pair.getProtocol(); break;
                    case "Method": value = pair.getMethod(); break;
                    case "Host": value = pair.getHost(); break;
                    case "URL": value = pair.getUrl(); break;
                    case "Status": value = pair.getStatusCode(); break;
                    case "Req Len": value = Integer.toString(pair.getRequestLength()); break;
                    case "Resp Len": value = Integer.toString(pair.getResponseLength()); break;
                    case "Process": value = pair.getProcessInfo(); break;
                    case "Complete": value = pair.isComplete() ? "✓" : "..."; break;
                    case "Request Body":
                        if (pair.getRequest() != null && pair.getRequest().getPayload() != null)
                            value = new String(pair.getRequest().getPayload(), StandardCharsets.UTF_8);
                        break;
                    case "Response Body":
                        if (pair.getResponse() != null && pair.getResponse().getPayload() != null)
                            value = new String(pair.getResponse().getPayload(), StandardCharsets.UTF_8);
                        break;
                    default:
                        value = "";
                }
                sb.append('"').append(escape(value)).append('"');
            }
            sb.append('\n');
        }

        out.write(sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\"", "\"\"");
    }
}
