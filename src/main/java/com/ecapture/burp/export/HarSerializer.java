package com.ecapture.burp.export;

import com.ecapture.burp.event.MatchedHttpPair;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;

/**
 * Minimal HAR serializer implemented without external JSON libraries.
 */
public class HarSerializer {

    public static void writeHar(OutputStream out, List<MatchedHttpPair> pairs, List<String> columns) throws Exception {
        StringBuilder sb = new StringBuilder();
        DateTimeFormatter fmt = DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC);

        sb.append("{");
        sb.append("\"log\":{");
        sb.append("\"version\":\"1.2\",");
        sb.append("\"creator\":{\"name\":\"eCaptureBurp\",\"version\":\"1.0\"},");
        sb.append("\"entries\":[");

        boolean firstEntry = true;
        for (MatchedHttpPair pair : pairs) {
            if (!firstEntry) sb.append(',');
            firstEntry = false;

            sb.append('{');
            long startedMillis = pair.getCreatedAt();
            sb.append("\"startedDateTime\":\"").append(escape(fmt.format(Instant.ofEpochMilli(startedMillis)))).append("\",");
            sb.append("\"time\":0,");

            // request
            sb.append("\"request\":{");
            sb.append("\"method\":\"").append(escape(pair.getMethod())).append("\",");
            sb.append("\"url\":\"").append(escape(pair.getUrl())).append("\",");
            sb.append("\"httpVersion\":\"HTTP/1.1\",");
            sb.append("\"headers\":[{" + "\"name\":\"Host\",\"value\":\"" + escape(pair.getHost()) + "\"}],");
            sb.append("\"headersSize\":-1,");
            sb.append("\"bodySize\":").append(pair.getRequestLength());

            // postData
            if (pair.getRequest() != null && pair.getRequest().getPayload() != null) {
                byte[] payload = pair.getRequest().getPayload();
                boolean binary = !isMostlyText(payload);
                sb.append(',');
                sb.append("\"postData\":{");
                if (binary) {
                    sb.append("\"mimeType\":\"application/octet-stream\",");
                    sb.append("\"text\":\"").append(Base64.getEncoder().encodeToString(payload)).append("\",");
                    sb.append("\"encoding\":\"base64\"");
                } else {
                    String text = new String(payload, StandardCharsets.UTF_8);
                    sb.append("\"mimeType\":\"text/plain\",");
                    sb.append("\"text\":\"").append(escape(text)).append("\"");
                }
                sb.append('}');
            }

            sb.append('}'); // end request
            sb.append(',');

            // response
            sb.append("\"response\":{");
            sb.append("\"status\":").append(parseStatus(pair.getStatusCode())).append(',');
            sb.append("\"statusText\":\"\",");
            sb.append("\"httpVersion\":\"HTTP/1.1\",");
            sb.append("\"headers\":[],");
            sb.append("\"headersSize\":-1,");
            sb.append("\"bodySize\":").append(pair.getResponseLength());

            if (pair.getResponse() != null && pair.getResponse().getPayload() != null) {
                byte[] payload = pair.getResponse().getPayload();
                boolean binary = !isMostlyText(payload);
                sb.append(',');
                sb.append("\"content\":{");
                sb.append("\"size\":").append(payload.length).append(',');
                sb.append("\"mimeType\":\"application/octet-stream\",");
                if (binary) {
                    sb.append("\"text\":\"").append(Base64.getEncoder().encodeToString(payload)).append("\",");
                    sb.append("\"encoding\":\"base64\"");
                } else {
                    sb.append("\"text\":\"").append(escape(new String(payload, StandardCharsets.UTF_8))).append("\"");
                }
                sb.append('}');
            }

            // add protocol as comment
            sb.append(',');
            sb.append("\"comment\":\"").append(escape(pair.getProtocol())).append("\"");

            sb.append('}'); // end entry
        }

        sb.append("]}");
        sb.append('}');

        out.write(sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static boolean isMostlyText(byte[] data) {
        int printable = 0;
        int total = Math.min(data.length, 200);
        for (int i = 0; i < total; i++) {
            int b = data[i] & 0xff;
            if (b >= 32 && b <= 126) printable++;
            if (b == '\n' || b == '\r' || b == '\t') printable++;
        }
        return total == 0 || ((double) printable / total) > 0.8;
    }

    private static int parseStatus(String statusStr) {
        try {
            return Integer.parseInt(statusStr);
        } catch (Exception e) {
            return 0;
        }
    }

    // very small JSON string escaper
    private static String escape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"': sb.append("\\\""); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int)c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }
}
