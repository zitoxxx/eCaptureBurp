package com.ecapture.burp.event;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

public class Http2FrameConverter {

    public static byte[] framesToHttp2Request(byte[] frameBytes) {
        String frames = new String(frameBytes, StandardCharsets.UTF_8);

        String method = "GET";
        String path = "/";
        String host = "";
        Map<String, String> headers = new LinkedHashMap<>();
        StringBuilder body = new StringBuilder();

        for (String frame : frames.split("Frame Type\t=>\t")) {
            if (frame.isEmpty()) {
                continue;
            }
            String[] frameParts = frame.split("\n", 2);
            String frameType = frameParts[0].trim();
            String frameBody = frameParts.length > 1 ? frameParts[1] : "";

            // HEADERS
            if (frameType.equals("HEADERS")) {
                for (String rawLine : frameBody.split("\n")) {
                    String line = rawLine.trim();
                    if (line.startsWith("header field")) {
                        String[] kv = parseHeader(line);
                        switch (kv[0]) {
                            case ":method" -> method = kv[1].toUpperCase();
                            case ":path" -> path = kv[1];
                            case ":authority" -> host = kv[1];
                            case ":scheme" -> {
                            }
                            default -> headers.put(kv[0], unescape(kv[1]));
                        }
                        continue;
                    }
                }
            }

            // DATA
            if (frameType.equals("DATA")) {
                ArrayList<String> dataLines = new ArrayList<>();
                for (String rawLine : frameBody.split("\n")) {
                    String line = rawLine.trim();
                    if (line.startsWith("Frame StreamID\t=>\t")) {
                        continue;
                    }
                    if (line.startsWith("Frame Length\t=>\t")) {
                        continue;
                    }
                    dataLines.add(rawLine);
                }
                body.append(String.join("\n", dataLines));
            }
        }

        StringBuilder req = new StringBuilder();
        req.append(method).append(" ").append(path).append(" HTTP/2\r\n");

        if (!host.isEmpty()) {
            req.append("Host: ").append(host).append("\r\n");
        }

        headers.forEach((k, v) -> req.append(toHeaderCase(k)).append(": ").append(v).append("\r\n"));

        if (!body.isEmpty()) {
            req.append("\r\n").append(body);
        }

        return req.toString().getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] framesToHttp2Response(byte[] frameBytes) {
        String frames = new String(frameBytes, StandardCharsets.UTF_8);

        String status = "200";
        Map<String, String> headers = new LinkedHashMap<>();
        StringBuilder body = new StringBuilder();

        for (String frame : frames.split("Frame Type\t=>\t")) {
            if (frame.isEmpty()) {
                continue;
            }
            String[] frameParts = frame.split("\n", 2);
            String frameType = frameParts[0].trim();
            String frameBody = frameParts.length > 1 ? frameParts[1] : "";

            // HEADERS
            if (frameType.equals("HEADERS")) {
                for (String rawLine : frameBody.split("\n")) {
                    String line = rawLine.trim();
                    if (line.startsWith("header field")) {
                        String[] kv = parseHeader(line);
                        if (":status".equals(kv[0])) {
                            status = kv[1];
                        } else {
                            headers.put(kv[0], unescape(kv[1]));
                        }
                        continue;
                    }
                }
            }

            // DATA
            if (frameType.equals("DATA")) {
                ArrayList<String> dataLines = new ArrayList<>();
                for (String rawLine : frameBody.split("\n")) {
                    String line = rawLine.trim();
                    if (line.startsWith("Frame StreamID\t=>\t")) {
                        continue;
                    }
                    if (line.startsWith("Frame Length\t=>\t")) {
                        continue;
                    }
                    dataLines.add(rawLine);
                }
                body.append(String.join("\n", dataLines));
            }
        }

        StringBuilder resp = new StringBuilder();
        String reason = reasonPhrase(status);
        resp.append("HTTP/2 ")
                .append(status)
                .append(reason.isEmpty() ? "" : " " + reason)
                .append("\r\n");

        headers.forEach((k, v) -> resp.append(toHeaderCase(k)).append(": ").append(v).append("\r\n"));

        if (!body.isEmpty()) {
            resp.append("\r\n").append(body);
        }

        return resp.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String[] parseHeader(String line) {
        int k1 = line.indexOf('"');
        int k2 = line.indexOf('"', k1 + 1);
        int v1 = line.indexOf('"', k2 + 1);
        int v2 = line.lastIndexOf('"');
        return new String[] {
                line.substring(k1 + 1, k2),
                line.substring(v1 + 1, v2)
        };
    }

    private static String toHeaderCase(String name) {
        StringBuilder sb = new StringBuilder();
        boolean upper = true;
        for (char c : name.toCharArray()) {
            if (c == '-') {
                sb.append('-');
                upper = true;
            } else {
                sb.append(upper ? Character.toUpperCase(c) : Character.toLowerCase(c));
                upper = false;
            }
        }
        return sb.toString();
    }

    private static String reasonPhrase(String status) {
        return switch (status) {
            case "100" -> "Continue";
            case "101" -> "Switching Protocols";
            case "200" -> "OK";
            case "201" -> "Created";
            case "202" -> "Accepted";
            case "204" -> "No Content";
            case "301" -> "Moved Permanently";
            case "302" -> "Found";
            case "304" -> "Not Modified";
            case "400" -> "Bad Request";
            case "401" -> "Unauthorized";
            case "403" -> "Forbidden";
            case "404" -> "Not Found";
            case "405" -> "Method Not Allowed";
            case "409" -> "Conflict";
            case "500" -> "Internal Server Error";
            case "502" -> "Bad Gateway";
            case "503" -> "Service Unavailable";
            default -> "";
        };
    }

    private static String unescape(String v) {
        return v.replace("\\\"", "\"");
    }

}
