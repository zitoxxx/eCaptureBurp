package com.ecapture.burp.event;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Represents a captured HTTP event from eCapture.
 */
public class CapturedEvent {
    
    /**
     * Event types from eCapture protocol
     */
    public enum EventType {
        UNKNOWN(0, "Unknown"),
        HTTP1_REQUEST(1, "HTTP/1.x Request"),
        HTTP2_REQUEST(2, "HTTP/2 Request"),
        HTTP1_RESPONSE(3, "HTTP/1.x Response"),
        HTTP2_RESPONSE(4, "HTTP/2 Response"),
        // Auto-detected types (for type=0 with content analysis)
        AUTO_REQUEST(-1, "Auto-Detected Request"),
        AUTO_RESPONSE(-2, "Auto-Detected Response");
        
        private final int code;
        private final String description;
        
        EventType(int code, String description) {
            this.code = code;
            this.description = description;
        }
        
        public int getCode() {
            return code;
        }
        
        public String getDescription() {
            return description;
        }
        
        public static EventType fromCode(int code) {
            for (EventType type : values()) {
                if (type.code == code) {
                    return type;
                }
            }
            return UNKNOWN;
        }
        
        public boolean isRequest() {
            return this == HTTP1_REQUEST || this == HTTP2_REQUEST || this == AUTO_REQUEST;
        }
        
        public boolean isResponse() {
            return this == HTTP1_RESPONSE || this == HTTP2_RESPONSE || this == AUTO_RESPONSE;
        }
    }
    
    private final long timestamp;
    private final String uuid;
    private final String srcIp;
    private final int srcPort;
    private final String dstIp;
    private final int dstPort;
    private final long pid;
    private final String processName;
    private final EventType eventType;
    private final int length;
    private final byte[] payload;
    private final long receivedAt;
    
    public CapturedEvent(long timestamp, String uuid, String srcIp, int srcPort,
                         String dstIp, int dstPort, long pid, String processName,
                         int type, int length, byte[] payload) {
        this.timestamp = timestamp;
        this.uuid = uuid;
        this.srcIp = srcIp;
        this.srcPort = srcPort;
        this.dstIp = dstIp;
        this.dstPort = dstPort;
        this.pid = pid;
        this.processName = processName;
        this.length = length;
        this.payload = payload;
        this.receivedAt = System.currentTimeMillis();
        
        // Auto-detect event type if UNKNOWN (type=0)
        EventType detectedType = EventType.fromCode(type);
        if (detectedType == EventType.UNKNOWN && payload != null && payload.length > 0) {
            detectedType = detectEventType(payload);
        }
        this.eventType = detectedType;
    }
    
    /**
     * Auto-detect if payload is HTTP request or response based on content.
     */
    private static EventType detectEventType(byte[] payload) {
        if (payload == null || payload.length < 4) {
            return EventType.UNKNOWN;
        }
        
        String start = new String(payload, 0, Math.min(payload.length, 200));

        // Check for HTTP/2 pseudo-headers text form
        if (start.contains(":method") || start.contains(":path") || start.contains(":authority") || start.contains(":status")) {
            // If contains :status it's a response
            if (start.contains(":status")) return EventType.AUTO_RESPONSE;
            return EventType.AUTO_REQUEST;
        }

        // Check for HTTP response (starts with "HTTP/")
        if (start.startsWith("HTTP/")) {
            return EventType.AUTO_RESPONSE;
        }
        
        // Check for HTTP request methods
        if (start.startsWith("GET ") || 
            start.startsWith("POST ") || 
            start.startsWith("PUT ") || 
            start.startsWith("DELETE ") || 
            start.startsWith("HEAD ") || 
            start.startsWith("OPTIONS ") || 
            start.startsWith("PATCH ") ||
            start.startsWith("CONNECT ") ||
            start.startsWith("TRACE ")) {
            return EventType.AUTO_REQUEST;
        }
        
        // Check for HTTP/2 pseudo headers in other positions
        if (start.contains(":status")) return EventType.AUTO_RESPONSE;

        return EventType.UNKNOWN;
    }
    
    public long getTimestamp() {
        return timestamp;
    }
    
    public String getFormattedTimestamp() {
        return Instant.ofEpochSecond(timestamp)
                .atZone(ZoneId.systemDefault())
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }
    
    public String getUuid() {
        return uuid;
    }
    
    public String getSrcIp() {
        return srcIp;
    }
    
    public int getSrcPort() {
        return srcPort;
    }
    
    public String getDstIp() {
        return dstIp;
    }
    
    public int getDstPort() {
        return dstPort;
    }
    
    public String getSource() {
        return srcIp + ":" + srcPort;
    }
    
    public String getDestination() {
        return dstIp + ":" + dstPort;
    }
    
    public long getPid() {
        return pid;
    }
    
    public String getProcessName() {
        return processName;
    }
    
    public EventType getEventType() {
        return eventType;
    }
    
    public int getLength() {
        return length;
    }
    
    public byte[] getPayload() {
        return payload;
    }
    
    public long getReceivedAt() {
        return receivedAt;
    }
    
    public boolean isRequest() {
        return eventType.isRequest();
    }
    
    public boolean isResponse() {
        return eventType.isResponse();
    }
    
    /**
     * Extract HTTP method from request payload, support HTTP/1.x and HTTP/2 pseudo-headers.
     */
    public String getHttpMethod() {
        if (!isRequest() || payload == null || payload.length == 0) {
            return "-";
        }
        String payloadStr = new String(payload);
        // HTTP/1.x style: METHOD <path> HTTP/1.1
        int spaceIndex = payloadStr.indexOf(' ');
        if (spaceIndex > 0 && spaceIndex < 12) {
            String candidate = payloadStr.substring(0, spaceIndex);
            if (candidate.matches("[A-Z]+")) return candidate;
        }
        // HTTP/2 pseudo-headers (text representation), look for :method: or :method <value>
        String method = extractPseudoHeader(payloadStr, ":method");
        if (method != null) return method;
        // Try case-insensitive
        method = extractPseudoHeader(payloadStr, ":Method");
        if (method != null) return method;
        return "-";
    }
    
    /**
     * Extract URL or path from request payload; for HTTP/2 reconstruct using :scheme, :authority, :path when possible.
     */
    public String getUrl() {
        if (!isRequest() || payload == null || payload.length == 0) {
            return "-";
        }
        String payloadStr = new String(payload);
        // HTTP/1.x
        int firstSpace = payloadStr.indexOf(' ');
        if (firstSpace > 0) {
            int secondSpace = payloadStr.indexOf(' ', firstSpace + 1);
            if (secondSpace > firstSpace) {
                return payloadStr.substring(firstSpace + 1, secondSpace);
            }
        }
        // HTTP/2 pseudo-headers
        String path = extractPseudoHeader(payloadStr, ":path");
        String authority = extractPseudoHeader(payloadStr, ":authority");
        String scheme = extractPseudoHeader(payloadStr, ":scheme");
        if (path != null) {
            if (authority != null) {
                if (scheme == null) scheme = (isHttpsPort(dstPort) ? "https" : "http");
                return scheme + "://" + authority + path;
            }
            return path;
        }
        return "-";
    }
    
    /**
     * Extract status code from response payload; support HTTP/1.x and HTTP/2 pseudo-headers.
     */
    public String getStatusCode() {
        if (!isResponse() || payload == null || payload.length == 0) {
            return "-";
        }
        String payloadStr = new String(payload);
        // HTTP/1.x response: HTTP/1.1 200 OK
        if (payloadStr.startsWith("HTTP/")) {
            int firstSpace = payloadStr.indexOf(' ');
            if (firstSpace > 0) {
                int secondSpace = payloadStr.indexOf(' ', firstSpace + 1);
                int endIndex = secondSpace > firstSpace ? secondSpace : Math.min(payloadStr.length(), firstSpace + 4);
                if (endIndex > firstSpace + 1) {
                    return payloadStr.substring(firstSpace + 1, endIndex).trim();
                }
            }
        }
        // HTTP/2 pseudo-header :status
        String status = extractPseudoHeader(payloadStr, ":status");
        if (status != null) return status;
        return "-";
    }
    
    /**
     * Extract Host header from HTTP request; for HTTP/2 check :authority.
     */
    public String getHost() {
        if (payload == null || payload.length == 0) {
            return dstIp;
        }
        String payloadStr = new String(payload);
        // HTTP/1.x Host: header
        String hostHeader = "Host:";
        int hostIndex = payloadStr.indexOf(hostHeader);
        if (hostIndex == -1) {
            hostHeader = "host:";
            hostIndex = payloadStr.indexOf(hostHeader);
        }
        if (hostIndex >= 0) {
            int start = hostIndex + hostHeader.length();
            int end = payloadStr.indexOf('\r', start);
            if (end == -1) {
                end = payloadStr.indexOf('\n', start);
            }
            if (end > start) {
                return payloadStr.substring(start, end).trim();
            }
        }
        // HTTP/2 pseudo-header
        String authority = extractPseudoHeader(payloadStr, ":authority");
        if (authority != null) return authority;
        return dstIp;
    }
    
    private static String extractPseudoHeader(String s, String headerName) {
        if (s == null) return null;
        // look for lines like ":method: GET" or ":method GET" or ":method" then next token
        int idx = s.indexOf(headerName);
        if (idx == -1) return null;
        int lineEnd = s.indexOf('\n', idx);
        int lineStart = s.lastIndexOf('\n', idx);
        if (lineStart == -1) lineStart = 0; else lineStart += 1;
        String line = (lineEnd == -1) ? s.substring(lineStart) : s.substring(lineStart, lineEnd);
        // strip headerName
        String rest = line.substring(Math.min(line.length(), line.indexOf(headerName) + headerName.length())).trim();
        // remove leading ':' or ':' plus separator
        if (rest.startsWith(":")) rest = rest.substring(1).trim();
        if (rest.isEmpty()) {
            // maybe value follows on next token
            String[] toks = line.split("\\s+", 3);
            if (toks.length >= 2) return toks[1].trim();
            return null;
        }
        // if rest like ":value" or "value"
        return rest.replaceFirst("^:\\s*", "").trim();
    }

    private static boolean isHttpsPort(int port) {
        return port == 443 || port == 8443;
    }

    @Override
    public String toString() {
        return String.format("CapturedEvent[uuid=%s, type=%s, %s -> %s, process=%s(%d), len=%d]",
                uuid, eventType.getDescription(), getSource(), getDestination(), processName, pid, length);
    }
}

