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

        public boolean isHttp2Request() {
            return this == HTTP2_REQUEST;
        }

        public boolean isHttp2Response() {
            return this == HTTP2_RESPONSE;
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
        this.receivedAt = System.currentTimeMillis();
        
        // Auto-detect event type if UNKNOWN (type=0)
        EventType detectedType = EventType.fromCode(type);
        if (detectedType == EventType.UNKNOWN && payload != null && payload.length > 0) {
            detectedType = detectEventType(payload);
        }
        this.eventType = detectedType;
        if (this.eventType.isHttp2Request()) {
            this.payload = Http2FrameConverter.framesToHttp2Request(payload);
        } else if (this.eventType.isHttp2Response()) {
            this.payload = Http2FrameConverter.framesToHttp2Response(payload);
        } else {
            this.payload = payload;
        }
    }
    
    /**
     * Auto-detect if payload is HTTP request or response based on content.
     */
    private static EventType detectEventType(byte[] payload) {
        if (payload == null || payload.length < 4) {
            return EventType.UNKNOWN;
        }
        
        String start = new String(payload, 0, Math.min(payload.length, 20));
        
        // Check for HTTP response (starts with "HTTP/")
        if (start.startsWith("HTTP/")) {
            return EventType.HTTP1_REQUEST;
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
            return EventType.HTTP1_RESPONSE;
        }
        
        // Check for HTTP/2 pseudo headers (requests often start with these in text form)
        if (start.contains(":method") || start.contains(":path") || start.contains(":authority")) {
            return EventType.HTTP2_REQUEST;
        }
        if (start.contains(":status")) {
            return EventType.HTTP2_RESPONSE;
        }
        
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
     * Extract HTTP method from request payload
     */
    public String getHttpMethod() {
        if (!isRequest() || payload == null || payload.length == 0) {
            return "-";
        }
        String payloadStr = new String(payload);
        int spaceIndex = payloadStr.indexOf(' ');
        if (spaceIndex > 0 && spaceIndex < 10) {
            return payloadStr.substring(0, spaceIndex);
        }
        return "-";
    }
    
    /**
     * Extract URL/path from request payload
     */
    public String getUrl() {
        if (!isRequest() || payload == null || payload.length == 0) {
            return "-";
        }
        String payloadStr = new String(payload);
        int firstSpace = payloadStr.indexOf(' ');
        if (firstSpace > 0) {
            int secondSpace = payloadStr.indexOf(' ', firstSpace + 1);
            if (secondSpace > firstSpace) {
                return payloadStr.substring(firstSpace + 1, secondSpace);
            }
        }
        return "-";
    }
    
    /**
     * Extract status code from response payload
     */
    public String getStatusCode() {
        if (!isResponse() || payload == null || payload.length == 0) {
            return "-";
        }
        String payloadStr = new String(payload);
        // HTTP/1.1 200 OK or HTTP/2 200
        int firstSpace = payloadStr.indexOf(' ');
        if (firstSpace > 0) {
            int secondSpace = payloadStr.indexOf(' ', firstSpace + 1);
            int endIndex = secondSpace > firstSpace ? secondSpace : Math.min(payloadStr.length(), firstSpace + 4);
            if (endIndex > firstSpace + 1) {
                return payloadStr.substring(firstSpace + 1, endIndex).trim();
            }
        }
        return "-";
    }
    
    /**
     * Extract Host header from HTTP request
     */
    public String getHost() {
        if (payload == null || payload.length == 0) {
            return dstIp;
        }
        String payloadStr = new String(payload);
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
        return dstIp;
    }
    
    @Override
    public String toString() {
        return String.format("CapturedEvent[uuid=%s, type=%s, %s -> %s, process=%s(%d), len=%d]",
                uuid, eventType.getDescription(), getSource(), getDestination(), processName, pid, length);
    }
}

