package com.ecapture.burp.event;

/**
 * Represents a matched HTTP request-response pair.
 */
public class MatchedHttpPair {
    
    private final String uuid;
    private CapturedEvent request;
    private CapturedEvent response;
    private final long createdAt;
    private boolean sentToProxy;
    
    public MatchedHttpPair(String uuid) {
        this.uuid = uuid;
        this.createdAt = System.currentTimeMillis();
        this.sentToProxy = false;
    }
    
    public String getUuid() {
        return uuid;
    }
    
    public CapturedEvent getRequest() {
        return request;
    }
    
    public void setRequest(CapturedEvent request) {
        this.request = request;
    }
    
    public CapturedEvent getResponse() {
        return response;
    }
    
    public void setResponse(CapturedEvent response) {
        this.response = response;
    }
    
    public boolean hasRequest() {
        return request != null;
    }
    
    public boolean hasResponse() {
        return response != null;
    }
    
    public boolean isComplete() {
        return hasRequest() && hasResponse();
    }
    
    public long getCreatedAt() {
        return createdAt;
    }
    
    public boolean isSentToProxy() {
        return sentToProxy;
    }
    
    public void setSentToProxy(boolean sentToProxy) {
        this.sentToProxy = sentToProxy;
    }
    
    /**
     * Get display timestamp (from request if available, otherwise response)
     */
    public String getTimestamp() {
        try {
            if (request != null && request.getTimestamp() > 0) {
                return request.getFormattedTimestamp();
            } else if (response != null && response.getTimestamp() > 0) {
                return response.getFormattedTimestamp();
            }
        } catch (Exception e) {
            // Timestamp conversion failed
        }
        // Fallback to current time
        return java.time.LocalDateTime.now().format(
                java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }
    
    /**
     * Get HTTP method from request
     */
    public String getMethod() {
        return request != null ? request.getHttpMethod() : "-";
    }
    
    /**
     * Get URL from request
     */
    public String getUrl() {
        return request != null ? request.getUrl() : "-";
    }
    
    /**
     * Get host from request
     */
    public String getHost() {
        if (request != null) {
            return request.getHost();
        } else if (response != null) {
            return response.getDstIp();
        }
        return "-";
    }
    
    /**
     * Get status code from response
     */
    public String getStatusCode() {
        return response != null ? response.getStatusCode() : "-";
    }
    
    /**
     * Get request length
     */
    public int getRequestLength() {
        return request != null ? request.getLength() : 0;
    }
    
    /**
     * Get response length
     */
    public int getResponseLength() {
        return response != null ? response.getLength() : 0;
    }
    
    /**
     * Get process info
     */
    public String getProcessInfo() {
        if (request != null) {
            return request.getProcessName() + " (" + request.getPid() + ")";
        } else if (response != null) {
            return response.getProcessName() + " (" + response.getPid() + ")";
        }
        return "-";
    }
    
    /**
     * Get destination port (typically the server port)
     */
    public int getPort() {
        if (request != null) {
            return request.getDstPort();
        } else if (response != null) {
            return response.getSrcPort();
        }
        return 0;
    }
    
    /**
     * Check if this is HTTPS (based on port heuristics)
     */
    public boolean isHttps() {
        int port = getPort();
        return port == 443 || port == 8443;
    }
    
    /**
     * Get protocol string: HTTP/1.x or HTTP/2 if detectable from events.
     */
    public String getProtocol() {
        // Prefer request's eventType if available
        if (request != null) {
            switch (request.getEventType()) {
                case HTTP2_REQUEST:
                case AUTO_REQUEST:
                    return "HTTP/2";
                case HTTP1_REQUEST:
                    return "HTTP/1.x";
                default:
                    break;
            }
        }
        if (response != null) {
            switch (response.getEventType()) {
                case HTTP2_RESPONSE:
                case AUTO_RESPONSE:
                    return "HTTP/2";
                case HTTP1_RESPONSE:
                    return "HTTP/1.x";
                default:
                    break;
            }
        }
        // fallback to port heuristic or content
        if (isHttps()) return "HTTPS";
        return "Unknown";
    }

    @Override
    public String toString() {
        return String.format("MatchedHttpPair[uuid=%s, method=%s, url=%s, status=%s, complete=%s]",
                uuid, getMethod(), getUrl(), getStatusCode(), isComplete());
    }
}

