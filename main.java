public abstract class LogEntry {
    private final LocalDateTime timestamp;
    private final String sourceIp;
    private final String logLevel;

    public LogEntry(LocalDateTime timestamp, String sourceIp, String logLevel) {
        this.timestamp = timestamp;
        this.sourceIp = sourceIp;
        this.logLevel = logLevel;
    }
