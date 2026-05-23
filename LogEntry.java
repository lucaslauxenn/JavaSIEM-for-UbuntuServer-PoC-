import java.time.LocalDateTime;

public abstract class LogEntry {
    private final LocalDateTime timestamp;
    private final String sourceIp;
    private final String logLevel;

    public LogEntry(LocalDateTime timestamp, String sourceIp, String logLevel) {
        this.timestamp = timestamp;
        this.sourceIp = sourceIp;
        this.logLevel = logLevel;
    }

    // getters para campos fixos
    public LocalDateTime getTimestamp() { return timestamp; }
    public String getSourceIp() { return sourceIp; }
    public String getLogLevel() { return logLevel; }

    // método abstrato: cada tipo de log tem seus detalhes específicos
    public abstract String getDetails();

    
}
}
