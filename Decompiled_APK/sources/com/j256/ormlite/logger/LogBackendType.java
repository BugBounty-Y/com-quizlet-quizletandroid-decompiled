package com.j256.ormlite.logger;

import com.j256.ormlite.logger.LocalLogBackend;
import com.j256.ormlite.logger.NullLogBackend;

/* loaded from: classes2.dex */
public enum LogBackendType implements LogBackendFactory {
    SLF4J("com.j256.ormlite.logger.Slf4jLoggingLogBackend$Slf4jLoggingLogBackendFactory"),
    ANDROID("com.j256.ormlite.android.AndroidLogBackend$AndroidLogBackendFactory"),
    LOGBACK("com.j256.ormlite.logger.LogbackLogBackend$LogbackLogBackendFactory"),
    COMMONS_LOGGING("com.j256.ormlite.logger.CommonsLoggingLogBackend$CommonsLoggingLogBackendFactory"),
    LOG4J2("com.j256.ormlite.logger.Log4j2LogBackend$Log4j2LogBackendFactory"),
    LOG4J("com.j256.ormlite.logger.Log4jLogBackend$Log4jLogBackendFactory"),
    LOCAL(new LocalLogBackend.LocalLogBackendFactory()),
    CONSOLE(new LogBackendFactory() { // from class: com.j256.ormlite.logger.ConsoleLogBackend.ConsoleLogBackendFactory
        @Override // com.j256.ormlite.logger.LogBackendFactory
        public LogBackend createLogBackend(String str) {
            return new ConsoleLogBackend(str);
        }
    }),
    JAVA_UTIL("com.j256.ormlite.logger.JavaUtilLogBackend$JavaUtilLogBackendFactory"),
    NULL(new NullLogBackend.NullLogBackendFactory());

    private final LogBackendFactory factory;

    LogBackendType(LogBackendFactory logBackendFactory) {
        this.factory = logBackendFactory;
    }

    private LogBackendFactory detectFactory(String str) {
        try {
            LogBackendFactory logBackendFactory = (LogBackendFactory) Class.forName(str).newInstance();
            logBackendFactory.createLogBackend("test").isLevelEnabled(Level.INFO);
            return logBackendFactory;
        } catch (Throwable th) {
            return new LocalLogBackend.LocalLogBackendFactory("Unable to create instance of class " + str + " for log type " + this + ", using local log: " + th.getMessage());
        }
    }

    @Override // com.j256.ormlite.logger.LogBackendFactory
    public LogBackend createLogBackend(String str) {
        return this.factory.createLogBackend(str);
    }

    public boolean isAvailable() {
        if (this != LOCAL) {
            return (this == NULL || (this.factory instanceof LocalLogBackend.LocalLogBackendFactory)) ? false : true;
        }
        return true;
    }

    LogBackendType(String str) {
        this.factory = detectFactory(str);
    }
}
