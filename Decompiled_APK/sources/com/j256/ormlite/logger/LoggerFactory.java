package com.j256.ormlite.logger;

/* loaded from: classes2.dex */
public class LoggerFactory {
    public static final String LOG_TYPE_SYSTEM_PROPERTY = "com.j256.simplelogger.backend";
    private static LogBackendFactory logBackendFactory;

    private LoggerFactory() {
    }

    private static LogBackendFactory findLogBackendFactory() {
        String property = System.getProperty(LOG_TYPE_SYSTEM_PROPERTY);
        if (property != null) {
            try {
                return LogBackendType.valueOf(property);
            } catch (IllegalArgumentException unused) {
                new LocalLogBackend(LoggerFactory.class.getName()).log(Level.WARNING, "Could not find valid log-type from system property 'com.j256.simplelogger.backend', value '" + property + "'");
            }
        }
        for (LogBackendType logBackendType : LogBackendType.values()) {
            if (logBackendType.isAvailable()) {
                return logBackendType;
            }
        }
        return LogBackendType.LOCAL;
    }

    public static LogBackendFactory getLogBackendFactory() {
        return logBackendFactory;
    }

    public static Logger getLogger(Class<?> cls) {
        return getLogger(cls.getName());
    }

    public static String getSimpleClassName(String str) {
        int iLastIndexOf = str.lastIndexOf(46);
        return (iLastIndexOf < 0 || iLastIndexOf == str.length() + (-1)) ? str : str.substring(iLastIndexOf + 1);
    }

    public static void setLogBackendFactory(LogBackendFactory logBackendFactory2) {
        logBackendFactory = logBackendFactory2;
    }

    public static void setLogBackendType(LogBackendType logBackendType) {
        if (logBackendType.isAvailable()) {
            logBackendFactory = logBackendType;
            return;
        }
        throw new IllegalArgumentException("Logging backend type " + logBackendType + " is not available on the classpath");
    }

    public static Logger getLogger(String str) {
        if (logBackendFactory == null) {
            logBackendFactory = findLogBackendFactory();
        }
        return new Logger(logBackendFactory.createLogBackend(str));
    }
}
