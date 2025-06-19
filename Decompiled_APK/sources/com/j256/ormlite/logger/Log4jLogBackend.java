package com.j256.ormlite.logger;

/* loaded from: classes2.dex */
public class Log4jLogBackend implements LogBackend {
    private final org.apache.log4j.Logger logger;

    /* renamed from: com.j256.ormlite.logger.Log4jLogBackend$1, reason: invalid class name */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$j256$ormlite$logger$Level;

        static {
            int[] iArr = new int[Level.values().length];
            $SwitchMap$com$j256$ormlite$logger$Level = iArr;
            try {
                iArr[Level.TRACE.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$com$j256$ormlite$logger$Level[Level.DEBUG.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$com$j256$ormlite$logger$Level[Level.WARNING.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                $SwitchMap$com$j256$ormlite$logger$Level[Level.ERROR.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                $SwitchMap$com$j256$ormlite$logger$Level[Level.FATAL.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                $SwitchMap$com$j256$ormlite$logger$Level[Level.INFO.ordinal()] = 6;
            } catch (NoSuchFieldError unused6) {
            }
        }
    }

    public static class Log4jLogBackendFactory implements LogBackendFactory {
        @Override // com.j256.ormlite.logger.LogBackendFactory
        public LogBackend createLogBackend(String str) {
            return new Log4jLogBackend(str);
        }
    }

    public Log4jLogBackend(String str) {
        this.logger = org.apache.log4j.Logger.getLogger(str);
    }

    private org.apache.log4j.Level levelToLog4jLevel(Level level) {
        int i = AnonymousClass1.$SwitchMap$com$j256$ormlite$logger$Level[level.ordinal()];
        return i != 1 ? i != 2 ? i != 3 ? i != 4 ? i != 5 ? org.apache.log4j.Level.INFO : org.apache.log4j.Level.FATAL : org.apache.log4j.Level.ERROR : org.apache.log4j.Level.WARN : org.apache.log4j.Level.DEBUG : org.apache.log4j.Level.TRACE;
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public boolean isLevelEnabled(Level level) {
        return this.logger.isEnabledFor(levelToLog4jLevel(level));
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public void log(Level level, String str) {
        this.logger.log(levelToLog4jLevel(level), str);
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public void log(Level level, String str, Throwable th) {
        this.logger.log(levelToLog4jLevel(level), str, th);
    }
}
