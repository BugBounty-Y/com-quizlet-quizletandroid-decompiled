package com.j256.ormlite.logger;

/* loaded from: classes2.dex */
public class JavaUtilLogBackend implements LogBackend {
    private final java.util.logging.Logger logger;

    /* renamed from: com.j256.ormlite.logger.JavaUtilLogBackend$1, reason: invalid class name */
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

    public static class JavaUtilLogBackendFactory implements LogBackendFactory {
        @Override // com.j256.ormlite.logger.LogBackendFactory
        public LogBackend createLogBackend(String str) {
            return new JavaUtilLogBackend(str);
        }
    }

    public JavaUtilLogBackend(String str) {
        this.logger = java.util.logging.Logger.getLogger(str);
    }

    private java.util.logging.Level levelToJavaLevel(Level level) {
        int i = AnonymousClass1.$SwitchMap$com$j256$ormlite$logger$Level[level.ordinal()];
        if (i == 1) {
            return java.util.logging.Level.FINER;
        }
        if (i == 2) {
            return java.util.logging.Level.FINE;
        }
        if (i == 3) {
            return java.util.logging.Level.WARNING;
        }
        if (i != 4 && i != 5) {
            return java.util.logging.Level.INFO;
        }
        return java.util.logging.Level.SEVERE;
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public boolean isLevelEnabled(Level level) {
        return this.logger.isLoggable(levelToJavaLevel(level));
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public void log(Level level, String str) {
        this.logger.log(levelToJavaLevel(level), str);
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public void log(Level level, String str, Throwable th) {
        this.logger.log(levelToJavaLevel(level), str, th);
    }
}
