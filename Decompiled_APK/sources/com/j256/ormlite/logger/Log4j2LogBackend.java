package com.j256.ormlite.logger;

import org.apache.logging.log4j.LogManager;

/* loaded from: classes2.dex */
public class Log4j2LogBackend implements LogBackend {
    private final org.apache.logging.log4j.Logger logger;

    /* renamed from: com.j256.ormlite.logger.Log4j2LogBackend$1, reason: invalid class name */
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

    public static class Log4j2LogBackendFactory implements LogBackendFactory {
        @Override // com.j256.ormlite.logger.LogBackendFactory
        public LogBackend createLogBackend(String str) {
            return new Log4j2LogBackend(str);
        }
    }

    public Log4j2LogBackend(String str) {
        this.logger = LogManager.getLogger(str);
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public boolean isLevelEnabled(Level level) {
        int i = AnonymousClass1.$SwitchMap$com$j256$ormlite$logger$Level[level.ordinal()];
        return i != 1 ? i != 2 ? i != 3 ? i != 4 ? i != 5 ? this.logger.isInfoEnabled() : this.logger.isFatalEnabled() : this.logger.isErrorEnabled() : this.logger.isWarnEnabled() : this.logger.isDebugEnabled() : this.logger.isTraceEnabled();
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public void log(Level level, String str) {
        int i = AnonymousClass1.$SwitchMap$com$j256$ormlite$logger$Level[level.ordinal()];
        if (i == 1) {
            this.logger.trace(str);
            return;
        }
        if (i == 2) {
            this.logger.debug(str);
            return;
        }
        if (i == 3) {
            this.logger.warn(str);
            return;
        }
        if (i == 4) {
            this.logger.error(str);
        } else if (i != 5) {
            this.logger.info(str);
        } else {
            this.logger.fatal(str);
        }
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public void log(Level level, String str, Throwable th) {
        int i = AnonymousClass1.$SwitchMap$com$j256$ormlite$logger$Level[level.ordinal()];
        if (i == 1) {
            this.logger.trace(str, th);
            return;
        }
        if (i == 2) {
            this.logger.debug(str, th);
            return;
        }
        if (i == 3) {
            this.logger.warn(str, th);
            return;
        }
        if (i == 4) {
            this.logger.error(str, th);
        } else if (i != 5) {
            this.logger.info(str, th);
        } else {
            this.logger.fatal(str, th);
        }
    }
}
