package com.j256.ormlite.logger;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/* loaded from: classes2.dex */
public class CommonsLoggingLogBackend implements LogBackend {
    private final Log log;

    /* renamed from: com.j256.ormlite.logger.CommonsLoggingLogBackend$1, reason: invalid class name */
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

    public static class CommonsLoggingLogBackendFactory implements LogBackendFactory {
        @Override // com.j256.ormlite.logger.LogBackendFactory
        public LogBackend createLogBackend(String str) {
            return new CommonsLoggingLogBackend(str);
        }
    }

    public CommonsLoggingLogBackend(String str) {
        this.log = LogFactory.getLog(str);
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public boolean isLevelEnabled(Level level) {
        int i = AnonymousClass1.$SwitchMap$com$j256$ormlite$logger$Level[level.ordinal()];
        return i != 1 ? i != 2 ? i != 3 ? i != 4 ? i != 5 ? this.log.isInfoEnabled() : this.log.isFatalEnabled() : this.log.isErrorEnabled() : this.log.isWarnEnabled() : this.log.isDebugEnabled() : this.log.isTraceEnabled();
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public void log(Level level, String str) {
        int i = AnonymousClass1.$SwitchMap$com$j256$ormlite$logger$Level[level.ordinal()];
        if (i == 1) {
            this.log.trace(str);
            return;
        }
        if (i == 2) {
            this.log.debug(str);
            return;
        }
        if (i == 3) {
            this.log.warn(str);
            return;
        }
        if (i == 4) {
            this.log.error(str);
        } else if (i != 5) {
            this.log.info(str);
        } else {
            this.log.fatal(str);
        }
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public void log(Level level, String str, Throwable th) {
        int i = AnonymousClass1.$SwitchMap$com$j256$ormlite$logger$Level[level.ordinal()];
        if (i == 1) {
            this.log.trace(str, th);
            return;
        }
        if (i == 2) {
            this.log.debug(str, th);
            return;
        }
        if (i == 3) {
            this.log.warn(str, th);
            return;
        }
        if (i == 4) {
            this.log.error(str, th);
        } else if (i != 5) {
            this.log.info(str, th);
        } else {
            this.log.fatal(str, th);
        }
    }
}
