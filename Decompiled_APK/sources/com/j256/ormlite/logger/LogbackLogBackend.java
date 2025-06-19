package com.j256.ormlite.logger;

import org.slf4j.a;
import org.slf4j.b;

/* loaded from: classes2.dex */
public class LogbackLogBackend implements LogBackend {
    private final b logger;

    /* renamed from: com.j256.ormlite.logger.LogbackLogBackend$1, reason: invalid class name */
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

    public static class LogbackLogBackendFactory implements LogBackendFactory {
        private final a factory = org.slf4j.impl.a.b.a;

        @Override // com.j256.ormlite.logger.LogBackendFactory
        public LogBackend createLogBackend(String str) {
            return new LogbackLogBackend(this.factory.a(str));
        }
    }

    public LogbackLogBackend(b bVar) {
        this.logger = bVar;
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public boolean isLevelEnabled(Level level) {
        int i = AnonymousClass1.$SwitchMap$com$j256$ormlite$logger$Level[level.ordinal()];
        if (i == 1) {
            return this.logger.g();
        }
        if (i == 2) {
            return this.logger.b();
        }
        if (i == 3) {
            return this.logger.a();
        }
        if (i != 4 && i != 5) {
            return this.logger.e();
        }
        return this.logger.d();
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public void log(Level level, String str) {
        int i = AnonymousClass1.$SwitchMap$com$j256$ormlite$logger$Level[level.ordinal()];
        if (i == 1) {
            this.logger.n(str);
            return;
        }
        if (i == 2) {
            this.logger.f(str);
            return;
        }
        if (i == 3) {
            this.logger.warn(str);
            return;
        }
        if (i == 4) {
            this.logger.error(str);
        } else if (i != 5) {
            this.logger.m(str);
        } else {
            this.logger.error(str);
        }
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public void log(Level level, String str, Throwable th) {
        int i = AnonymousClass1.$SwitchMap$com$j256$ormlite$logger$Level[level.ordinal()];
        if (i == 1) {
            this.logger.k(str, th);
            return;
        }
        if (i == 2) {
            this.logger.l(str, th);
            return;
        }
        if (i == 3) {
            this.logger.j(str, th);
            return;
        }
        if (i == 4) {
            this.logger.c(str, th);
        } else if (i != 5) {
            this.logger.h(str, th);
        } else {
            this.logger.c(str, th);
        }
    }
}
