package com.j256.ormlite.android;

import android.util.Log;
import com.j256.ormlite.logger.Level;
import com.j256.ormlite.logger.LogBackend;
import com.j256.ormlite.logger.LogBackendFactory;
import com.j256.ormlite.logger.LoggerFactory;

/* loaded from: classes2.dex */
public class AndroidLogBackend implements LogBackend {
    private static final String ALL_LOGS_NAME = "ORMLite";
    private static final int MAX_TAG_LENGTH = 23;
    private static final int REFRESH_LEVEL_CACHE_EVERY = 200;
    private final String className;
    private final boolean[] levelCache;
    private volatile int levelCacheC = 0;

    /* renamed from: com.j256.ormlite.android.AndroidLogBackend$1, reason: invalid class name */
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

    public static class AndroidLogBackendFactory implements LogBackendFactory {
        @Override // com.j256.ormlite.logger.LogBackendFactory
        public LogBackend createLogBackend(String str) {
            return new AndroidLogBackend(str);
        }
    }

    public AndroidLogBackend(String str) {
        String simpleClassName = LoggerFactory.getSimpleClassName(str);
        int length = simpleClassName.length();
        this.className = length > 23 ? str.substring(length - 23, length) : simpleClassName;
        int i = 0;
        for (Level level : Level.values()) {
            int iLevelToAndroidLevel = levelToAndroidLevel(level);
            if (iLevelToAndroidLevel > i) {
                i = iLevelToAndroidLevel;
            }
        }
        this.levelCache = new boolean[i + 1];
        refreshLevelCache();
    }

    private boolean isLevelEnabledInternal(int i) {
        return Log.isLoggable(this.className, i) || Log.isLoggable(ALL_LOGS_NAME, i);
    }

    private int levelToAndroidLevel(Level level) {
        int i = AnonymousClass1.$SwitchMap$com$j256$ormlite$logger$Level[level.ordinal()];
        if (i == 1) {
            return 2;
        }
        if (i == 2) {
            return 3;
        }
        if (i != 3) {
            return (i == 4 || i == 5) ? 6 : 4;
        }
        return 5;
    }

    private void refreshLevelCache() {
        for (Level level : Level.values()) {
            int iLevelToAndroidLevel = levelToAndroidLevel(level);
            boolean[] zArr = this.levelCache;
            if (iLevelToAndroidLevel < zArr.length) {
                zArr[iLevelToAndroidLevel] = isLevelEnabledInternal(iLevelToAndroidLevel);
            }
        }
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public boolean isLevelEnabled(Level level) {
        int i = this.levelCacheC + 1;
        this.levelCacheC = i;
        if (i >= 200) {
            refreshLevelCache();
            this.levelCacheC = 0;
        }
        int iLevelToAndroidLevel = levelToAndroidLevel(level);
        boolean[] zArr = this.levelCache;
        return iLevelToAndroidLevel < zArr.length ? zArr[iLevelToAndroidLevel] : isLevelEnabledInternal(iLevelToAndroidLevel);
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public void log(Level level, String str) {
        int i = AnonymousClass1.$SwitchMap$com$j256$ormlite$logger$Level[level.ordinal()];
        if (i == 1 || i == 2) {
            return;
        }
        if (i == 3) {
            Log.w(this.className, str);
            return;
        }
        if (i == 4) {
            Log.e(this.className, str);
        } else if (i != 5) {
            Log.i(this.className, str);
        } else {
            Log.e(this.className, str);
        }
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public void log(Level level, String str, Throwable th) {
        int i = AnonymousClass1.$SwitchMap$com$j256$ormlite$logger$Level[level.ordinal()];
        if (i == 1 || i == 2) {
            return;
        }
        if (i == 3) {
            Log.w(this.className, str, th);
            return;
        }
        if (i == 4) {
            Log.e(this.className, str, th);
        } else if (i != 5) {
            Log.i(this.className, str, th);
        } else {
            Log.e(this.className, str, th);
        }
    }
}
