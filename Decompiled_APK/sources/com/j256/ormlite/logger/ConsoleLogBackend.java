package com.j256.ormlite.logger;

/* loaded from: classes2.dex */
public class ConsoleLogBackend implements LogBackend {
    private static final String LINE_SEPARATOR = System.lineSeparator();
    private String className;

    public ConsoleLogBackend(String str) {
        this.className = str;
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public boolean isLevelEnabled(Level level) {
        return true;
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public void log(Level level, String str) {
        String str2 = this.className + ' ' + level + ' ' + str + LINE_SEPARATOR;
        if (Level.WARNING.isEnabled(level)) {
            System.err.print(str2);
        } else {
            System.out.print(str2);
        }
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public void log(Level level, String str, Throwable th) {
        log(level, str);
        if (th != null) {
            log(level, LogBackendUtil.throwableToString(th));
        }
    }
}
