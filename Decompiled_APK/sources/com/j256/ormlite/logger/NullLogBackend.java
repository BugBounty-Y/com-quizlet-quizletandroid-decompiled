package com.j256.ormlite.logger;

/* loaded from: classes2.dex */
public class NullLogBackend implements LogBackend {

    public static class NullLogBackendFactory implements LogBackendFactory {
        private static final NullLogBackend singleton = new NullLogBackend();

        @Override // com.j256.ormlite.logger.LogBackendFactory
        public LogBackend createLogBackend(String str) {
            return singleton;
        }
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public boolean isLevelEnabled(Level level) {
        return false;
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public void log(Level level, String str) {
    }

    @Override // com.j256.ormlite.logger.LogBackend
    public void log(Level level, String str, Throwable th) {
    }
}
