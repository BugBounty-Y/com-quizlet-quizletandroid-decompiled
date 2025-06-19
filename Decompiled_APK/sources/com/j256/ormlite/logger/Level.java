package com.j256.ormlite.logger;

/* loaded from: classes2.dex */
public enum Level {
    TRACE(1),
    DEBUG(2),
    INFO(3),
    WARNING(4),
    ERROR(5),
    FATAL(6),
    OFF(7);

    private final int value;

    Level(int i) {
        this.value = i;
    }

    public boolean isEnabled(Level level) {
        Level level2 = OFF;
        return (this == level2 || level == level2 || this.value > level.value) ? false : true;
    }
}
