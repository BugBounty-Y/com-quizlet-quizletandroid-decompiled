package com.quizlet.offline.managers;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class j {
    public static final j a;
    public static final j b;
    public static final /* synthetic */ j[] c;

    static {
        j jVar = new j("LAUNCH_NO_PROBLEM", 0);
        a = jVar;
        j jVar2 = new j("WARN_MISSING_CONTENT", 1);
        b = jVar2;
        c = new j[]{jVar, jVar2};
    }

    public static j valueOf(String str) {
        return (j) Enum.valueOf(j.class, str);
    }

    public static j[] values() {
        return (j[]) c.clone();
    }
}
