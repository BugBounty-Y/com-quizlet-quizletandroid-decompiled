package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class T {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ T[] $VALUES;
    public static final T EASY;
    public static final T HARD;
    public static final T MEDIUM;

    static {
        T t = new T("EASY", 0);
        EASY = t;
        T t2 = new T("MEDIUM", 1);
        MEDIUM = t2;
        T t3 = new T("HARD", 2);
        HARD = t3;
        T[] tArr = {t, t2, t3};
        $VALUES = tArr;
        $ENTRIES = AbstractC3328d.f(tArr);
    }

    public static T valueOf(String str) {
        return (T) Enum.valueOf(T.class, str);
    }

    public static T[] values() {
        return (T[]) $VALUES.clone();
    }
}
