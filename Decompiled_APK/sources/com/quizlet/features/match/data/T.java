package com.quizlet.features.match.data;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class T {
    public static final T a;
    public static final T b;
    public static final T c;
    public static final /* synthetic */ T[] d;

    static {
        T t = new T("NoSelected", 0);
        a = t;
        T t2 = new T("HasSelected", 1);
        b = t2;
        T t3 = new T("StudySelected", 2);
        c = t3;
        T[] tArr = {t, t2, t3};
        d = tArr;
        AbstractC3328d.f(tArr);
    }

    public static T valueOf(String str) {
        return (T) Enum.valueOf(T.class, str);
    }

    public static T[] values() {
        return (T[]) d.clone();
    }
}
