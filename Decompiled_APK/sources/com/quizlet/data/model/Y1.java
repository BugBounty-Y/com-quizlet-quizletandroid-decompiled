package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class Y1 {
    public static final Y1 a;
    public static final Y1 b;
    public static final Y1 c;
    public static final Y1 d;
    public static final /* synthetic */ Y1[] e;
    public static final /* synthetic */ kotlin.enums.b f;

    static {
        Y1 y1 = new Y1("ALL", 0);
        a = y1;
        Y1 y12 = new Y1("CREATED", 1);
        b = y12;
        Y1 y13 = new Y1("STUDIED", 2);
        c = y13;
        Y1 y14 = new Y1("DOWNLOADED", 3);
        d = y14;
        Y1[] y1Arr = {y1, y12, y13, y14};
        e = y1Arr;
        f = AbstractC3328d.f(y1Arr);
    }

    public static Y1 valueOf(String str) {
        return (Y1) Enum.valueOf(Y1.class, str);
    }

    public static Y1[] values() {
        return (Y1[]) e.clone();
    }
}
