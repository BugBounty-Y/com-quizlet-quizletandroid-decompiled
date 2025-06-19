package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class K1 {
    public static final C4170u0 a;
    public static final K1 b;
    public static final K1 c;
    public static final K1 d;
    public static final /* synthetic */ K1[] e;

    static {
        K1 k1 = new K1("EMPTY", 0);
        b = k1;
        K1 k12 = new K1("NORMAL", 1);
        c = k12;
        K1 k13 = new K1("OVERFLOW", 2);
        d = k13;
        K1[] k1Arr = {k1, k12, k13};
        e = k1Arr;
        AbstractC3328d.f(k1Arr);
        a = new C4170u0();
    }

    public static K1 valueOf(String str) {
        return (K1) Enum.valueOf(K1.class, str);
    }

    public static K1[] values() {
        return (K1[]) e.clone();
    }
}
