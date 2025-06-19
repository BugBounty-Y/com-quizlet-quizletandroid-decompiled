package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class A0 {
    public static final A0 a;
    public static final A0 b;
    public static final A0 c;
    public static final /* synthetic */ A0[] d;

    static {
        A0 a0 = new A0("LOCKED", 0);
        a = a0;
        A0 a02 = new A0("NONE", 1);
        b = a02;
        A0 a03 = new A0("BETA", 2);
        c = a03;
        A0[] a0Arr = {a0, a02, a03};
        d = a0Arr;
        AbstractC3328d.f(a0Arr);
    }

    public static A0 valueOf(String str) {
        return (A0) Enum.valueOf(A0.class, str);
    }

    public static A0[] values() {
        return (A0[]) d.clone();
    }
}
