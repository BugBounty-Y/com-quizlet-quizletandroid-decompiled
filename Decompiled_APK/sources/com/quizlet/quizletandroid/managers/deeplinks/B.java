package com.quizlet.quizletandroid.managers.deeplinks;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class B {
    public static final B a;
    public static final B b;
    public static final /* synthetic */ B[] c;

    static {
        B b2 = new B("LOGGED_IN_INVALID_JOIN_LINK", 0);
        a = b2;
        B b3 = new B("LOGGED_OUT_INVALID_JOIN_LINK", 1);
        b = b3;
        B[] bArr = {b2, b3, new B("LOGGED_OUT", 2)};
        c = bArr;
        AbstractC3328d.f(bArr);
    }

    public static B valueOf(String str) {
        return (B) Enum.valueOf(B.class, str);
    }

    public static B[] values() {
        return (B[]) c.clone();
    }
}
