package com.perimeterx.mobile_sdk.configurations;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class m {
    public static final /* synthetic */ m[] a;

    static {
        m[] mVarArr = {new m("SHA_1", 0), new m("SHA_256", 1), new m("SHA_512", 2)};
        a = mVarArr;
        AbstractC3328d.f(mVarArr);
    }

    public static m valueOf(String str) {
        return (m) Enum.valueOf(m.class, str);
    }

    public static m[] values() {
        return (m[]) a.clone();
    }
}
