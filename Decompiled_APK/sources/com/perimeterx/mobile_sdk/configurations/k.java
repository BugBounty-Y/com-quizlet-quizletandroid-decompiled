package com.perimeterx.mobile_sdk.configurations;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class k {
    public static final /* synthetic */ k[] a;

    static {
        k[] kVarArr = {new k("WWW", 0), new k("DOT", 1)};
        a = kVarArr;
        AbstractC3328d.f(kVarArr);
    }

    public static k valueOf(String str) {
        return (k) Enum.valueOf(k.class, str);
    }

    public static k[] values() {
        return (k[]) a.clone();
    }
}
