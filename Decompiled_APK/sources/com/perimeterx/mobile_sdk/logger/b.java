package com.perimeterx.mobile_sdk.logger;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class b {
    public static final b a;
    public static final /* synthetic */ b[] b;

    static {
        b bVar = new b("INFO", 0);
        b bVar2 = new b("ERROR", 1);
        a = bVar2;
        b[] bVarArr = {bVar, bVar2};
        b = bVarArr;
        AbstractC3328d.f(bVarArr);
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) b.clone();
    }
}
