package com.perimeterx.mobile_sdk.doctor_app.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class h {
    public static final h a;
    public static final h b;
    public static final h c;
    public static final /* synthetic */ h[] d;

    static {
        h hVar = new h("SUCCESS", 0);
        a = hVar;
        h hVar2 = new h("FAILURE", 1);
        b = hVar2;
        h hVar3 = new h("SKIPPED", 2);
        c = hVar3;
        h[] hVarArr = {hVar, hVar2, hVar3};
        d = hVarArr;
        AbstractC3328d.f(hVarArr);
    }

    public static h valueOf(String str) {
        return (h) Enum.valueOf(h.class, str);
    }

    public static h[] values() {
        return (h[]) d.clone();
    }
}
