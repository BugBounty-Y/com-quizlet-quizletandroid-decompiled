package com.perimeterx.mobile_sdk.web_view_interception;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class a {
    public static final com.google.firebase.perf.logging.b a;
    public static final /* synthetic */ a[] b;

    static {
        a[] aVarArr = {new a("VID", 0), new a("TOKEN", 1), new a("WEB_WITH_MOBILE", 2), new a("HD", 3)};
        b = aVarArr;
        AbstractC3328d.f(aVarArr);
        a = new com.google.firebase.perf.logging.b(23);
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) b.clone();
    }
}
