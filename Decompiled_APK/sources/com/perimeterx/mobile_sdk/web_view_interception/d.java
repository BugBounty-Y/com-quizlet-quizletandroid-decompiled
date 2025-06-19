package com.perimeterx.mobile_sdk.web_view_interception;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.NoWhenBranchMatchedException;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class d {
    public static final com.google.mlkit.common.sdkinternal.b a;
    public static final d b;
    public static final d c;
    public static final d d;
    public static final /* synthetic */ d[] e;

    static {
        d dVar = new d("CAPTCHA", 0);
        b = dVar;
        d dVar2 = new d("HC", 1);
        c = dVar2;
        d dVar3 = new d("CP", 2);
        d = dVar3;
        d[] dVarArr = {dVar, dVar2, dVar3};
        e = dVarArr;
        AbstractC3328d.f(dVarArr);
        a = new com.google.mlkit.common.sdkinternal.b(23);
    }

    public static d valueOf(String str) {
        return (d) Enum.valueOf(d.class, str);
    }

    public static d[] values() {
        return (d[]) e.clone();
    }

    public final String a() {
        int iOrdinal = ordinal();
        if (iOrdinal == 0) {
            return "c";
        }
        if (iOrdinal == 1) {
            return "pxhc";
        }
        if (iOrdinal == 2) {
            return "pxcp";
        }
        throw new NoWhenBranchMatchedException();
    }
}
