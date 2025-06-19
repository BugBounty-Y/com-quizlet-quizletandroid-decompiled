package com.perimeterx.mobile_sdk.reachability;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.google.firebase.heartbeatinfo.e;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class a {
    public static final e a;
    public static final a b;
    public static final a c;
    public static final /* synthetic */ a[] d;

    static {
        a aVar = new a("WIFI", 0);
        b = aVar;
        a aVar2 = new a("CELLULAR", 1);
        c = aVar2;
        a[] aVarArr = {aVar, aVar2};
        d = aVarArr;
        AbstractC3328d.f(aVarArr);
        a = new e(23);
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) d.clone();
    }
}
