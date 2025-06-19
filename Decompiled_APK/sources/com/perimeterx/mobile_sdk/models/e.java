package com.perimeterx.mobile_sdk.models;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.NoWhenBranchMatchedException;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class e {
    public static final com.google.android.material.shape.e a;
    public static final e b;
    public static final e c;
    public static final e d;
    public static final /* synthetic */ e[] e;

    static {
        e eVar = new e("PX", 0);
        b = eVar;
        e eVar2 = new e("PX2", 1);
        c = eVar2;
        e eVar3 = new e("PX3", 2);
        d = eVar3;
        e[] eVarArr = {eVar, eVar2, eVar3};
        e = eVarArr;
        AbstractC3328d.f(eVarArr);
        a = new com.google.android.material.shape.e(23);
    }

    public static e valueOf(String str) {
        return (e) Enum.valueOf(e.class, str);
    }

    public static e[] values() {
        return (e[]) e.clone();
    }

    public final int a() {
        int iOrdinal = ordinal();
        if (iOrdinal == 0) {
            return 1;
        }
        if (iOrdinal == 1) {
            return 2;
        }
        if (iOrdinal == 2) {
            return 3;
        }
        throw new NoWhenBranchMatchedException();
    }

    public final String b() {
        int iOrdinal = ordinal();
        if (iOrdinal == 0) {
            return "_px";
        }
        if (iOrdinal == 1) {
            return "_px2";
        }
        if (iOrdinal == 2) {
            return "_px3";
        }
        throw new NoWhenBranchMatchedException();
    }
}
