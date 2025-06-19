package com.perimeterx.mobile_sdk.configurations;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.NoWhenBranchMatchedException;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class l {
    public static final l a;
    public static final l b;
    public static final /* synthetic */ l[] c;

    static {
        l lVar = new l("FIRST_PARAM", 0);
        a = lVar;
        l lVar2 = new l("OTHER_PARAM", 1);
        b = lVar2;
        l[] lVarArr = {lVar, lVar2};
        c = lVarArr;
        AbstractC3328d.f(lVarArr);
    }

    public static l valueOf(String str) {
        return (l) Enum.valueOf(l.class, str);
    }

    public static l[] values() {
        return (l[]) c.clone();
    }

    public final String a() {
        int iOrdinal = ordinal();
        if (iOrdinal == 0) {
            return "?";
        }
        if (iOrdinal == 1) {
            return "&";
        }
        throw new NoWhenBranchMatchedException();
    }
}
