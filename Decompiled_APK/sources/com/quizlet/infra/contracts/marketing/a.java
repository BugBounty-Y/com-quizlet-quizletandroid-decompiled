package com.quizlet.infra.contracts.marketing;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a {
    public static final a a;
    public static final a b;
    public static final /* synthetic */ a[] c;

    static {
        a aVar = new a("SIGN_UP", 0);
        a = aVar;
        a aVar2 = new a("START_TRIAL", 1);
        a aVar3 = new a("LOGIN", 2);
        b = aVar3;
        a[] aVarArr = {aVar, aVar2, aVar3, new a("SUBSCRIPTION", 3)};
        c = aVarArr;
        AbstractC3328d.f(aVarArr);
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) c.clone();
    }
}
