package com.quizlet.studiablemodels.assistantMode;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a {
    public static final a a;
    public static final a b;
    public static final a c;
    public static final /* synthetic */ a[] d;

    static {
        a aVar = new a("FAMILIARITY", 0);
        a aVar2 = new a("MEMORIZATION", 1);
        a = aVar2;
        a aVar3 = new a("CHALLENGE", 2);
        b = aVar3;
        a aVar4 = new a("UNDERSTANDING", 3);
        c = aVar4;
        a[] aVarArr = {aVar, aVar2, aVar3, aVar4};
        d = aVarArr;
        AbstractC3328d.f(aVarArr);
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) d.clone();
    }
}
