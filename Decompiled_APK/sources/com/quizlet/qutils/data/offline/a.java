package com.quizlet.qutils.data.offline;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a {
    public static final a a;
    public static final a b;
    public static final a c;
    public static final a d;
    public static final /* synthetic */ a[] e;

    static {
        a aVar = new a("ALWAYS", 0);
        a = aVar;
        a aVar2 = new a("IF_MISSING", 1);
        b = aVar2;
        a aVar3 = new a("UNDECIDED", 2);
        c = aVar3;
        a aVar4 = new a("NO", 3);
        d = aVar4;
        a[] aVarArr = {aVar, aVar2, aVar3, aVar4};
        e = aVarArr;
        AbstractC3328d.f(aVarArr);
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) e.clone();
    }
}
