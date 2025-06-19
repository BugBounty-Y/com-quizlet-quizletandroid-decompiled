package com.quizlet.features.setpage.progress;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a {
    public static final a b;
    public static final a c;
    public static final a d;
    public static final /* synthetic */ a[] e;
    public final String a;

    static {
        a aVar = new a("NOT_STUDIED", 0, "notStudied");
        b = aVar;
        a aVar2 = new a("STILL_LEARNING", 1, "stillLearning");
        c = aVar2;
        a aVar3 = new a("MASTERED", 2, "mastered");
        d = aVar3;
        a[] aVarArr = {aVar, aVar2, aVar3};
        e = aVarArr;
        AbstractC3328d.f(aVarArr);
    }

    public a(String str, int i, String str2) {
        this.a = str2;
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) e.clone();
    }
}
