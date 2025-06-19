package com.quizlet.assembly.widgets;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class a {
    public static final com.quizlet.shared.usecase.folderstudymaterials.a b;
    public static final a c;
    public static final a d;
    public static final /* synthetic */ a[] e;
    public final int a;

    static {
        a aVar = new a("DEFAULT", 0, 0);
        c = aVar;
        a aVar2 = new a("INDIGO", 1, 1);
        a aVar3 = new a("INDIGO_BG", 2, 2);
        d = aVar3;
        a[] aVarArr = {aVar, aVar2, aVar3, new a("YELLOW", 3, 3), new a("WHITE", 4, 4)};
        e = aVarArr;
        AbstractC3328d.f(aVarArr);
        b = new com.quizlet.shared.usecase.folderstudymaterials.a(23);
    }

    public a(String str, int i, int i2) {
        this.a = i2;
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) e.clone();
    }
}
