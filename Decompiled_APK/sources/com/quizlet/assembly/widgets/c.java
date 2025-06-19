package com.quizlet.assembly.widgets;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class c {
    public static final com.quizlet.shared.usecase.folderstudymaterials.c b;
    public static final c c;
    public static final c d;
    public static final c e;
    public static final /* synthetic */ c[] f;
    public final int a;

    static {
        c cVar = new c("DEFAULT", 0, 0);
        c = cVar;
        c cVar2 = new c("CORAL", 1, 1);
        c cVar3 = new c("PLUS", 2, 2);
        d = cVar3;
        c cVar4 = new c("MINT", 3, 3);
        c cVar5 = new c("SHERBERT", 4, 4);
        c cVar6 = new c("GRAY", 5, 5);
        c cVar7 = new c("VERIFIED", 6, 6);
        e = cVar7;
        c[] cVarArr = {cVar, cVar2, cVar3, cVar4, cVar5, cVar6, cVar7, new c("SUBTLE", 7, 7), new c("CALLOUT", 8, 8)};
        f = cVarArr;
        AbstractC3328d.f(cVarArr);
        b = new com.quizlet.shared.usecase.folderstudymaterials.c(23);
    }

    public c(String str, int i, int i2) {
        this.a = i2;
    }

    public static c valueOf(String str) {
        return (c) Enum.valueOf(c.class, str);
    }

    public static c[] values() {
        return (c[]) f.clone();
    }
}
