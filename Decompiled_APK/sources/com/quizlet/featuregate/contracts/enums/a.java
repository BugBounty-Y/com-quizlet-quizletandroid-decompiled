package com.quizlet.featuregate.contracts.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class a {
    public static final a a;
    public static final a b;
    public static final /* synthetic */ a[] c;
    public static final /* synthetic */ kotlin.enums.b d;

    static {
        a aVar = new a("OFF", 0);
        a = aVar;
        a aVar2 = new a("MEXICAN_SPANISH", 1);
        b = aVar2;
        a[] aVarArr = {aVar, aVar2, new a("BR_PT_LEARN_APRENDA", 2), new a("BR_PT_LEARN_TREINE", 3), new a("BR_PT_LEARN_ESTUDE", 4)};
        c = aVarArr;
        d = AbstractC3328d.f(aVarArr);
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) c.clone();
    }
}
