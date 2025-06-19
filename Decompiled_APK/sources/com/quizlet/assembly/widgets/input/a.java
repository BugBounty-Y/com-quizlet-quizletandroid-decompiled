package com.quizlet.assembly.widgets.input;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class a {
    public static final com.quizlet.shared.usecase.studiableMetadata.a b;
    public static final /* synthetic */ a[] c;
    public final int a;

    static {
        a[] aVarArr = {new a("DEFAULT", 0, 0), new a("NON_PERSISTENT_LABEL", 1, 1)};
        c = aVarArr;
        AbstractC3328d.f(aVarArr);
        b = new com.quizlet.shared.usecase.studiableMetadata.a(23);
    }

    public a(String str, int i, int i2) {
        this.a = i2;
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) c.clone();
    }
}
