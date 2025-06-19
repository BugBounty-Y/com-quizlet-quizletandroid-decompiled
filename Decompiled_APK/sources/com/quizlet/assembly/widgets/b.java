package com.quizlet.assembly.widgets;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class b {
    public static final com.quizlet.shared.usecase.folderstudymaterials.b b;
    public static final /* synthetic */ b[] c;
    public final int a;

    static {
        b[] bVarArr = {new b("SMALL", 0, 0), new b("MEDIUM", 1, 1)};
        c = bVarArr;
        AbstractC3328d.f(bVarArr);
        b = new com.quizlet.shared.usecase.folderstudymaterials.b(23);
    }

    public b(String str, int i, int i2) {
        this.a = i2;
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) c.clone();
    }
}
