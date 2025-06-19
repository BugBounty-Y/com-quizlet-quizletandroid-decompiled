package com.quizlet.features.folders.data;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class z0 {
    public static final z0 a;
    public static final z0 b;
    public static final /* synthetic */ z0[] c;

    static {
        z0 z0Var = new z0("PEERS", 0);
        a = z0Var;
        z0 z0Var2 = new z0("FALLBACK", 1);
        b = z0Var2;
        z0[] z0VarArr = {z0Var, z0Var2};
        c = z0VarArr;
        AbstractC3328d.f(z0VarArr);
    }

    public static z0 valueOf(String str) {
        return (z0) Enum.valueOf(z0.class, str);
    }

    public static z0[] values() {
        return (z0[]) c.clone();
    }
}
