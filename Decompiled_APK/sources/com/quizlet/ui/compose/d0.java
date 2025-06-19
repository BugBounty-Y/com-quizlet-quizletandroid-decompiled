package com.quizlet.ui.compose;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class d0 {
    public static final d0 a;
    public static final d0 b;
    public static final d0 c;
    public static final /* synthetic */ d0[] d;

    static {
        d0 d0Var = new d0("TOP", 0);
        a = d0Var;
        d0 d0Var2 = new d0("BOTTOM", 1);
        b = d0Var2;
        d0 d0Var3 = new d0("START", 2);
        d0 d0Var4 = new d0("END", 3);
        d0 d0Var5 = new d0("CENTER", 4);
        d0 d0Var6 = new d0("DROPDOWN", 5);
        c = d0Var6;
        d0[] d0VarArr = {d0Var, d0Var2, d0Var3, d0Var4, d0Var5, d0Var6};
        d = d0VarArr;
        AbstractC3328d.f(d0VarArr);
    }

    public static d0 valueOf(String str) {
        return (d0) Enum.valueOf(d0.class, str);
    }

    public static d0[] values() {
        return (d0[]) d.clone();
    }
}
