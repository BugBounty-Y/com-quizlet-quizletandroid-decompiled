package com.quizlet.features.onboarding.ell;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class u {
    public static final u b;
    public static final u c;
    public static final /* synthetic */ u[] d;
    public final boolean a;

    static {
        u uVar = new u("CLOSE", 0, false);
        b = uVar;
        u uVar2 = new u("COMPLETE", 1, true);
        c = uVar2;
        u[] uVarArr = {uVar, uVar2};
        d = uVarArr;
        AbstractC3328d.f(uVarArr);
    }

    public u(String str, int i, boolean z) {
        this.a = z;
    }

    public static u valueOf(String str) {
        return (u) Enum.valueOf(u.class, str);
    }

    public static u[] values() {
        return (u[]) d.clone();
    }
}
