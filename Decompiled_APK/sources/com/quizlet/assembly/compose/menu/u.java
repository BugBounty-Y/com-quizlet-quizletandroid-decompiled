package com.quizlet.assembly.compose.menu;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class u {
    public static final u a;
    public static final u b;
    public static final u c;
    public static final u d;
    public static final /* synthetic */ u[] e;

    static {
        u uVar = new u("Open", 0);
        a = uVar;
        u uVar2 = new u("Closed", 1);
        b = uVar2;
        u uVar3 = new u("Closing", 2);
        c = uVar3;
        u uVar4 = new u("Loading", 3);
        d = uVar4;
        u[] uVarArr = {uVar, uVar2, uVar3, uVar4};
        e = uVarArr;
        AbstractC3328d.f(uVarArr);
    }

    public static u valueOf(String str) {
        return (u) Enum.valueOf(u.class, str);
    }

    public static u[] values() {
        return (u[]) e.clone();
    }
}
