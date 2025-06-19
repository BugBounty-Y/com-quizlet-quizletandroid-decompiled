package com.quizlet.assembly.compose.menu;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class p {
    public static final p a;
    public static final p b;
    public static final p c;
    public static final p d;
    public static final /* synthetic */ p[] e;

    static {
        p pVar = new p("Selected", 0);
        a = pVar;
        p pVar2 = new p("SelectedWithLeadingIcon", 1);
        b = pVar2;
        p pVar3 = new p("SelectedWithTrailingIcon", 2);
        c = pVar3;
        p pVar4 = new p("Unselected", 3);
        d = pVar4;
        p[] pVarArr = {pVar, pVar2, pVar3, pVar4};
        e = pVarArr;
        AbstractC3328d.f(pVarArr);
    }

    public static p valueOf(String str) {
        return (p) Enum.valueOf(p.class, str);
    }

    public static p[] values() {
        return (p[]) e.clone();
    }
}
