package com.quizlet.shared.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@kotlinx.serialization.f(with = o.class)
/* loaded from: classes3.dex */
public final class p implements serialization.b {

    @NotNull
    public static final StudyMaterialType$Companion Companion;
    public static final p b;
    public static final p c;
    public static final p d;
    public static final p e;
    public static final p f;
    public static final p g;
    public static final /* synthetic */ p[] h;
    public final int a;

    static {
        p pVar = new p("SET", 0, 1);
        b = pVar;
        p pVar2 = new p("FOLDER", 1, 2);
        c = pVar2;
        p pVar3 = new p("TEXTBOOK", 2, 3);
        d = pVar3;
        p pVar4 = new p("TEXTBOOK_EXERCISE", 3, 4);
        e = pVar4;
        p pVar5 = new p("EXPLANATION_QUESTION", 4, 5);
        f = pVar5;
        p pVar6 = new p("NOTE", 5, 6);
        g = pVar6;
        p[] pVarArr = {pVar, pVar2, pVar3, pVar4, pVar5, pVar6};
        h = pVarArr;
        AbstractC3328d.f(pVarArr);
        Companion = new StudyMaterialType$Companion();
    }

    public p(String str, int i, int i2) {
        this.a = i2;
    }

    public static p valueOf(String str) {
        return (p) Enum.valueOf(p.class, str);
    }

    public static p[] values() {
        return (p[]) h.clone();
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }
}
