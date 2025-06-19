package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class m2 {
    public static final m2 a;
    public static final m2 b;
    public static final m2 c;
    public static final /* synthetic */ m2[] d;

    static {
        m2 m2Var = new m2("STUDY_GUIDES", 0);
        a = m2Var;
        m2 m2Var2 = new m2("FLASHCARDS", 1);
        b = m2Var2;
        m2 m2Var3 = new m2("PRACTICE_TESTS", 2);
        c = m2Var3;
        m2[] m2VarArr = {m2Var, m2Var2, m2Var3};
        d = m2VarArr;
        AbstractC3328d.f(m2VarArr);
    }

    public static m2 valueOf(String str) {
        return (m2) Enum.valueOf(m2.class, str);
    }

    public static m2[] values() {
        return (m2[]) d.clone();
    }
}
