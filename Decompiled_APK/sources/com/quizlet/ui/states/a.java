package com.quizlet.ui.states;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a {
    public static final com.quizlet.quizletandroid.logging.initializer.a b;
    public static final a c;
    public static final a d;
    public static final /* synthetic */ a[] e;
    public final int a;

    static {
        a aVar = new a("Plus", 0, 0);
        c = aVar;
        a aVar2 = new a("PlusTeacher", 1, 1);
        d = aVar2;
        a[] aVarArr = {aVar, aVar2};
        e = aVarArr;
        AbstractC3328d.f(aVarArr);
        b = new com.quizlet.quizletandroid.logging.initializer.a(5);
    }

    public a(String str, int i, int i2) {
        this.a = i2;
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) e.clone();
    }
}
