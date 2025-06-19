package com.quizlet.themes.nighttheme;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a {
    public static final com.quizlet.quizletandroid.ui.setcreation.adapters.a b;
    public static final a c;
    public static final a d;
    public static final a e;
    public static final /* synthetic */ a[] f;
    public final int a;

    static {
        a aVar = new a("SYSTEM_DEFAULT", 0, -1);
        c = aVar;
        a aVar2 = new a("ALWAYS_OFF", 1, 0);
        d = aVar2;
        a aVar3 = new a("ALWAYS_ON", 2, 1);
        e = aVar3;
        a[] aVarArr = {aVar, aVar2, aVar3};
        f = aVarArr;
        AbstractC3328d.f(aVarArr);
        b = new com.quizlet.quizletandroid.ui.setcreation.adapters.a(4);
    }

    public a(String str, int i, int i2) {
        this.a = i2;
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) f.clone();
    }
}
