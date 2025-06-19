package com.quizlet.quizletandroid.managers;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class e {
    public static final e a;
    public static final e b;
    public static final e c;
    public static final /* synthetic */ e[] d;

    static {
        e eVar = new e("INDETERMINATE", 0);
        a = eVar;
        e eVar2 = new e("UNDER_AGE", 1);
        b = eVar2;
        e eVar3 = new e("OF_AGE", 2);
        c = eVar3;
        d = new e[]{eVar, eVar2, eVar3};
    }

    public static e valueOf(String str) {
        return (e) Enum.valueOf(e.class, str);
    }

    public static e[] values() {
        return (e[]) d.clone();
    }
}
