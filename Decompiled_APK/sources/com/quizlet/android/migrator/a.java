package com.quizlet.android.migrator;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class a {
    public static final a a;
    public static final a b;
    public static final a c;
    public static final a d;
    public static final /* synthetic */ a[] e;

    static {
        a aVar = new a("INTEGER", 0);
        a = aVar;
        a aVar2 = new a("LONG", 1);
        b = aVar2;
        a aVar3 = new a("VARCHAR", 2);
        c = aVar3;
        a aVar4 = new a("BOOLEAN", 3);
        d = aVar4;
        e = new a[]{aVar, aVar2, aVar3, aVar4};
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) e.clone();
    }

    @Override // java.lang.Enum
    public final String toString() {
        return name();
    }
}
