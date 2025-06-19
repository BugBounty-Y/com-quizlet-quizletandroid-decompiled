package com.facebook.internal;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class x {
    public static final x a;
    public static final x b;
    public static final x c;
    public static final x d;
    public static final /* synthetic */ x[] e;

    static {
        x xVar = new x("NOT_LOADED", 0);
        a = xVar;
        x xVar2 = new x("LOADING", 1);
        b = xVar2;
        x xVar3 = new x("SUCCESS", 2);
        c = xVar3;
        x xVar4 = new x("ERROR", 3);
        d = xVar4;
        e = new x[]{xVar, xVar2, xVar3, xVar4};
    }

    public static x valueOf(String str) {
        return (x) Enum.valueOf(x.class, str);
    }

    public static x[] values() {
        return (x[]) e.clone();
    }
}
