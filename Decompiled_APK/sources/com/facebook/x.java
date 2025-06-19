package com.facebook;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class x {
    public static final x a;
    public static final x b;
    public static final /* synthetic */ x[] c;

    static {
        x xVar = new x("GET", 0);
        a = xVar;
        x xVar2 = new x("POST", 1);
        b = xVar2;
        c = new x[]{xVar, xVar2, new x("DELETE", 2)};
    }

    public static x valueOf(String str) {
        return (x) Enum.valueOf(x.class, str);
    }

    public static x[] values() {
        return (x[]) c.clone();
    }
}
