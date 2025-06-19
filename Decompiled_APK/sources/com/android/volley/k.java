package com.android.volley;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class k {
    public static final k a;
    public static final k b;
    public static final /* synthetic */ k[] c;

    static {
        k kVar = new k("LOW", 0);
        a = kVar;
        k kVar2 = new k("NORMAL", 1);
        b = kVar2;
        c = new k[]{kVar, kVar2, new k("HIGH", 2), new k("IMMEDIATE", 3)};
    }

    public static k valueOf(String str) {
        return (k) Enum.valueOf(k.class, str);
    }

    public static k[] values() {
        return (k[]) c.clone();
    }
}
