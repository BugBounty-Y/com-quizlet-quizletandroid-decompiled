package com.google.android.gms.measurement.internal;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class i1 {
    public static final i1 a;
    public static final i1 b;
    public static final /* synthetic */ i1[] c;

    static {
        i1 i1Var = new i1("CONSENT", 0);
        a = i1Var;
        i1 i1Var2 = new i1("LEGITIMATE_INTEREST", 1);
        i1 i1Var3 = new i1("FLEXIBLE_CONSENT", 2);
        i1 i1Var4 = new i1("FLEXIBLE_LEGITIMATE_INTEREST", 3);
        b = i1Var4;
        c = new i1[]{i1Var, i1Var2, i1Var3, i1Var4};
    }

    public static i1[] values() {
        return (i1[]) c.clone();
    }
}
