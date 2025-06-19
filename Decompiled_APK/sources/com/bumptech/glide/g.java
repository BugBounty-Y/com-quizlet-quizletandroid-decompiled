package com.bumptech.glide;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class g {
    public static final g a;
    public static final g b;
    public static final g c;
    public static final g d;
    public static final /* synthetic */ g[] e;

    static {
        g gVar = new g("IMMEDIATE", 0);
        a = gVar;
        g gVar2 = new g("HIGH", 1);
        b = gVar2;
        g gVar3 = new g("NORMAL", 2);
        c = gVar3;
        g gVar4 = new g("LOW", 3);
        d = gVar4;
        e = new g[]{gVar, gVar2, gVar3, gVar4};
    }

    public static g valueOf(String str) {
        return (g) Enum.valueOf(g.class, str);
    }

    public static g[] values() {
        return (g[]) e.clone();
    }
}
