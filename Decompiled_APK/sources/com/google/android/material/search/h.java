package com.google.android.material.search;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class h {
    public static final h a;
    public static final h b;
    public static final h c;
    public static final h d;
    public static final /* synthetic */ h[] e;

    static {
        h hVar = new h("HIDING", 0);
        a = hVar;
        h hVar2 = new h("HIDDEN", 1);
        b = hVar2;
        h hVar3 = new h("SHOWING", 2);
        c = hVar3;
        h hVar4 = new h("SHOWN", 3);
        d = hVar4;
        e = new h[]{hVar, hVar2, hVar3, hVar4};
    }

    public static h valueOf(String str) {
        return (h) Enum.valueOf(h.class, str);
    }

    public static h[] values() {
        return (h[]) e.clone();
    }
}
