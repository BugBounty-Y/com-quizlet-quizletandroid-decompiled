package com.airbnb.lottie;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class D {
    public static final D a;
    public static final D b;
    public static final D c;
    public static final /* synthetic */ D[] d;

    static {
        D d2 = new D("AUTOMATIC", 0);
        a = d2;
        D d3 = new D("HARDWARE", 1);
        b = d3;
        D d4 = new D("SOFTWARE", 2);
        c = d4;
        d = new D[]{d2, d3, d4};
    }

    public static D valueOf(String str) {
        return (D) Enum.valueOf(D.class, str);
    }

    public static D[] values() {
        return (D[]) d.clone();
    }
}
