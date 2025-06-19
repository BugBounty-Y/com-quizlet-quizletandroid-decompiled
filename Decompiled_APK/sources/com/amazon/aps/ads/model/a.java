package com.amazon.aps.ads.model;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class a {
    public static final a a;
    public static final a b;
    public static final a c;
    public static final a d;
    public static final /* synthetic */ a[] e;

    static {
        a aVar = new a("BANNER", 0);
        a = aVar;
        a aVar2 = new a("MREC", 1);
        b = aVar2;
        a aVar3 = new a("LEADERBOARD", 2);
        c = aVar3;
        a aVar4 = new a("BANNER_SMART", 3);
        a aVar5 = new a("INTERSTITIAL", 4);
        d = aVar5;
        e = new a[]{aVar, aVar2, aVar3, aVar4, aVar5, new a("REWARDED_VIDEO", 5), new a("INSTREAM_VIDEO", 6)};
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) e.clone();
    }
}
