package com.iab.omid.library.amazon.adsession;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class g {
    public static final g a;
    public static final /* synthetic */ g[] b;

    /* JADX INFO: Fake field, exist only in values array */
    g EF0;

    static {
        g gVar = new g("VIDEO_CONTROLS", 0);
        g gVar2 = new g("CLOSE_AD", 1);
        a = gVar2;
        b = new g[]{gVar, gVar2, new g("NOT_VISIBLE", 2), new g("OTHER", 3)};
    }

    public static g valueOf(String str) {
        return (g) Enum.valueOf(g.class, str);
    }

    public static g[] values() {
        return (g[]) b.clone();
    }
}
