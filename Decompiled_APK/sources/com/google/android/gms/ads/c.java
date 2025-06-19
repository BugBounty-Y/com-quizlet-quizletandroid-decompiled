package com.google.android.gms.ads;

/* loaded from: classes2.dex */
public enum c {
    BANNER(0),
    INTERSTITIAL(1),
    REWARDED(2),
    REWARDED_INTERSTITIAL(3),
    NATIVE(4),
    APP_OPEN_AD(6);

    public final int a;

    c(int i) {
        this.a = i;
    }

    public static c a(int i) {
        for (c cVar : values()) {
            if (cVar.a == i) {
                return cVar;
            }
        }
        return null;
    }
}
