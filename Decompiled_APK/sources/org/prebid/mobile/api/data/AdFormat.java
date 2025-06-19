package org.prebid.mobile.api.data;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class AdFormat {
    public static final AdFormat a;
    public static final AdFormat b;
    public static final AdFormat c;
    public static final AdFormat d;
    public static final /* synthetic */ AdFormat[] e;

    static {
        AdFormat adFormat = new AdFormat("BANNER", 0);
        a = adFormat;
        AdFormat adFormat2 = new AdFormat("INTERSTITIAL", 1);
        b = adFormat2;
        AdFormat adFormat3 = new AdFormat("NATIVE", 2);
        c = adFormat3;
        AdFormat adFormat4 = new AdFormat("VAST", 3);
        d = adFormat4;
        e = new AdFormat[]{adFormat, adFormat2, adFormat3, adFormat4};
    }

    public static AdFormat valueOf(String str) {
        return (AdFormat) Enum.valueOf(AdFormat.class, str);
    }

    public static AdFormat[] values() {
        return (AdFormat[]) e.clone();
    }
}
